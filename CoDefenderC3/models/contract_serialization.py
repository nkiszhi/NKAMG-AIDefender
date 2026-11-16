"""Opt-in strict serialization for trusted-local, frozen generic ensembles.

The outer envelope and NumPy payloads use pickle: NEVER load untrusted files.
Checksums bind accidental corruption, not authenticity or safe deserialization.
No registry reconstruction, partial model loading, downloads or deployment.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import pickle
import tempfile
import numpy as np
from engine.feature_contract import ContractError, canonical
from engine.decision_policy import DecisionPolicy
from models.input_contract import ModelInputContract, ARTIFACT_SCHEMA


def contract_layout(contract):
    groups = {}
    for name in contract.model_names:
        groups.setdefault(contract.spec(name)["view"], []).append(name)
    indices = {view: [contract.model_names.index(n) for n in members] for view, members in groups.items()}
    return groups, indices


def validate_binding(ens, *, require_policy=True):
    contract = getattr(ens, "_input_contract", None)
    if not isinstance(contract, ModelInputContract):
        raise ContractError("explicit model input contract required")
    contract.validate_runtime()
    groups, indices = contract_layout(contract)
    names = list(contract.model_names)
    types = {n: contract.spec(n)["engine"] for n in names}
    kwargs = {n: contract.spec(n)["constructor"] for n in names}
    if (ens._model_names != names or ens._model_types != types or ens.view_groups != groups
            or ens._view_indices != indices or ens.K != len(names) or ens.V != len(groups)
            or set(ens._models) != set(names) or canonical(ens._actual_kwargs) != canonical(kwargs)):
        raise ContractError("ensemble topology/constructor differs from frozen input contract")
    for name in names:
        contract.validate_model(name, ens._models[name], ens._actual_kwargs[name])
    if require_policy:
        policy = getattr(ens, "_decision_policy", None)
        if not isinstance(policy, DecisionPolicy) or policy.model_names != contract.model_names:
            raise ContractError("explicit fixed decision policy with identical ordered allowlist required")
        weights = np.asarray(ens._weights)
        if weights.shape != (len(names),) or not np.array_equal(weights, np.asarray(policy.document["weights"])):
            raise ContractError("ensemble weights differ from fixed decision policy")
    return contract


def save_contract_ensemble(ens, path):
    contract = validate_binding(ens)
    if ens._fitted is not True:
        raise ContractError("all contracted models must be fitted before serialization")
    payloads = {}
    for name in contract.model_names:
        model = ens._models[name]
        if contract.spec(name)["engine"] == "numpy":
            value = model
        else:
            value = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        payload = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        payloads[name] = {"payload": payload, "sha256": hashlib.sha256(payload).hexdigest()}
    envelope = dict(schema_version=ARTIFACT_SCHEMA, input_contract=contract.document,
                    input_fingerprint=contract.fingerprint, model_names=list(contract.model_names),
                    decision_policy=ens._decision_policy.document,
                    policy_fingerprint=ens._decision_policy.fingerprint, models=payloads)
    path = Path(path)
    if path.is_symlink():
        raise ContractError("artifact output cannot replace a symbolic link")
    fd, temporary = tempfile.mkstemp(prefix=path.name+".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            pickle.dump(envelope, stream, protocol=pickle.HIGHEST_PROTOCOL)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def load_contract_ensemble(cls, envelope, expected):
    if expected is None:
        raise ContractError("new input-contract artifact requires caller-supplied expected contract")
    expected = expected if isinstance(expected, ModelInputContract) else ModelInputContract(expected)
    required = {"schema_version", "input_contract", "input_fingerprint", "model_names",
                "decision_policy", "policy_fingerprint", "models"}
    if not isinstance(envelope, dict) or set(envelope) != required or envelope["schema_version"] != ARTIFACT_SCHEMA:
        raise ContractError("invalid strict ensemble envelope")
    saved = ModelInputContract(envelope["input_contract"])
    if (saved.fingerprint != expected.fingerprint or saved.document != expected.document
            or envelope["input_fingerprint"] != expected.fingerprint
            or envelope["model_names"] != list(expected.model_names)):
        raise ContractError("saved input contract differs from caller expectation")
    expected.validate_runtime()  # Before importing/reconstructing or unpickling ANY model payload.
    policy = DecisionPolicy(envelope["decision_policy"])
    if policy.fingerprint != envelope["policy_fingerprint"] or policy.model_names != expected.model_names:
        raise ContractError("saved decision policy identity/allowlist mismatch")
    payloads = envelope["models"]
    if not isinstance(payloads, dict) or set(payloads) != set(expected.model_names):
        raise ContractError("all contracted model payloads required")
    # Validate every payload before loading the first; never drop a failed slot.
    for name in expected.model_names:
        item = payloads[name]
        if (not isinstance(item, dict) or set(item) != {"payload", "sha256"}
                or not isinstance(item["payload"], bytes)
                or hashlib.sha256(item["payload"]).hexdigest() != item["sha256"]):
            raise ContractError("model payload checksum mismatch: "+name)
    ens = cls(available_views=[])
    ens._model_names = list(expected.model_names)
    ens.view_groups, ens._view_indices = contract_layout(expected)
    ens._model_types = {n: expected.spec(n)["engine"] for n in expected.model_names}
    ens._actual_kwargs = {n: expected.spec(n)["constructor"] for n in expected.model_names}
    ens.K, ens.V = len(expected.model_names), len(ens.view_groups)
    for name in expected.model_names:
        model_cls = expected.load_class(name)
        try:
            payload = pickle.loads(payloads[name]["payload"])
            if expected.spec(name)["engine"] == "numpy":
                model = payload
            else:
                model = model_cls(**expected.spec(name)["constructor"])
                model.load_state_dict(payload, strict=True)
                model.eval()
            expected.validate_model(name, model, ens._actual_kwargs[name])
        except ContractError:
            raise
        except Exception as error:
            raise ContractError("contracted model reconstruction failed: "+name) from error
        ens._models[name] = model
    ens._input_contract = expected
    ens._weights = np.asarray(policy.document["weights"], dtype=np.float64)
    ens.set_decision_policy(policy)
    ens._fitted = True
    validate_binding(ens)
    return ens
