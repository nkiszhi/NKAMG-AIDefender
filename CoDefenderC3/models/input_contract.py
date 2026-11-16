"""Frozen generic-model input/constructor/serialization contract.

Trusted local artifacts only: pickle is not a safe format for untrusted input.
No graph/external pipelines, extraction fallback, registry defaults or deployment.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import importlib
import importlib.metadata
import inspect
from pathlib import Path
import platform
import re
import numpy as np
from engine.feature_contract import FeatureContract, ContractError, canonical, digest, NAME_RE, SHA_RE

SCHEMA = "model-input-contract-v1"
ARTIFACT_SCHEMA = "ensemble-input-contract-v1"
MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
PROJECT = Path(__file__).resolve().parents[1]


def file_hash(path):
    h=hashlib.sha256()
    try:
        with open(path,"rb") as stream:
            for chunk in iter(lambda:stream.read(1 << 20),b""): h.update(chunk)
    except OSError as error:
        raise ContractError("pinned source unreadable") from error
    return h.hexdigest()


def implementation_revision():
    return digest({name:file_hash(PROJECT/name) for name in
                   ("models/input_contract.py", "models/contract_serialization.py",
                    "models/ensemble.py", "engine/prediction_policy.py", "engine/feature_contract.py",
                    "engine/app.py", "engine/contract_pipeline.py", "engine/staged_scan.py")})


def freeze_constructor(cls, kwargs):
    if not inspect.isclass(cls) or not isinstance(kwargs,dict): raise ContractError("explicit class and constructor dictionary required")
    try:
        signature=inspect.signature(cls.__init__)
        bound=signature.bind(None,**kwargs)
        bound.apply_defaults()
        result={}
        for key,param in signature.parameters.items():
            if key=="self": continue
            value=bound.arguments[key]
            if param.kind==inspect.Parameter.VAR_POSITIONAL:
                if value: raise ContractError("positional constructor arguments unsupported")
            elif param.kind==inspect.Parameter.VAR_KEYWORD: result.update(value)
            elif param.kind==inspect.Parameter.POSITIONAL_ONLY:
                raise ContractError("positional-only constructor unsupported")
            else: result[key]=value
        if result.get("pretrained") is not None and result.get("pretrained") is not False:
            raise ContractError("pretrained downloads are not a frozen constructor")
        # No defaults may be supplied later by registry or an environment.
        import json
        return json.loads(canonical(result))
    except (TypeError,ValueError,KeyError) as error:
        raise ContractError("constructor is not completely explicit finite JSON") from error


def class_identity(cls):
    if not inspect.isclass(cls): raise ContractError("model class required")
    try:
        source=Path(inspect.getfile(cls)).resolve()
    except (TypeError, OSError) as error:
        raise ContractError("model has no pinnable source file") from error
    if not source.is_relative_to(PROJECT):
        raise ContractError("model implementation must be a pinned project source")
    if not MODULE_RE.fullmatch(cls.__module__) or not NAME_RE.fullmatch(cls.__qualname__):
        raise ContractError("top-level importable model class required")
    return dict(module=cls.__module__,class_name=cls.__qualname__,
                source=source.relative_to(PROJECT).as_posix(),source_sha256=file_hash(source))


@dataclass(frozen=True,init=False)
class ModelInputContract:
    _raw: bytes
    fingerprint: str

    def __init__(self,document):
        import json
        try: doc=json.loads(canonical(document))
        except (TypeError,ValueError) as error: raise ContractError("finite input-contract JSON required") from error
        if (not isinstance(doc,dict) or set(doc)!={"schema_version","feature_contract","model_names","models","packages","implementation_revision"}
                or doc["schema_version"]!=SCHEMA):
            raise ContractError("explicit model-input-contract-v1 required")
        feature=FeatureContract(doc["feature_contract"])
        doc["feature_contract"]=feature.document
        names=doc["model_names"]
        if (not isinstance(names,list) or not names or any(not isinstance(n,str) or not NAME_RE.fullmatch(n) for n in names)
                or len(names)!=len(set(names)) or not isinstance(doc["models"],dict) or set(doc["models"])!=set(names)):
            raise ContractError("unique explicit model allowlist/specs required")
        packages=doc["packages"]
        if (not isinstance(packages,dict) or not {"python","numpy"}.issubset(packages)
                or any(not isinstance(k,str) or not k or not isinstance(v,str) or not v for k,v in packages.items())
                or not isinstance(doc["implementation_revision"],str) or not SHA_RE.fullmatch(doc["implementation_revision"])):
            raise ContractError("exact package versions and implementation revision required")
        required={"view","engine","constructor","class_identity","tensor_dtype","output","output_container"}
        for name,spec in doc["models"].items():
            if not isinstance(spec,dict) or set(spec)!=required:
                raise ContractError("complete model input/constructor/output spec required: "+name)
            if (not isinstance(spec["view"],str) or spec["view"] not in feature.view_names or spec["engine"] not in ("numpy","pytorch")
                    or not isinstance(spec["constructor"],dict) or spec["output_container"]!="first_if_tuple"):
                raise ContractError("unsupported generic model spec")
            identity=spec["class_identity"]
            if (not isinstance(identity,dict) or set(identity)!={"module","class_name","source","source_sha256"}
                    or not isinstance(identity["module"],str) or not MODULE_RE.fullmatch(identity["module"])
                    or not isinstance(identity["class_name"],str) or not NAME_RE.fullmatch(identity["class_name"])
                    or not isinstance(identity["source_sha256"],str) or not SHA_RE.fullmatch(identity["source_sha256"])):
                raise ContractError("pinned importable class identity required")
            source=identity["source"]
            if (not isinstance(source,str) or not source or "\\" in source
                    or source.startswith("/") or any(c in {".","..",""} for c in source.split("/"))
                    or ":" in source or not source.endswith(".py")):
                raise ContractError("project-relative source path required")
            dtype=np.dtype(feature.view_spec(spec["view"])["dtype"])
            if spec["engine"]=="numpy":
                if spec["tensor_dtype"]!="float32" or dtype!=np.dtype("float32") or spec["output"]!="binary_proba":
                    raise ContractError("numpy generic model requires exact float32/probability columns")
            else:
                if "torch" not in packages or spec["output"] not in ("probability_1","logits_2"):
                    raise ContractError("torch version and explicit binary output required")
                if spec["tensor_dtype"]=="int64":
                    if dtype.kind not in "iu" or not np.can_cast(dtype,np.int64,casting="safe"):
                        raise ContractError("explicit safe integer token conversion required")
                elif spec["tensor_dtype"]!="float32" or dtype!=np.dtype("float32"):
                    raise ContractError("explicit exact float32 tensor input required")
            if spec["constructor"].get("pretrained") is not None and spec["constructor"].get("pretrained") is not False:
                raise ContractError("pretrained constructor forbidden")
            if "input_dim" in spec["constructor"] and (type(spec["constructor"]["input_dim"]) is not int
                    or spec["constructor"]["input_dim"]!=feature.view_dimension(spec["view"])):
                raise ContractError("constructor input_dim differs from frozen view")
        raw=canonical(doc)
        object.__setattr__(self,"_raw",raw)
        object.__setattr__(self,"fingerprint",hashlib.sha256(raw).hexdigest())

    @property
    def document(self):
        import json
        return json.loads(self._raw)

    @property
    def model_names(self): return tuple(self.document["model_names"])

    @property
    def feature_contract(self): return FeatureContract(self.document["feature_contract"])

    def spec(self,name):
        if name not in self.model_names: raise ContractError("model outside input allowlist")
        return self.document["models"][name]

    def validate_runtime(self):
        doc=self.document
        if doc["implementation_revision"]!=implementation_revision():
            raise ContractError("model-input implementation revision mismatch")
        for name,wanted in doc["packages"].items():
            try: actual=platform.python_version() if name=="python" else importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError as error: raise ContractError("required model package unavailable: "+name) from error
            if actual!=wanted: raise ContractError("model package version mismatch: "+name)
        for spec in doc["models"].values():
            identity=spec["class_identity"]; file=PROJECT/identity["source"]
            if file.resolve()!=file or not file.resolve().is_relative_to(PROJECT) or not file.is_file() or file_hash(file)!=identity["source_sha256"]:
                raise ContractError("model source identity mismatch")
        return self

    def verify_class(self,name,cls):
        spec=self.spec(name)
        if class_identity(cls)!=spec["class_identity"] or freeze_constructor(cls,spec["constructor"])!=spec["constructor"]:
            raise ContractError("class/constructor differs from frozen model spec: "+name)

    def load_class(self,name):
        self.validate_runtime()
        identity=self.spec(name)["class_identity"]
        try:
            cls=getattr(importlib.import_module(identity["module"]),identity["class_name"])
        except (ImportError, AttributeError) as error:
            raise ContractError("frozen class unavailable: "+name) from error
        self.verify_class(name,cls)
        return cls

    def validate_model(self,name,model,actual_kwargs):
        spec=self.spec(name)
        if model is None or canonical(actual_kwargs)!=canonical(spec["constructor"]):
            raise ContractError("missing model or actual constructor mismatch: "+name)
        self.verify_class(name,type(model))
        if spec["engine"]=="numpy":
            n_features=getattr(model,"n_features_in_",None)
            if n_features is not None and (isinstance(n_features, (bool,np.bool_))
                    or not isinstance(n_features, (int,np.integer))
                    or n_features!=self.feature_contract.view_dimension(spec["view"])):
                raise ContractError("fitted model input dimension mismatch")
        return model

    def prepare(self,name,value,*,batch):
        spec=self.spec(name)
        return self.feature_contract.validate_view(spec["view"],value,batch=batch)

    def transform_features(self,bundle,views=None):
        feature=self.feature_contract
        if (not isinstance(bundle,dict) or set(bundle)!={"features","feature_fingerprint"}
                or bundle["feature_fingerprint"]!=feature.feature_fingerprint):
            raise ContractError("contract-bound extraction bundle required (no legacy fallback)")
        return feature.transform(bundle["features"],views)

    @classmethod
    def build(cls,feature,names,declarations,*,packages=None):
        feature=feature if isinstance(feature,FeatureContract) else FeatureContract(feature)
        if (not isinstance(names,(list,tuple)) or not names
                or any(not isinstance(n,str) or not NAME_RE.fullmatch(n) for n in names)
                or len(names)!=len(set(names)) or not isinstance(declarations,dict) or set(declarations)!=set(names)):
            raise ContractError("explicit unique model declarations required")
        for declaration in declarations.values():
            if not isinstance(declaration,dict) or set(declaration)!={"class","view","engine","kwargs","tensor_dtype","output"}:
                raise ContractError("complete model declaration required")
        if packages is None:
            packages={"python":platform.python_version(),"numpy":np.__version__}
            if any(declarations[n]["engine"]=="pytorch" for n in names):
                try: packages["torch"]=importlib.metadata.version("torch")
                except importlib.metadata.PackageNotFoundError as error:
                    raise ContractError("required torch package unavailable") from error
        models={}
        for name in names:
            d=declarations[name]
            models[name]=dict(view=d["view"],engine=d["engine"],constructor=freeze_constructor(d["class"],d["kwargs"]),
                class_identity=class_identity(d["class"]),tensor_dtype=d["tensor_dtype"],output=d["output"],output_container="first_if_tuple")
        return cls(dict(schema_version=SCHEMA,feature_contract=feature.document,model_names=list(names),models=models,
                        packages=packages,implementation_revision=implementation_revision()))
