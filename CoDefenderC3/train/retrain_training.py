"""Explicit external-validation training helpers; never infer a role/month."""
import math
import numpy as np
try:
    from .retrain_contract import ContractError
    from .retrain_selection import labels
except ImportError:
    from retrain_contract import ContractError
    from retrain_selection import labels


def validate_pair(X, y, X_val, y_val):
    y, y_val = labels(y), labels(y_val)
    if (not isinstance(X, np.ndarray) or not isinstance(X_val, np.ndarray)
            or X.ndim != 2 or X_val.ndim != 2 or X.shape[1] != X_val.shape[1]
            or X.shape[0] != len(y) or X_val.shape[0] != len(y_val)
            or X.dtype != X_val.dtype or X.dtype.kind not in "iuf"):
        raise ContractError("train/model_val input schema or row count mismatch")
    for value in (X, X_val):
        flat = value.reshape(-1)
        for start in range(0, flat.size, 1 << 20):
            if not np.isfinite(flat[start:start+(1 << 20)]).all():
                raise ContractError("nonfinite training/validation input")
    return y, y_val


def train_numpy_external(cls, kwargs, X, y, X_val, y_val, *, mode, seed):
    y, y_val = validate_pair(X, y, X_val, y_val)
    if mode != "scratch":
        raise ContractError("NumPy models do not support verified finetune; use scratch explicitly")
    np.random.seed(seed)
    model = cls(**kwargs)
    # Declared dtype is consumed verbatim; no view casts/column padding here.
    model.fit(X, y)
    return model, dict(engine="numpy", actual_kwargs=dict(kwargs), warm_started=False,
                       n_train=len(y), n_val=len(y_val), validation_source="model_val",
                       validation_usage="post_fit_selection_only", all_train_rows_used=True)


def train_torch_external(cls, kwargs, X, y, X_val, y_val, *, device, loss_kind,
                         x_dtype, epochs, lr, patience, seed, warm_state=None):
    y, y_val = validate_pair(X, y, X_val, y_val)
    if (type(epochs) is not int or epochs <= 0 or type(patience) is not int or patience <= 0
            or type(lr) not in (int, float) or not math.isfinite(lr) or lr <= 0
            or type(seed) is not int or not 0 <= seed < 2**32 or device not in {"cpu", "cuda"}
            or loss_kind not in {"bce", "ce"}
            or x_dtype not in {"long", "float"}):
        raise ContractError("invalid external-validation training options")
    if x_dtype == "float" and X.dtype != np.dtype("float32"):
        raise ContractError("float model requires an explicit float32 view")
    if x_dtype == "long" and (X.dtype.kind not in "iu" or not np.can_cast(X.dtype, np.int64, casting="safe")):
        raise ContractError("token model requires an explicit integer view")
    import torch
    import torch.nn as nn
    torch.manual_seed(seed)
    if device == "cuda":
        torch.cuda.manual_seed_all(seed)
    np.random.seed(seed)
    model = cls(**kwargs).to(device)
    if warm_state is not None:
        # Never silently fall back to scratch or accept missing/unexpected keys.
        model.load_state_dict(warm_state, strict=True)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.BCELoss() if loss_kind == "bce" else nn.CrossEntropyLoss()
    dtype = torch.long if x_dtype == "long" else torch.float32
    batch_size = 16 if X.shape[1] > 100000 else 32 if X.shape[1] > 10000 else 64
    rng = np.random.default_rng(seed)
    best_loss, best_state, best_epoch, wait = float("inf"), None, -1, 0
    def loss_at(values, targets):
        output = model(values)
        if isinstance(output, tuple): output = output[0]
        loss = loss_fn(output.squeeze(-1), targets) if loss_kind == "bce" else loss_fn(output, targets.long())
        if not math.isfinite(float(loss.item())):
            raise ContractError("nonfinite model training/validation loss")
        return loss
    for epoch in range(epochs):
        model.train()
        order = rng.permutation(len(y))  # all train rows, never a random internal val split
        for start in range(0, len(y), batch_size):
            indices = order[start:start+batch_size]
            xb = torch.tensor(X[indices], dtype=dtype, device=device)
            yb = torch.tensor(y[indices], dtype=torch.float32, device=device)
            optimizer.zero_grad()
            loss = loss_at(xb, yb)
            loss.backward(); optimizer.step()
        model.eval()
        total = 0.
        with torch.no_grad():
            for start in range(0, len(y_val), batch_size):
                xv = torch.tensor(X_val[start:start+batch_size], dtype=dtype, device=device)
                yv = torch.tensor(y_val[start:start+batch_size], dtype=torch.float32, device=device)
                total += float(loss_at(xv, yv).item()) * len(yv)
        value = total / len(y_val)
        if value < best_loss - 1e-4:
            best_loss, best_epoch, wait = value, epoch, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            wait += 1
            if wait >= patience: break
    if best_state is None:
        raise ContractError("external model_val did not produce a valid best state")
    model.load_state_dict(best_state, strict=True)
    model.eval()
    return model, dict(engine="pytorch", actual_kwargs=dict(kwargs), warm_started=warm_state is not None,
                       n_train=len(y), n_val=len(y_val), validation_source="model_val",
                       best_val=best_loss, best_epoch=best_epoch, epochs_run=epoch+1,
                       batch_size=batch_size, all_train_rows_used=True)
