"""
MultiModelEnsemble — 多模型集成桥接层
========================================
连接 model_registry + unified 特征提取 ↔ SDD 引擎

核心接口:
  ens = MultiModelEnsemble(available_views=views.keys())
  ens.fit(views, y)                       # 训练所有子模型
  preds, scores = ens.predict_all(views)  # 返回 (N, K) 矩阵
  sdd_groups = ens.perspective_groups()   # 返回视角组→模型索引映射

数据流:
  run_all.py → create_loader() → loader.all_views(X) → views dict
            → MultiModelEnsemble.predict_all(views) → (N, K) 分数矩阵
            → SDDEngine.detect(preds, scores) → SDDResult
"""
import os, gc
import pickle
import importlib
import inspect
import numpy as np

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

import config


# FeatureType 需要 LongTensor 输入的类型 (Embedding 层)
LONG_INPUT_FEATURES = {"RAW_BYTES", "OPCODE_SEQ"}


def _input_dtype(model_name):
    """根据模型的 feature_type 确定 torch 输入 dtype."""
    try:
        from model_registry import get_model_config
        ft = get_model_config(model_name)["feature_type"].name
        if ft in LONG_INPUT_FEATURES:
            return "long"
    except Exception:
        pass
    return "float"


# 需要特殊数据管线的模型 (不通过通用 predict_all, 通过 merge_external_scores 合并)
SPECIAL_PIPELINE_MODELS = {"MalGraph"}


def _build_view_groups(available_views):
    """
    从 config.VIEW_GROUPS 中选取 available_views 涉及的视角，构建模型列表。
    
    参数:
        available_views: list/set of view names that have data (e.g., {"V2_byte_stat", "V3_pe_struct", ...})
    返回:
        dict: {view_name: [model_name, ...]}
    """
    groups = {}
    for vname, vinfo in config.VIEW_GROUPS.items():
        if vname not in available_views:
            continue
        model_names = [m[0] for m in vinfo["models"]]
        groups[vname] = model_names
    return groups


class MultiModelEnsemble:
    """
    多模型集成 — 桥接 model_registry 与 SDD 引擎
    
    数据驱动: 根据实际提供的 views 确定使用哪些视角和模型，
    不存在 "ember" vs "full" 模式的区分。
    """

    def __init__(self, available_views):
        """
        参数:
            available_views: list/set of view names, 例如 {"V2_byte_stat", "V3_pe_struct", ...}
        """
        self.view_groups = _build_view_groups(available_views)

        # 构建模型列表和索引
        self._models = {}
        self._model_names = []
        self._model_types = {}
        self._view_indices = {}
        self._weights = None
        self._actual_kwargs = {}
        self._decision_policy = None
        self._input_contract = None

        idx = 0
        for vname, mnames in self.view_groups.items():
            indices = []
            for mname in mnames:
                self._model_names.append(mname)
                indices.append(idx)
                idx += 1
            self._view_indices[vname] = indices

        self.K = len(self._model_names)
        self.V = len(self.view_groups)
        self._fitted = False

    def _load_model_class(self, model_name):
        """从 model_registry 动态加载模型类"""
        try:
            from model_registry import get_model_config
            cfg = get_model_config(model_name)
            mod = importlib.import_module(cfg["module"])
            cls = getattr(mod, cfg["class"])
            return cls, cfg
        except (KeyError, ImportError, AttributeError) as e:
            print(f"  [警告] 无法加载 {model_name}: {e}")
            return None, None

    def fit(self, views, y):
        """
        训练所有子模型

        参数:
            views: dict, 视角名→特征矩阵 {"V2_byte_stat": (N, 512), ...}
            y: numpy array (N,), 标签
        """
        if self._input_contract is not None:
            raise ValueError("contract-bound training must use the explicit split-aware backend")
        from model_registry import get_model_config, PYTORCH, NUMPY
        from concurrent.futures import ThreadPoolExecutor, as_completed

        print(f"  训练 {self.K} 个模型 ({self.V} 个视角组)")
        self._weights = np.ones(self.K) / self.K

        # 分离 numpy 和 pytorch 训练任务
        numpy_tasks = []
        pytorch_queue = []

        for vname, mnames in self.view_groups.items():
            if vname not in views:
                print(f"    [跳过] 视角 {vname} 无数据")
                continue
            X_view = views[vname]

            for mname in mnames:
                if mname in SPECIAL_PIPELINE_MODELS:
                    self._models[mname] = None
                    self._model_types[mname] = "special"
                    continue
                try:
                    cfg = get_model_config(mname)
                except KeyError:
                    print(f"    [跳过] {mname} 未注册")
                    self._models[mname] = None
                    self._model_types[mname] = "skip"
                    continue

                engine = cfg["engine"]
                self._model_types[mname] = engine

                if engine == NUMPY:
                    cls, _ = self._load_model_class(mname)
                    if cls is None:
                        self._models[mname] = None; continue
                    numpy_tasks.append((mname, cls, cfg["model_kwargs"], X_view))
                elif engine == PYTORCH and HAS_TORCH:
                    pytorch_queue.append((mname, cfg, X_view))

        # ── numpy 模型: 并行训练 (sklearn 释放 GIL) ──
        def _train_numpy(args):
            mn, cls, kw, xv = args
            model = cls(**kw)
            xn = xv if isinstance(xv, np.ndarray) else np.array(xv)
            yn = y if isinstance(y, np.ndarray) else np.array(y)
            if xn.dtype != np.float32: xn = xn.astype(np.float32)
            model.fit(xn, yn)
            return mn, model

        if numpy_tasks:
            with ThreadPoolExecutor(max_workers=min(len(numpy_tasks), 4)) as pool:
                futs = {pool.submit(_train_numpy, t): t[0] for t in numpy_tasks}
                for fut in as_completed(futs):
                    mn, model = fut.result()
                    self._models[mn] = model
                    print(f"    {mn} (numpy): 训练完成")

        # ── pytorch 模型: 串行训练 (GPU 资源竞争) ──
        for mname, cfg, X_view in pytorch_queue:
            cls, _ = self._load_model_class(mname)
            if cls is None:
                self._models[mname] = None; continue
            # 用实际视角维度覆盖/注入 input_dim
            kwargs = dict(cfg["model_kwargs"])
            actual_dim = X_view.shape[1] if hasattr(X_view, 'shape') else len(X_view[0])
            # 检查模型 __init__ 是否接受 input_dim 参数
            import inspect
            init_params = inspect.signature(cls.__init__).parameters
            if "input_dim" in init_params:
                old_dim = kwargs.get("input_dim", init_params["input_dim"].default)
                if old_dim != actual_dim:
                    print(f"      {mname}: input_dim {old_dim} → {actual_dim}")
                kwargs["input_dim"] = actual_dim
            model = cls(**kwargs)
            self._actual_kwargs[mname] = kwargs  # 保存实际 kwargs (含动态 input_dim)
            # 简化训练: 用全数据训练少量epoch
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            model = model.to(device)
            # 根据模型 feature_type 选择正确 dtype (Embedding需要long)
            x_dtype = torch.long if _input_dtype(mname) == "long" else torch.float32
            X_t = torch.tensor(X_view, dtype=x_dtype) if not isinstance(X_view, torch.Tensor) else X_view
            y_t = torch.tensor(y, dtype=torch.float32) if not isinstance(y, torch.Tensor) else y

            optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
            loss_fn = nn.BCELoss() if cfg["loss"] == "bce" else nn.CrossEntropyLoss()

            model.train()
            # 自适应 batch size: 高维输入 (序列/图像) 自动缩小, 防 OOM
            input_dim = X_view.shape[1] if hasattr(X_view, 'shape') else len(X_view[0])
            if input_dim > 100000:     # V8 图像 (256×256=65536+)
                bs = 16
            elif input_dim > 10000:    # V1 字节 (32768)
                bs = 32
            elif input_dim > 2000:     # V6 操作码 (4096), V7 func_embed (6144)
                bs = 64
            elif input_dim > 500:      # V2/V3/V4/V5 中等维度
                bs = 256
            else:
                bs = 512
            n_epochs = 20
            patience = 3
            # 留 10% 做 early stopping 验证, 但至少保留一半数据训练
            n_val = min(max(len(X_t) // 10, 1), len(X_t) // 2)
            perm_init = torch.randperm(len(X_t))
            val_idx = perm_init[:n_val]
            train_idx = perm_init[n_val:]
            # 验证集保持在 CPU, 按 batch 送 GPU (防 OOM)
            X_val_cpu, y_val_cpu = X_t[val_idx], y_t[val_idx]
            best_loss = float("inf")
            wait = 0
            for epoch in range(n_epochs):
                model.train()
                perm = train_idx[torch.randperm(len(train_idx))]
                for i in range(0, len(perm), bs):
                    idx = perm[i:i+bs]
                    xb = X_t[idx].to(device)
                    yb = y_t[idx].to(device)
                    optimizer.zero_grad()
                    out = model(xb)
                    if isinstance(out, tuple): out = out[0]
                    if cfg["loss"] == "bce":
                        loss = loss_fn(out.squeeze(-1), yb)
                    else:
                        loss = loss_fn(out, yb.long())
                    loss.backward()
                    optimizer.step()
                    del xb, yb, out, loss
                # 验证 early stopping (分批送 GPU)
                model.eval()
                v_losses = []
                with torch.no_grad():
                    for vi in range(0, len(X_val_cpu), bs):
                        xvb = X_val_cpu[vi:vi+bs].to(device)
                        yvb = y_val_cpu[vi:vi+bs].to(device)
                        v_out = model(xvb)
                        if isinstance(v_out, tuple): v_out = v_out[0]
                        if cfg["loss"] == "bce":
                            vl = loss_fn(v_out.squeeze(-1), yvb).item()
                        else:
                            vl = loss_fn(v_out, yvb.long()).item()
                        v_losses.append(vl * len(xvb))
                        del xvb, yvb, v_out
                v_loss = sum(v_losses) / max(len(X_val_cpu), 1)
                if v_loss < best_loss - 1e-4:
                    best_loss = v_loss
                    wait = 0
                else:
                    wait += 1
                    if wait >= patience:
                        break
            del X_val_cpu, y_val_cpu, X_t, y_t; gc.collect()
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

            model.eval()
            self._models[mname] = model
            print(f"    {mname} (pytorch): 训练完成")

        self._status_cache_scope = None  # Fitting invalidates invocation-scoped score caches.
        self._fitted = True
        print(f"  集成训练完成: {sum(1 for v in self._models.values() if v is not None)}/{self.K} 模型可用")

    def predict_all(self, views, *, return_status=False):
        """
        所有模型并行推断, 返回 (N, K) 矩阵。

        return_status=True adds invocation-owned per-row status. The default raw
        compatibility tuple retains .5 failure slots; never aggregate it without
        the matching status matrix. A real .5 result remains status="ok".
        
        同一视角内的模型共享 X_view, 不同视角之间并行。
        numpy 模型用 ThreadPoolExecutor (sklearn 释放 GIL)。
        pytorch 模型用批量推断。
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        input_contract = getattr(self, "_input_contract", None)
        if input_contract is not None:
            from models.contract_serialization import validate_binding
            from engine.feature_contract import ContractError
            validate_binding(self)
            needed = {input_contract.spec(n)["view"] for n in self._model_names}
            if not isinstance(views, dict) or set(views) != needed:
                raise ContractError("exact frozen input view set required")
            sizes = set()
            for name in self._model_names:
                value = input_contract.prepare(name, views[input_contract.spec(name)["view"]], batch=True)
                sizes.add(len(value))
            if len(sizes) != 1:
                raise ContractError("contracted view batch row counts differ")

        N = None
        for v in views.values():
            N = len(v) if hasattr(v, '__len__') else v.shape[0]
            break
        if N is None:
            raise ValueError("views 为空")

        _preds = np.zeros((self.K, N), dtype=np.float32)
        _scores = np.full((self.K, N), 0.5, dtype=np.float64)
        _statuses = np.full((self.K, N), "missing", dtype="U16")
        for k, name in enumerate(self._model_names):
            if self._model_types.get(name) in {"special", "skip"}:
                _statuses[k] = "not_requested"
            elif self._models.get(name) is None:
                _statuses[k] = "unavailable"

        def accept(k, p, s):
            _statuses[k] = "error"
            if s is None:
                return
            value = np.asarray(s)
            if value.shape != (N,) or value.dtype.kind not in "iuf":
                return
            ok = np.isfinite(value) & (value >= 0) & (value <= 1)
            _scores[k,ok] = value[ok]
            _preds[k,ok] = (value[ok] > .5).astype(np.float32)
            _statuses[k,ok] = "ok"

        def _infer_one(mname, k, X_view):
            """单模型推断, 返回 (k, scores_k)"""
            model = self._models.get(mname)
            if model is None:
                return k, None, None
            try:
                if input_contract is not None:
                    from types import SimpleNamespace
                    from engine.prediction_policy import _infer_model_scores
                    s = _infer_model_scores(SimpleNamespace(torch=globals().get("torch")), self, mname, X_view)
                    return k, (s > .5).astype(np.float32), s
                if self._model_types[mname] == "numpy":
                    X_np = X_view if isinstance(X_view, np.ndarray) else np.array(X_view)
                    if X_np.dtype != np.float32:
                        X_np = X_np.astype(np.float32)
                    proba = np.asarray(model.predict_proba(X_np))
                    if proba.shape != (len(X_np),2) or proba.dtype.kind not in "iuf":
                        raise ValueError("invalid_binary_probability_shape")
                    ok = (np.isfinite(proba).all(axis=1) & (proba >= 0).all(axis=1)
                          & (proba <= 1).all(axis=1) & np.isclose(proba.sum(axis=1),1,rtol=1e-6,atol=1e-6))
                    s = proba[:, 1].astype(np.float64)
                    s[~ok] = np.nan
                    return k, (s > 0.5).astype(np.float32), s

                elif self._model_types[mname] == "pytorch" and HAS_TORCH:
                    device = next(model.parameters()).device
                    x_dtype = torch.long if _input_dtype(mname) == "long" else torch.float32
                    X_t = torch.tensor(X_view, dtype=x_dtype) if not isinstance(X_view, torch.Tensor) else X_view
                    model.eval()
                    with torch.no_grad():
                        all_s = []
                        # 自适应 batch size (与训练一致)
                        idim = X_t.shape[1] if X_t.ndim > 1 else 1
                        if idim > 100000: bs = 16
                        elif idim > 10000: bs = 32
                        elif idim > 2000: bs = 64
                        elif idim > 500: bs = 256
                        else: bs = 512
                        for i in range(0, len(X_t), bs):
                            xb = X_t[i:i+bs].to(device)
                            out = model(xb)
                            if isinstance(out, tuple): out = out[0]
                            if out.ndim != 2 or out.shape[-1] not in {1,2} or len(out) != len(xb):
                                raise ValueError("invalid_binary_output_shape")
                            if out.shape[-1] == 1:
                                s = out.squeeze(-1).cpu().numpy()
                            else:
                                s = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
                            all_s.append(s)
                            del xb, out
                        s = np.concatenate(all_s).astype(np.float64)
                        return k, (s > 0.5).astype(np.float32), s
            except Exception as e:
                print(f"  [推断错误] {mname}: {e}")
            return k, None, None

        # 收集所有推断任务
        tasks = []
        for vname, mnames in self.view_groups.items():
            if vname not in views:
                continue
            X_view = views[vname]
            for mname in mnames:
                if self._model_types.get(mname) in {"special", "skip"} or self._models.get(mname) is None:
                    continue
                k = self._model_names.index(mname)
                tasks.append((mname, k, X_view))

        # 分离 numpy (可并行) 和 pytorch (串行, CUDA 不线程安全)
        numpy_tasks = [(mn, k, xv) for mn, k, xv in tasks
                       if self._model_types.get(mn) == "numpy"]
        pytorch_tasks = [(mn, k, xv) for mn, k, xv in tasks
                         if self._model_types.get(mn) != "numpy"]

        # numpy 并行 - 动态调整worker数量based on CPU cores
        if len(numpy_tasks) > 1:
            # Use dynamic max_workers based on available cores
            # On 32-core system: use 16 workers (50% of cores) instead of 4 (12.5%)
            max_workers = min(len(numpy_tasks), max(4, (os.cpu_count() or 32) // 2))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(_infer_one, mn, k, xv): mn
                           for mn, k, xv in numpy_tasks}
                for fut in as_completed(futures):
                    k, p, s = fut.result()
                    accept(k,p,s)
        else:
            for mn, k, xv in numpy_tasks:
                k, p, s = _infer_one(mn, k, xv)
                accept(k,p,s)

        # pytorch 并行 (CPU环境) / 串行 (GPU/CUDA 不线程安全)
        # In CPU-only environments, PyTorch models can run in parallel safely
        try:
            import torch
            is_cuda_available = torch.cuda.is_available()
        except Exception:
            is_cuda_available = False
        
        if not is_cuda_available and len(pytorch_tasks) > 1:
            # CPU-only environment: parallelize PyTorch models
            # Use 8-12 workers for parallel inference
            max_workers = min(len(pytorch_tasks), 12)
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(_infer_one, mn, k, xv): mn
                           for mn, k, xv in pytorch_tasks}
                for fut in as_completed(futures):
                    k, p, s = fut.result()
                    accept(k,p,s)
        else:
            # CUDA environment or single model: keep serial for thread safety
            for mn, k, xv in pytorch_tasks:
                k, p, s = _infer_one(mn, k, xv)
                accept(k,p,s)

        if return_status:
            return _preds.T, _scores.T, _statuses.T
        return _preds.T, _scores.T

    def valid_model_mask(self):
        """Legacy loaded-capability mask only; NOT per-invocation success status.

        Do not use this mask to authorize aggregation of predict_all placeholders.
        The shared decision requires the returned per-row statuses instead.

        B3 修复：special / skip / 缺失模型不参与集成分数聚合。

        predict_all 的 _scores 初值是 0.5 常量，special 槽位（如 MalGraph）
        从不被覆盖，旧版等权平均会把 0.5 吸收进集成分数（向 0.5 拉近约
        3%）。返回长度 K 的 bool 掩码，True 表示该槽位本轮有真实分数。
        """
        mask = np.zeros(self.K, dtype=bool)
        for k, name in enumerate(self._model_names):
            if self._models.get(name) is None:
                continue
            if self._model_types.get(name) in ("special", "skip"):
                continue
            mask[k] = True
        return mask

    def set_input_contract(self, document):
        """Opt in only after all generic models/topology/actual kwargs are bound.

        Does not publish a candidate or validate a raw runtime extractor.
        """
        from models.input_contract import ModelInputContract
        from models.contract_serialization import validate_binding
        contract = document if isinstance(document, ModelInputContract) else ModelInputContract(document)
        previous = getattr(self, "_input_contract", None)
        self._input_contract = contract
        try:
            validate_binding(self, require_policy=self._decision_policy is not None)
        except Exception:
            self._input_contract = previous
            raise
        return self

    def set_decision_policy(self, document):
        """Install validated decision math only; not a model/input deployment approval."""
        from engine.decision_policy import DecisionPolicy, PolicyError
        policy = document if isinstance(document,DecisionPolicy) else DecisionPolicy(document)
        if not set(policy.model_names).issubset(self._model_names):
            raise PolicyError("policy references models outside this ensemble")
        if getattr(self, "_input_contract", None) is not None:
            if policy.model_names != self._input_contract.model_names:
                raise PolicyError("fixed input and decision allowlists must match exactly")
            self._weights = np.asarray(policy.document["weights"], dtype=np.float64)
        self._decision_policy = policy

    def decide(self, scores, *, statuses, weights=None):
        from engine.decision_policy import for_ensemble
        policy = for_ensemble(self,weights=weights)
        return policy.evaluate(scores,model_names=list(self._model_names),statuses=statuses)

    def ensemble_predict(self, scores, weights=None, *, statuses=None):
        """Strict compatibility tuple; real per-row model statuses are mandatory.

        Use predict_all(return_status=True), then decide for auditable partial or
        undecidable rows. Missing/failed/constant placeholders never cast votes.
        """
        decision = self.decide(scores,statuses=statuses,weights=weights).require_decidable()
        return decision.predictions, decision.scores

    def perspective_groups(self):
        """
        返回 SDD 需要的视角组映射 (含 models + label + attck)

        返回:
            dict: {"V1_byte": {"models": [0,1,2], "label": "Byte-Level", "attck": "T1027.002"}, ...}
        """
        result = {}
        for vname, indices in self._view_indices.items():
            info = {"models": indices}
            vg = config.VIEW_GROUPS.get(vname, {})
            info["label"] = vg.get("label", vname)
            info["attck"] = vg.get("attck", "")
            result[vname] = info
        return result

    @property
    def vg(self):
        """返回 config.VIEW_GROUPS 中属于当前集成的视角组信息"""
        return {k: v for k, v in config.VIEW_GROUPS.items() if k in self._view_indices}

    def per_model_eval(self, views, y, cached_preds=None):
        """
        评估每个子模型的独立性能

        参数:
            views: dict, 视角名→特征矩阵
            y: 真实标签
            cached_preds: 可选, 已缓存的 (N, K) 预测矩阵
        返回:
            dict: {model_name: accuracy, ...}
        """
        if cached_preds is not None:
            preds = cached_preds
        else:
            preds, _ = self.predict_all(views)

        result = {}
        y = np.asarray(y)
        for k, mname in enumerate(self._model_names):
            # preds is (N, K), column k is model k's predictions
            acc = float(np.mean(preds[:, k] == y)) if len(y) > 0 else 0.0
            result[mname] = acc
        return result

    def model_info(self):
        """返回模型摘要信息"""
        lines = [f"  多模型集成: K={self.K}, V={self.V}"]
        for vname, mnames in self.view_groups.items():
            indices = self._view_indices[vname]
            model_status = []
            for mname in mnames:
                m = self._models.get(mname)
                status = "✓" if m is not None else "✗"
                mtype = self._model_types.get(mname, "?")
                model_status.append(f"{mname}({mtype}:{status})")
            lines.append(f"    {vname}: [{','.join(str(i) for i in indices)}] {', '.join(model_status)}")
        return "\n".join(lines)

    def save(self, path):
        """保存集成 (pickle)"""
        if getattr(self, "_input_contract", None) is not None:
            from models.contract_serialization import save_contract_ensemble
            return save_contract_ensemble(self, path)
        state = {
            "available_views": list(self.view_groups.keys()),
            "model_names": self._model_names,
            "model_types": self._model_types,
            "weights": self._weights,
            "decision_policy": self._decision_policy.document if self._decision_policy is not None else None,
            "view_indices": self._view_indices,
            "model_kwargs": self._actual_kwargs,
            "models": {},
        }
        for mname, model in self._models.items():
            if model is None:
                state["models"][mname] = None
            elif self._model_types.get(mname) == "numpy":
                state["models"][mname] = model
            elif self._model_types.get(mname) == "pytorch" and HAS_TORCH:
                state["models"][mname] = model.state_dict()
            else:
                state["models"][mname] = None

        with open(path, "wb") as f:
            pickle.dump(state, f)

    @classmethod
    def load(cls, path, *, expected_input_contract=None, allow_legacy=True):
        """Load trusted-local pickle only; frozen schemas require an expected contract."""
        with open(path, "rb") as f:
            state = pickle.load(f)

        from models.input_contract import ARTIFACT_SCHEMA
        from engine.feature_contract import ContractError
        if not isinstance(state, dict):
            raise ContractError("ensemble state dictionary required")
        if state.get("schema_version") == ARTIFACT_SCHEMA:
            from models.contract_serialization import load_contract_ensemble
            return load_contract_ensemble(cls, state, expected_input_contract)
        if "schema_version" in state:
            raise ContractError("unknown/non-runtime artifact schema; no legacy fallback")
        if expected_input_contract is not None or allow_legacy is not True:
            raise ContractError("legacy artifact has no expected frozen input contract")

        available_views = state.get("available_views", state.get("view_keys", []))
        # 兼容旧格式: 如果存了 "mode" 而非 "available_views"
        if not available_views and "mode" in state:
            available_views = list(state.get("view_indices", {}).keys())

        ens = cls(available_views=available_views)
        ens._model_names = state["model_names"]
        ens._model_types = state["model_types"]
        ens._weights = state["weights"]
        ens._view_indices = state["view_indices"]
        ens.K = len(ens._model_names)
        ens.V = len(ens._view_indices)

        # 从保存状态重建 view_groups
        ens.view_groups = {}
        for vname, indices in ens._view_indices.items():
            ens.view_groups[vname] = [ens._model_names[i] for i in indices]

        ens._actual_kwargs = state.get("model_kwargs", {})

        for mname, saved in state["models"].items():
            if saved is None:
                ens._models[mname] = None
            elif ens._model_types.get(mname) == "numpy":
                ens._models[mname] = saved
            elif ens._model_types.get(mname) == "pytorch" and HAS_TORCH:
                cls_obj, cfg = ens._load_model_class(mname)
                if cls_obj:
                    actual_kw = dict(ens._actual_kwargs.get(mname, cfg["model_kwargs"]))
                    try:
                        init_params = inspect.signature(cls_obj.__init__).parameters
                    except (TypeError, ValueError):
                        init_params = {}
                    if "pretrained" in init_params:
                        actual_kw["pretrained"] = False
                    model = cls_obj(**actual_kw)
                    model.load_state_dict(saved)
                    model.eval()
                    ens._models[mname] = model

        if state.get("decision_policy") is not None:
            ens.set_decision_policy(state["decision_policy"])
        ens._fitted = True
        return ens

    # ════════════════════════════════════════════════════════
    #  CoDefenderC3 核心接口: 预测即感知
    # ════════════════════════════════════════════════════════

    def predict_with_evidence(self, views, sdd_engine, weights=None):
        """
        统一的预测+漂移感知接口.

        不是"先预测再检测"，而是"预测的同时生成漂移证据"：
        每个样本在获得恶意/良性判定的同时，获得其偏离历史
        语义空间的证据向量和漂移类型推断。

        参数:
            views: dict, 视角名→特征矩阵
            sdd_engine: 已校准的 SDDEngine 实例
            weights: 可选 DSIR 权重

        返回:
            result: dict {
                "predictions": (N,) 集成预测 {0, 1}
                "scores": (N,) 集成恶意概率
                "per_model_scores": (N, K) 各模型分数
                "per_model_preds": (N, K) 各模型预测
                "drift_evidence": (N, L) 每样本每层级漂移异常分数
                "sample_drift_type": (N,) 每样本漂移类型
                "anomaly_score": (N,) 综合异常分数
                "is_drift_candidate": (N,) 潜在漂移样本标记
            }

        用法示例:
            result = ens.predict_with_evidence(views, sdd)
            # 对非漂移样本: 直接使用集成预测
            clean = ~result["is_drift_candidate"]
            y_pred[clean] = result["predictions"][clean]
            # 对漂移候选样本: 根据漂移类型采取不同策略
            for n in np.where(result["is_drift_candidate"])[0]:
                if result["sample_drift_type"][n] == "perturbation":
                    # 轻微扰动: 信任模型但降低置信度
                    y_pred[n] = result["predictions"][n]
                elif result["sample_drift_type"][n] == "structural":
                    # 结构重构: 仅信任不受影响的模型
                    ...
        """
        from engine.decision_policy import for_ensemble
        preds, scores, statuses = self.predict_all(views, return_status=True)
        policy = for_ensemble(self, weights=weights)
        decision = policy.evaluate(scores, model_names=list(self._model_names), statuses=statuses).require_decidable()
        if np.all(statuses == "ok"):
            evidence = sdd_engine.score_samples(scores)
        else:
            evidence = dict(drift_evidence=np.zeros((len(scores),3)),
                            sample_drift_type=np.full(len(scores),"none",dtype=object),
                            anomaly_score=np.zeros(len(scores)),is_drift_candidate=np.zeros(len(scores),bool),
                            drift_status="unavailable_partial_model_matrix")
        return dict(predictions=decision.predictions,scores=decision.scores,
                    per_model_scores=scores,per_model_preds=preds,model_statuses=statuses,
                    raw_scores=decision.raw_scores,decision_rows=decision.rows,
                    decision_policy=policy.document,
                    policy_fingerprint=decision.policy_fingerprint,**evidence)
