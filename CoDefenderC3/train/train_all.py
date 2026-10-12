#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
train_all.py — 数据集构建 + 集成训练 / 微调 CoDefenderC3（带逐模型 checkpoint）
（原 train_minimal.py，2026-09-28 更名并简化入口；同日集成 build_minimal_dataset.py）

快速用法
--------
  # ① 数据集已构建好：给定数据集目录 + run-id，扫描目录直接开训（最简形式）
  python CoDefenderC3/train/train_all.py D:/nkproject/data_10k_0917 run-0917

  # run-id 可省略：从目录名自动推导（含日期后缀 _MMDD → run-MMDD，
  # 如 data_10k_0917 → run-0917；无日期后缀 → run-<目录名>）
  python CoDefenderC3/train/train_all.py D:/nkproject/data_10k_0917

  # ② 一条龙：给定裸 PE 源目录 → 先构建数据集 → 构建完直接开训
  #    （源目录 = 平铺的 benign/ + malicious/；路径按实际替换）
  python CoDefenderC3/train/train_all.py \
      --source D:/nkproject/data_test/20260928 --out D:/nkproject/data_test_ds \
      --per-class 0 --mal-ratio 2.0 --months 10 --train-months 7 \
      --views full --force --mode scratch --epochs 20
  #   构建参数：--source/--out/--per-class/--mal-ratio/--months/--train-months/
  #             --views/--allow-partial-de/--force/--link（语义同 build_minimal_dataset.py）
  #   构建返回码非 0 → 立即终止，不会带着旧数据继续训练；
  #   加 --dry-run 只预演构建（不写盘）后退出，不进训练。

  # 旧写法（--dataset/--run-id 旗标）继续兼容
  python CoDefenderC3/train/train_all.py --dataset minimal_dataset --run-id run-x --dry-run

省空间 / 省复制时间：`--link`（同盘硬链接）
------------------------------------------
默认构建把每个样本 copy2 进 <out>，占用 = N × 样本大小（5k 规模 ≈ 25GB 纯冗余），
且 build 每次重跑都会再复制一遍。源目录与 <out> 在**同一卷**时加 `--link`：
样本改为硬链接落盘，与源文件共享 inode，零拷贝、不额外占空间。跨盘（WinError 17）、
VMware 共享目录、文件系统不支持时**自动回退 copy2**，不中断构建，只在第 4 步打印
一次回退原因与 link/复用/回退 计数；manifest.json 记 `sample_placement` 备查。

  # 一条龙 + 硬链接（只加一个 --link，其余参数不变）
  python CoDefenderC3/train/train_all.py \
      --source D:/nkproject/data_test/20260928 --out D:/nkproject/ds_0928 \
      --per-class 0 --months 10 --train-months 7 --views full --link \
      --run-id run-0928 --mode scratch --epochs 20

  ⚠ 硬链接与源文件是**同一实体**：就地修改 <out>/<benign|malicious>/<sha256>
    会同时改到源文件（本管线只读样本，正常流程无影响）；反过来删掉源目录
    **不会**影响数据集（inode 仍被数据集引用）。
  ⚠ 只省样本副本的空间；.cache/per_sample、per_month 与 bndb 临时文件照旧产生。
  想复验链接语义与回退行为：python CoDefenderC3/train/_probe_link_place.py（7 组断言）

设计要点（和 run_all.py 的区别）
--------------------------------
1. **不碰生产模型**。`run_all.py --single` 会把 `config.MODEL_PATH` 改写成
   `results/<dataset>/ensemble.pkl`；本脚本默认只写 `CoDefenderC3/runs/<run_id>/`，
   想覆盖生产模型必须显式 `--in-place`（会先备份）。

2. **视角不匹配时"冻结"而不是"删除"**。基线 ensemble.pkl 是 K=33 / V=15。
   本数据集实际取不到的视角，其对应模型**原样从基线继承（冻结）**：不重训、不置 0，
   样本仍保留。输出始终是 15 视角 / 33 槽位的完整集成，可直接被 `/reload-model` 热切换。
   注意：依赖 BinaryNinja 的视角（V6_opcode_seq / V6_opcode_stat / V6_func_embed /
   V7_graph）共 10 个模型槽位（MalGraph 为 special 透传，故 9 个可训练）。
   **本机 `--views full` 能正常提取这 4 个视角**（BN headless 已验证可用），
   因此 32 个可训练模型全部真训、frozen 为空——冻结路径只在 `--views fast`
   或 BN 不可用时才触发。

3. **逐模型 checkpoint**。每训完一个子模型立即落盘 `runs/<run_id>/partial/<model>.pkl`。
   例如 32 个模型训到第 31 个崩溃，`--resume` 只补剩下 1 个。断点粒度 = 单模型。

4. **修掉训练期 early-stopping 的缺陷**。`models/ensemble.py:236-277` 只记录 best_loss
   却从不恢复最优权重（实际用最后一轮）。本脚本保存并恢复最优 state_dict。

5. **等权平均的 0.5 常量问题**。`predict_all` 对"视角缺失"的模型返回 0.5 常量，
   直接按 K 求均值会把分数向 0.5 压缩。本脚本指标一律只对**本轮真正有数据的模型**取均值，
   同时把"基线口径"（含 0.5 填充）作为对照一起报出来。

更多用法
--------
  # 冒烟：看会训练哪些模型、冻结哪些
  python CoDefenderC3/train/train_all.py minimal_dataset --dry-run

  # 从零训练（默认） / 从基线权重继续（仅 pytorch 模型有 warm_start）
  python CoDefenderC3/train/train_all.py minimal_dataset --mode scratch
  python CoDefenderC3/train/train_all.py minimal_dataset --mode finetune

  # 崩溃后续训（run-id 必须与上次一致）
  python CoDefenderC3/train/train_all.py minimal_dataset run-0917 --resume
"""
import argparse
import glob
import hashlib
import inspect
import json
import os
import pickle
import re
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))       # CoDefenderC3/train
REPO_ROOT = os.path.dirname(HERE)                       # CoDefenderC3（仓库根）
for _p in (REPO_ROOT, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import numpy as np  # noqa: E402

import config  # noqa: E402


def hdr(t):
    print("\n" + "=" * 74)
    print("  " + t)
    print("=" * 74)


def sha256_of_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def auc_safe(y, s):
    """AUC，常量分数返回 NaN。"""
    try:
        from sklearn.metrics import roc_auc_score
        y = np.asarray(y)
        if len(set(y.tolist())) < 2:
            return float("nan")
        return float(roc_auc_score(y, s))
    except Exception:
        return float("nan")


def f1_at(y, s, thr):
    p = (np.asarray(s) > thr).astype(int)
    y = np.asarray(y)
    tp = int(((p == 1) & (y == 1)).sum())
    fp = int(((p == 1) & (y == 0)).sum())
    fn = int(((p == 0) & (y == 1)).sum())
    tn = int(((p == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return dict(thr=float(thr), f1=f1, prec=prec, rec=rec, fpr=fpr,
                acc=(tp + tn) / max(len(y), 1), tp=tp, fp=fp, fn=fn, tn=tn)


# ═══════════════════════════════════════════════════════════
#  数据：视角收集 + 训练矩阵拼接（沿用 run_all.py 口径）
# ═══════════════════════════════════════════════════════════

def collect_views_by_month(loader, months):
    """从 per_month 文件名推断每月视角集合（不读内容）。"""
    out = {}
    for m in months:
        loader._build_month_cache(m)
        yp = loader._month_y_path(m)
        if not os.path.exists(yp):
            continue
        pat = os.path.join(loader._month_cache, "m%d_V*.npy" % m)
        names = set()
        for fp in glob.glob(pat):
            mm = re.match(r"m%d_(.+)\.npy" % m, os.path.basename(fp))
            if mm:
                names.add(mm.group(1))
        if names:
            out[m] = names
    return out


def build_matrix(loader, months, views):
    """把多个月的视角拼成 (N, D) 矩阵 + y，并做维度对齐（列少则右侧补零）。"""
    chunks = {vn: [] for vn in views}
    ys = []
    for m in months:
        _, ym = loader.get_month(m)
        if len(ym) == 0:
            continue
        vm = loader.all_views(m)
        if not vm:
            continue
        ok = True
        for vn in views:
            if vn not in vm:
                ok = False
                break
        if not ok:
            print("    [警告] 月 %d 缺少部分视角，跳过该月" % m)
            continue
        for vn in views:
            chunks[vn].append(vm[vn])
        ys.append(ym)
        del vm
    if not ys:
        return {}, np.array([])
    y = np.concatenate(ys)
    mat = {}
    for vn, cs in chunks.items():
        max_d = max(c.shape[1] for c in cs)
        rows = []
        for c in cs:
            if c.shape[1] < max_d:
                pad = np.zeros((c.shape[0], max_d - c.shape[1]), dtype=c.dtype)
                rows.append(np.hstack([c, pad]))
            else:
                rows.append(c)
        mat[vn] = np.vstack(rows)
    return mat, y


# ═══════════════════════════════════════════════════════════
#  单模型训练
# ═══════════════════════════════════════════════════════════

def torch_batch_size(input_dim):
    if input_dim > 100000:
        return 16
    if input_dim > 10000:
        return 32
    if input_dim > 2000:
        return 64
    if input_dim > 500:
        return 256
    return 512


def train_torch_model(cls, kwargs, X, y, *, device, loss_kind, x_dtype,
                      epochs, lr, patience, seed, warm_state=None, verbose=True):
    """自写训练循环：保存并恢复最优权重（修掉 ensemble.py 只记 loss 不恢复的缺陷）。"""
    import torch
    import torch.nn as nn

    torch.manual_seed(seed)
    np.random.seed(seed)

    model = cls(**kwargs).to(device)
    warm_started = False
    if warm_state is not None:
        try:
            missing, unexpected = model.load_state_dict(warm_state, strict=False)
            warm_started = True
            if verbose and (missing or unexpected):
                print("        热启动: missing=%d unexpected=%d"
                      % (len(missing), len(unexpected)))
        except Exception as e:
            print("        热启动失败 (%s)，改为从零训练" % type(e).__name__)

    X_t = torch.tensor(X, dtype=torch.long if x_dtype == "long" else torch.float32)
    y_t = torch.tensor(y, dtype=torch.float32)

    n = len(X_t)
    bs = torch_batch_size(X_t.shape[1] if X_t.ndim > 1 else 1)
    n_val = min(max(n // 10, 1), max(n // 2, 1))
    g = torch.Generator().manual_seed(seed)
    perm0 = torch.randperm(n, generator=g)
    val_idx, train_idx = perm0[:n_val], perm0[n_val:]
    if len(train_idx) == 0:
        train_idx = perm0
    X_val, y_val = X_t[val_idx], y_t[val_idx]

    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.BCELoss() if loss_kind == "bce" else nn.CrossEntropyLoss()

    best_val = float("inf")
    best_state = None
    best_epoch = -1
    wait = 0
    for ep in range(epochs):
        model.train()
        perm = train_idx[torch.randperm(len(train_idx), generator=g)]
        for i in range(0, len(perm), bs):
            idx = perm[i:i + bs]
            xb, yb = X_t[idx].to(device), y_t[idx].to(device)
            opt.zero_grad()
            out = model(xb)
            if isinstance(out, tuple):
                out = out[0]
            if loss_kind == "bce":
                loss = loss_fn(out.squeeze(-1), yb)
            else:
                loss = loss_fn(out, yb.long())
            loss.backward()
            opt.step()
            del xb, yb, out, loss

        model.eval()
        v_sum, v_n = 0.0, 0
        with torch.no_grad():
            for i in range(0, len(X_val), bs):
                xvb = X_val[i:i + bs].to(device)
                yvb = y_val[i:i + bs].to(device)
                vo = model(xvb)
                if isinstance(vo, tuple):
                    vo = vo[0]
                vl = (loss_fn(vo.squeeze(-1), yvb) if loss_kind == "bce"
                      else loss_fn(vo, yvb.long())).item()
                v_sum += vl * len(xvb)
                v_n += len(xvb)
        v_loss = v_sum / max(v_n, 1)

        if v_loss < best_val - 1e-4:
            best_val = v_loss
            best_epoch = ep
            best_state = {k: v.detach().cpu().clone()
                          for k, v in model.state_dict().items()}
            wait = 0
        else:
            wait += 1
            if wait >= patience:
                break

    if best_state is not None:
        model.load_state_dict(best_state)   # ← 关键：恢复最优权重
    model.eval()
    return model, dict(warm_started=warm_started, best_val=best_val,
                       best_epoch=best_epoch, epochs_run=ep + 1,
                       batch_size=bs, n_train=len(train_idx), n_val=n_val)


def train_one(mname, cfg, ens, X, y, *, mode, device, epochs, lr,
              patience, seed):
    """训练单个子模型，返回 (model, info)。"""
    from model_registry import PYTORCH, NUMPY
    from models.ensemble import _input_dtype

    cls = ens._load_model_class(mname)[0]
    if cls is None:
        raise RuntimeError("无法加载模型类: %s" % mname)

    engine = cfg["engine"]
    kwargs = dict(cfg["model_kwargs"])
    Xn = X if isinstance(X, np.ndarray) else np.array(X)

    if engine == NUMPY:
        # 手写 NumPy 模型（DrebinLinear / PEMinerRF / EmberGBDT / OpcodeStatNet ...）
        # 全部在 fit() 内重置状态，没有一个支持 warm_start → finetune 只能退化为 scratch。
        model = cls(**kwargs)
        Xf = Xn if Xn.dtype == np.float32 else Xn.astype(np.float32)
        model.fit(Xf, y)
        return model, dict(warm_started=False, engine="numpy",
                           note="纯 NumPy 实现，无 warm_start 接口",
                           actual_kwargs=dict(kwargs),
                           n_train=int(len(y)))

    if engine == PYTORCH:
        # input_dim 用实际视角列数覆盖（与 ensemble.fit 一致）——
        # 但**只在类真的接受该参数时**：MalConv/MalConv2/ByteTransformer 是 RAW_BYTES
        # 模型，不支持 input_dim。若强行写进 model_kwargs，load() 会
        # TypeError: Malconv.__init__() got an unexpected keyword argument 'input_dim'
        params = inspect.signature(cls.__init__).parameters
        if "input_dim" in params:
            kwargs["input_dim"] = int(Xn.shape[1])
        warm_state = None
        if mode == "finetune":
            base = ens._models.get(mname)
            if base is not None and hasattr(base, "state_dict"):
                try:
                    warm_state = {k: v.detach().cpu() for k, v in base.state_dict().items()}
                except Exception:
                    warm_state = None
        model, info = train_torch_model(
            cls, kwargs, Xn, y, device=device, loss_kind=cfg["loss"],
            x_dtype=_input_dtype(mname), epochs=epochs, lr=lr,
            patience=patience, seed=seed, warm_state=warm_state)
        info.update(engine="pytorch",
                    input_dim=int(Xn.shape[1]) if "input_dim" in kwargs else None,
                    actual_kwargs=dict(kwargs),
                    n_train=info.get("n_train", len(y)))
        return model, info

    raise RuntimeError("未知 engine: %s" % engine)


# ═══════════════════════════════════════════════════════════
#  checkpoint
# ═══════════════════════════════════════════════════════════

def serialize_model(ens, mname, model):
    """与 MultiModelEnsemble.save() 完全相同的序列化约定，保证可被 load() 还原。"""
    if ens._model_types.get(mname) == "numpy":
        return model
    if ens._model_types.get(mname) == "pytorch":
        sd = model.state_dict()
        return {k: (v.detach().cpu() if hasattr(v, "detach") else v)
                for k, v in sd.items()}
    return None


def save_partial(partial_dir, mname, payload):
    os.makedirs(partial_dir, exist_ok=True)
    dst = os.path.join(partial_dir, mname + ".pkl")
    tmp = dst + ".tmp"
    with open(tmp, "wb") as f:
        pickle.dump(payload, f)
    os.replace(tmp, dst)
    return dst


def load_partial(partial_dir, mname):
    p = os.path.join(partial_dir, mname + ".pkl")
    if not os.path.exists(p):
        return None, None
    with open(p, "rb") as f:
        d = pickle.load(f)
    return d.get("model"), d.get("info")


KNOWN_STATE_KEYS = {"available_views", "model_names", "model_types", "weights",
                    "view_indices", "model_kwargs", "models"}


def save_ensemble_preserving(ens, path, extra_state=None, special_models=None):
    """与 MultiModelEnsemble.save() 同 schema，但保留 save() 会丢掉的顶层键。

    `models/ensemble.py:498-520` 的 save() 只写 7 个已知键，且只遍历 `self._models`
    → 基线里的 `special_state`（MalGraph 权重载体）与 `models['MalGraph']` 的
    `'SPECIAL_PLACEHOLDER'` 占位值都会被静默丢光，输出就不是等价替换件了。
    这里显式补回；同时把 torch state_dict 全部搬到 CPU，避免存成 CUDA 张量。
    """
    state = {
        "available_views": list(ens.view_groups.keys()),
        "model_names": ens._model_names,
        "model_types": ens._model_types,
        "weights": ens._weights,
        "view_indices": ens._view_indices,
        "model_kwargs": ens._actual_kwargs,
        "models": {},
    }
    for mname, model in ens._models.items():
        mt = ens._model_types.get(mname)
        if model is None:
            state["models"][mname] = None
        elif mt == "numpy":
            state["models"][mname] = model
        elif mt == "pytorch":
            state["models"][mname] = {
                k: (v.detach().cpu() if hasattr(v, "detach") else v)
                for k, v in model.state_dict().items()}
        else:
            state["models"][mname] = None
    for mname, mv in (special_models or {}).items():
        state["models"].setdefault(mname, mv)
    state.update(extra_state or {})

    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        pickle.dump(state, f)
    os.replace(tmp, path)
    return state


# ═══════════════════════════════════════════════════════════
#  主流程
# ═══════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="数据集上的集成训练 / 微调（带 checkpoint），支持一条龙（先构建后训练）。\n"
                    "两种用法:\n"
                    "  1) python train_all.py <数据集目录> [run-id]                # 数据集已构建好\n"
                    "  2) python train_all.py --source <裸PE源目录> [--out 目录]   # 先构建再训练\n"
                    "构建参数 --link：同盘时样本用硬链接落盘（零拷贝，省一份样本副本）；\n"
                    "详见脚本顶部 docstring「省空间 / 省复制时间：--link」一节。")
    ap.add_argument("dataset_pos", nargs="?", default=None,
                    help="数据集目录（含 metadata.json），可带日期后缀如 data_10k_0917")
    ap.add_argument("run_id_pos", nargs="?", default=None,
                    help="run-id（省略时从目录名自动推导，如 data_10k_0917 → run-0917）")
    ap.add_argument("--dataset", default=None, help="数据集目录（旗标写法，与位置参数二选一）")
    ap.add_argument("--baseline", default=None,
                    help="基线模型 (默认 config.MODEL_PATH = CoDefenderC3/ensemble.pkl)")
    ap.add_argument("--mode", choices=["scratch", "finetune"], default="scratch")
    ap.add_argument("--models", default="", help="只训练这些模型（逗号分隔）")
    ap.add_argument("--exclude", default="", help="排除这些模型（逗号分隔）")
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--lr", type=float, default=None, help="默认 scratch=1e-3, finetune=1e-4")
    ap.add_argument("--patience", type=int, default=3)
    ap.add_argument("--seed", type=int, default=config.SEED)
    ap.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    ap.add_argument("--run-dir", default=None, help="输出根目录 (默认 CoDefenderC3/runs)")
    ap.add_argument("--run-id", default=None, help="run-id（旗标写法，与位置参数二选一）")
    ap.add_argument("--resume", action="store_true", help="复用已有 partial checkpoint")
    # ── 一条龙：给定裸 PE 源目录 → 先构建数据集 → 直接训练 ──
    ap.add_argument("--source", default=None,
                    help="【一条龙模式】裸 PE 源目录（含 malicious/ benign/）。"
                         "给定后先自动构建数据集（到 --out），构建完成直接开训，"
                         "无需再手动跑 build_minimal_dataset.py")
    ap.add_argument("--out", default=None,
                    help="一条龙模式下数据集输出目录（默认 <仓库>/minimal_dataset）")
    ap.add_argument("--per-class", type=int, default=0,
                    help="构建：每类上限（0=全取）；配合 --mal-ratio>1 时表示**良性**上限")
    ap.add_argument("--mal-ratio", type=float, default=1.0,
                    help="构建：恶意:良性配比（默认 1.0=严格1:1 截断；2.0=良性全取、恶意按比例取）")
    ap.add_argument("--months", type=int, default=10, help="构建：合成月份桶数")
    ap.add_argument("--train-months", type=int, default=7,
                    help="构建：前 N 个月桶做训练（其余评估），如 7/10 ≈ 7:3 划分")
    ap.add_argument("--views", choices=["full", "fast"], default="full",
                    help="构建：full=15 视角(含 BinaryNinja)；fast=仅 11 快速视角")
    ap.add_argument("--allow-partial-de", action="store_true",
                    help="构建：允许 D/E 覆盖率<100%% 仍继续（缺失样本被归档丢弃）")
    ap.add_argument("--link", action="store_true",
                    help="构建：样本落盘优先硬链接（同盘零拷贝/不占额外空间），"
                         "跨盘或共享目录自动回退 copy2")
    ap.add_argument("--force", action="store_true",
                    help="构建：输出目录非空也继续（不删已有特征缓存，同路径命中跳过）")
    ap.add_argument("--weighting", choices=["equal", "auc"], default="equal")
    ap.add_argument("--threshold-grid", default="0.3,0.4,0.5,0.6,0.7,0.8")
    ap.add_argument("--preserve-extra-keys", dest="preserve_extra_keys",
                    action="store_true", default=True,
                    help="保留基线 pkl 里 save() 会丢掉的顶层键（默认开）")
    ap.add_argument("--no-preserve-extra-keys", dest="preserve_extra_keys",
                    action="store_false")
    ap.add_argument("--in-place", action="store_true",
                    help="训练后覆盖生产模型 config.MODEL_PATH（会先备份）")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    t0 = time.time()

    # ── 一条龙模式：--source 给定 → 先构建数据集，构建产物即训练入口 ──
    run_id_hint = None
    if args.source:
        # 位置参数在一条龙模式下没有"数据集"可指 → 视为 run-id
        if args.dataset_pos and not args.run_id_pos and not args.run_id:
            run_id_hint = args.dataset_pos
            print("[i] 一条龙模式：位置参数 %r 视为 run-id" % run_id_hint)
        import build_minimal_dataset as _bd
        out_dir = args.out or os.path.join(_bd.PROJECT_ROOT, "minimal_dataset")
        build_argv = [
            "--source", args.source,
            "--out", out_dir,
            "--per-class", str(args.per_class),
            "--mal-ratio", str(args.mal_ratio),
            "--months", str(args.months),
            "--train-months", str(args.train_months),
            "--views", args.views,
            "--seed", str(args.seed),
        ]
        if args.allow_partial_de:
            build_argv.append("--allow-partial-de")
        if args.link:
            build_argv.append("--link")
        if args.force:
            build_argv.append("--force")
        if args.dry_run:
            build_argv.append("--dry-run")
        hdr("0. 构建数据集（一条龙）")
        print("  " + " ".join(build_argv))
        rc_build = _bd.main(build_argv)
        if rc_build != 0:
            print("[X] 数据集构建失败 (exit=%d)，终止训练" % rc_build)
            return rc_build
        if args.dry_run:
            print("\n[i] --dry-run：仅预演构建，不写盘，故不进入训练。")
            return 0
        ds_raw = out_dir
    else:
        ds_raw = args.dataset_pos or args.dataset
        if not ds_raw:
            print("[X] 缺少数据集目录。用法: python train_all.py <数据集目录> [run-id]"
                  "  或一条龙: python train_all.py --source <裸PE源目录> [--out <输出目录>]")
            return 2
    dataset = os.path.normpath(os.path.abspath(ds_raw))

    run_id = args.run_id_pos or args.run_id or run_id_hint
    if not run_id:
        # 从目录名自动推导：尾部日期后缀 _MMDD → run-MMDD；否则 run-<目录名>
        dirname = os.path.basename(dataset.rstrip("\\/"))
        m = re.search(r"_+(\d{4})$", dirname)
        run_id = ("run-" + m.group(1)) if m else ("run-" + dirname)
        print("[i] 未指定 run-id，自动推导: %s" % run_id)

    baseline = os.path.normpath(os.path.abspath(args.baseline or config.MODEL_PATH))
    run_dir_root = os.path.normpath(os.path.abspath(
        args.run_dir or os.path.join(REPO_ROOT, "runs")))
    lr = args.lr if args.lr is not None else (1e-4 if args.mode == "finetune" else 1e-3)

    if not os.path.isfile(os.path.join(dataset, "metadata.json")):
        print("[X] %s 缺少 metadata.json。可用一条龙模式: "
              "python train_all.py --source <裸PE源目录> --out %s" % (dataset, dataset))
        return 1
    if not os.path.isfile(baseline):
        print("[X] 基线模型不存在: %s" % baseline)
        return 1

    device = "cuda" if args.device == "auto" else args.device
    if device == "cuda":
        try:
            import torch
            if not torch.cuda.is_available():
                print("  [警告] CUDA 不可用，回退 CPU")
                device = "cpu"
        except Exception:
            device = "cpu"

    hdr("1. 载入基线模型")
    print("  基线: %s (%.1f MB)" % (baseline, os.path.getsize(baseline) / 1e6))
    base_sha = sha256_of_file(baseline)
    print("  sha256: %s" % base_sha[:32])

    # 先单独读一次原始 pickle，抓出 save() 不透传的顶层键（如 special_state）
    # 与 special 模型的占位值 → 输出与基线同 schema，可直接热切换。
    extra_state, special_models = {}, {}
    if args.preserve_extra_keys:
        t = time.time()
        with open(baseline, "rb") as f:
            raw = pickle.load(f)
        extra_state = {k: v for k, v in raw.items() if k not in KNOWN_STATE_KEYS}
        special_models = {m: v for m, v in (raw.get("models") or {}).items()
                          if isinstance(v, str)}
        del raw
        print("  基线附加顶层键: %s" % (list(extra_state) or "无"))
        print("  special 占位模型: %s" % (list(special_models) or "无"))
        print("  原始 schema 读取 %.1fs" % (time.time() - t))

    from models.ensemble import MultiModelEnsemble
    t = time.time()
    ens = MultiModelEnsemble.load(baseline)
    print("  载入完成 %.1fs → K=%d, V=%d, 可用模型 %d/%d"
          % (time.time() - t, ens.K, ens.V,
             sum(1 for v in ens._models.values() if v is not None), ens.K))

    hdr("2. 载入最小数据集")
    from data_loader import create_loader
    loader, ftype = create_loader(dataset)
    print("  feature_type=%s  样本 %d (恶 %d / 良 %d)"
          % (ftype, len(loader.samples),
             sum(1 for s in loader.samples if s["label"] == 1),
             sum(1 for s in loader.samples if s["label"] == 0)))
    print("  训练月份 %s / 评估月份 %s" % (loader.train_months, loader.eval_months))

    views_train = collect_views_by_month(loader, loader.train_months)
    views_eval = collect_views_by_month(loader, loader.eval_months)
    if not views_train:
        print("[X] 训练月份没有任何视角缓存。")
        return 1
    ds_views = set.intersection(*[views_train[m] for m in views_train])
    for m, vs in views_eval.items():
        ds_views &= vs
    ds_views = sorted(ds_views)
    print("  数据集可用视角 (%d): %s" % (len(ds_views), ", ".join(ds_views)))

    # ── 3. 划分可训练 / 冻结 ──
    hdr("3. 可训练 / 冻结 划分")
    trainable, frozen = [], []
    view_of = {}
    for vname, mnames in ens.view_groups.items():
        for mname in mnames:
            view_of[mname] = vname
            (trainable if vname in ds_views else frozen).append(mname)

    only = set(x.strip() for x in args.models.split(",") if x.strip())
    excl = set(x.strip() for x in args.exclude.split(",") if x.strip())
    if only:
        trainable = [m for m in trainable if m in only]
    if excl:
        trainable = [m for m in trainable if m not in excl]

    # special 管线模型（MalGraph）不走通用 fit，原样保留基线里的占位值
    passthrough = [m for m in trainable if ens._model_types.get(m) == "special"]
    trainable = [m for m in trainable if m not in passthrough]

    print("  可训练 %d 个（视角有数据）:" % len(trainable))
    cur = None
    for m in trainable:
        if view_of[m] != cur:
            cur = view_of[m]
            print("      [%s]" % cur)
        print("        - %s (%s)" % (m, ens._model_types.get(m)))
    print("  冻结 %d 个（视角缺失，原样继承基线权重）:" % len(frozen))
    cur = None
    for m in frozen:
        if view_of[m] != cur:
            cur = view_of[m]
            print("      [%s]" % cur)
        print("        - %s (%s)" % (m, ens._model_types.get(m)))
    if frozen:
        dv = sorted(set(view_of[m] for m in frozen))
        print("\n  ⚠ 本数据集没有这些视角: %s" % ", ".join(dv))
        print("    → 对应 %d 个模型从基线**冻结继承**（不重训、不置 0、不删除）。"
              % len(frozen))
        print("    它们在 predict_all 里会保持 0.5 常量，评估指标已自动排除无数据模型。")
        print("    若要训练它们，用 build_minimal_dataset.py --views full 重建数据集"
              "（需 BinaryNinja 可用）。")
    if passthrough:
        print("\n  ℹ special 管线模型（不走通用 fit，原样保留基线占位值）: %s"
              % ", ".join(passthrough))

    if args.dry_run:
        print("\n[dry-run] 未训练任何模型。")
        return 0

    # ── 4. run 目录 + checkpoint ──
    run_dir = os.path.join(run_dir_root, run_id)
    partial_dir = os.path.join(run_dir, "partial")
    os.makedirs(partial_dir, exist_ok=True)
    hdr("4. 运行目录")
    print("  run_id : %s" % run_id)
    print("  run_dir: %s" % run_dir)
    print("  resume : %s" % args.resume)

    # 若本次要训练的模型里已有旧 checkpoint 但未 --resume → 明确拒绝，避免误当断点续训
    existing = [m for m in trainable if os.path.exists(os.path.join(partial_dir, m + ".pkl"))]
    if existing and not args.resume:
        print("\n  [X] 检测到 %d 个已存在的 checkpoint 但未指定 --resume：" % len(existing))
        for m in existing[:5]:
            print("      %s.pkl" % m)
        print("      加 --resume 复用它，或换一个 --run-id。")
        return 1

    # ── 5. 训练矩阵 ──
    hdr("5. 拼接训练矩阵")
    views_tr, y_tr = build_matrix(loader, loader.train_months, ds_views)
    if not views_tr:
        print("[X] 训练矩阵为空。")
        return 1
    N = len(y_tr)
    print("  训练: %d 样本 (恶 %d / 良 %d) × %d 视角"
          % (N, int((y_tr == 1).sum()), int((y_tr == 0).sum()), len(views_tr)))
    for vn in sorted(views_tr):
        a = views_tr[vn]
        print("      %-16s %s %s %.0f MB"
              % (vn, a.shape, a.dtype, a.nbytes / 1e6))

    if len(set(y_tr.tolist())) < 2:
        print("[X] 训练集只有单一类别，无法训练。")
        return 1

    # ── 6. 逐模型训练 + checkpoint ──
    hdr("6. 逐模型训练（每完成一个立即落盘 checkpoint）")
    from model_registry import get_model_config
    progress_path = os.path.join(run_dir, "progress.json")
    progress = {"run_id": run_id, "mode": args.mode, "dataset": dataset,
                "baseline": baseline, "baseline_sha256": base_sha,
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "trainable": trainable, "frozen": frozen,
                "passthrough": passthrough, "done": {}}
    if args.resume and os.path.exists(progress_path):
        with open(progress_path, encoding="utf-8") as f:
            old = json.load(f)
        progress["done"] = {k: v for k, v in old.get("done", {}).items() if k in trainable}
        print("  复用旧进度: 已完成 %d 个" % len(progress["done"]))

    def flush_progress():
        progress["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        tmp = progress_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(progress, f, ensure_ascii=False, indent=2)
        os.replace(tmp, progress_path)

    flush_progress()

    n_ok, n_fail = 0, 0
    for i, mname in enumerate(trainable, 1):
        vn = view_of[mname]
        tag = "[%2d/%2d] %-22s (%-16s)" % (i, len(trainable), mname, vn)
        done = progress["done"].get(mname)
        if args.resume and done and os.path.exists(os.path.join(partial_dir, mname + ".pkl")):
            m, info = load_partial(partial_dir, mname)
            if m is not None:
                ens._models[mname] = m
                print("%s 跳过（checkpoint 已存在, %.1fs）" % (tag, done.get("seconds", 0)))
                n_ok += 1
                continue
        try:
            cfg = get_model_config(mname)
        except KeyError:
            print("%s 跳过（未注册）" % tag)
            continue

        t = time.time()
        try:
            model, info = train_one(
                mname, cfg, ens, views_tr[vn], y_tr, mode=args.mode,
                device=device, epochs=args.epochs, lr=lr, patience=args.patience,
                seed=args.seed)
        except Exception as e:
            n_fail += 1
            print("%s 失败: %s: %s" % (tag, type(e).__name__, e))
            progress["done"][mname] = {"status": "failed",
                                       "error": "%s: %s" % (type(e).__name__, e)}
            flush_progress()
            continue

        elapsed = time.time() - t
        ens._models[mname] = model
        # 用**实际**构造 kwargs 覆盖，保证 load() 能原样重建：
        # 只写类真正接受的参数（RAW_BYTES 模型不接受 input_dim）。
        akw = (info or {}).get("actual_kwargs")
        if akw is not None:
            ens._actual_kwargs[mname] = dict(akw)

        payload = {"model": serialize_model(ens, mname, model), "info": info,
                   "view": vn, "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "mode": args.mode, "dataset_sha": sha256_of_file(
                       os.path.join(dataset, "metadata.json"))}
        save_partial(partial_dir, mname, payload)
        info = dict(info or {})
        info.update(status="ok", seconds=round(elapsed, 1))
        progress["done"][mname] = info
        flush_progress()
        n_ok += 1
        print("%s 完成 %.1fs  warm_start=%s  best_epoch=%s"
              % (tag, elapsed, info.get("warm_started"), info.get("best_epoch")))

    print("\n  训练完成: 成功 %d / 失败 %d / 共 %d" % (n_ok, n_fail, len(trainable)))
    available = sum(1 for v in ens._models.values() if v is not None)
    print("  集成可用模型: %d/%d" % (available, ens.K))

    # ── 7. 评估 ──
    hdr("7. 留出月份评估")
    active = [k for k, m in enumerate(ens._model_names)
              if view_of.get(m) in ds_views and ens._models.get(m) is not None]
    print("  参与集成的有效模型: %d / %d（其余视角无数据，predict_all 会返回 0.5 常量，已排除）"
          % (len(active), ens.K))

    views_ev, y_ev = build_matrix(loader, loader.eval_months, ds_views)
    metrics = {}
    if views_ev and len(y_ev):
        print("  评估集: %d 样本 (恶 %d / 良 %d)"
              % (len(y_ev), int((y_ev == 1).sum()), int((y_ev == 0).sum())))
        preds_ev, scores_ev = ens.predict_all(views_ev)

        print("\n  %-24s %-8s %-8s %-8s" % ("模型", "AUC", "训练AUC", "状态"))
        preds_tr_all = None
        if len(views_tr):
            preds_tr_all, scores_tr_all = ens.predict_all(views_tr)
        per_model = {}
        for k in active:
            mname = ens._model_names[k]
            a_ev = auc_safe(y_ev, scores_ev[:, k])
            a_tr = (auc_safe(y_tr, scores_tr_all[:, k])
                    if preds_tr_all is not None else float("nan"))
            per_model[mname] = {"auc_eval": a_ev, "auc_train": a_tr,
                                "mean_score": float(np.mean(scores_ev[:, k]))}
            print("  %-24s %-8.4f %-8.4f %s"
                  % (mname, a_ev, a_tr,
                     "★" if np.isfinite(a_ev) and a_ev >= 0.9 else ""))

        # 加权方式
        if args.weighting == "auc":
            w = np.zeros(ens.K, dtype=np.float64)
            for k in active:
                a = per_model[ens._model_names[k]]["auc_eval"]
                w[k] = max(0.0, (a - 0.5)) ** 2 if np.isfinite(a) else 0.0
            if w.sum() <= 0:
                w = np.zeros(ens.K); w[active] = 1.0 / len(active)
            else:
                w = w / w.sum()
        else:
            w = np.zeros(ens.K, dtype=np.float64)
            w[active] = 1.0 / len(active)

        thrs = [float(x) for x in args.threshold_grid.split(",") if x.strip()]
        def eval_set(yy, sc, label):
            ens_s = (sc * w[None, :]).sum(axis=1)
            auc = auc_safe(yy, ens_s)
            rows = [f1_at(yy, ens_s, t) for t in thrs]
            best = max(rows, key=lambda r: r["f1"])
            print("  %-22s AUC=%.4f  最佳阈值=%s F1=%.4f (P=%.3f R=%.3f FPR=%.3f)"
                  % (label, auc, best["thr"], best["f1"], best["prec"],
                     best["rec"], best["fpr"]))
            rows05 = f1_at(yy, ens_s, 0.5)
            print("  %-22s @0.5: F1=%.4f FPR=%.3f Acc=%.4f"
                  % ("", rows05["f1"], rows05["fpr"], rows05["acc"]))
            return dict(auc=auc, sweep=rows, best=best, at_0p5=rows05)

        metrics["ensemble_active_w"] = eval_set(y_ev, scores_ev, "[有效模型] 评估")
        metrics["ensemble_active_w_train"] = eval_set(y_tr, scores_tr_all, "[有效模型] 训练")

        # 基线口径对照：全部 K 个模型等权（含 0.5 常量填充）
        w_all = np.ones(ens.K) / ens.K
        ens_all = (scores_ev * w_all[None, :]).sum(axis=1)
        metrics["ensemble_all_k"] = dict(
            auc=auc_safe(y_ev, ens_all), **f1_at(y_ev, ens_all, 0.5))
        print("  %-22s AUC=%.4f  @0.5: F1=%.4f FPR=%.3f  ← 含 0.5 填充的基线口径"
              % ("[全 K 等权] 评估", metrics["ensemble_all_k"]["auc"],
                 metrics["ensemble_all_k"]["f1"], metrics["ensemble_all_k"]["fpr"]))
        metrics["per_model"] = per_model
    else:
        print("  评估月份无数据，跳过。")

    # ── 8. 保存 ──
    hdr("8. 保存结果")
    if args.weighting == "auc" and metrics:
        ens._weights = w
        print("  集成权重已按 AUC 重算（AUC<0.5 的模型权重为 0）")
    out_pkl = os.path.join(run_dir, "ensemble.pkl")
    saved_state = save_ensemble_preserving(ens, out_pkl, extra_state, special_models)
    print("  %s (%.1f MB)" % (out_pkl, os.path.getsize(out_pkl) / 1e6))
    print("  schema: %s" % sorted(saved_state.keys()))
    print("  槽位: models=%d 条（含 special 占位 %s）"
          % (len(saved_state["models"]), list(special_models) or "无"))

    manifest = {
        "run_id": run_id, "mode": args.mode,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": dataset,
        "dataset_metadata_sha256": sha256_of_file(os.path.join(dataset, "metadata.json")),
        "baseline": baseline, "baseline_sha256": base_sha,
        "baseline_bytes": os.path.getsize(baseline),
        "output": out_pkl, "output_bytes": os.path.getsize(out_pkl),
        "output_schema_keys": sorted(saved_state.keys()),
        "preserved_extra_keys": sorted(extra_state.keys()),
        "special_placeholder_models": sorted(special_models.keys()),
        "K": ens.K, "V": ens.V,
        "dataset_views": ds_views,
        "trainable": trainable, "frozen": frozen, "passthrough": passthrough,
        "n_train": int(N), "n_eval": int(len(y_ev)) if len(y_ev) else 0,
        "hyper": {"epochs": args.epochs, "lr": lr, "patience": args.patience,
                  "seed": args.seed, "device": device, "weighting": args.weighting},
        "per_model_status": progress["done"],
        "metrics": metrics,
        "elapsed_seconds": round(time.time() - t0, 1),
        "note": ("可训练集合 = 数据集有的视角；其余模型原样继承基线（冻结）。"
                 "指标按'本轮真正有数据的模型'重新归一化，避免 0.5 常量稀释集成分数。"),
    }
    man_path = os.path.join(run_dir, "manifest.json")
    with open(man_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print("  %s" % man_path)
    flush_progress()

    if args.in_place:
        bak = baseline + ".bak-%s" % time.strftime("%Y%m%d-%H%M%S")
        shutil.copy2(baseline, bak)
        shutil.copy2(out_pkl, baseline)
        print("\n  ⚠ 已覆盖生产模型（备份: %s）" % bak)
        print("     热切换: POST /reload-model   （不传 model_path 即原地重载）")
    else:
        print("\n  （未触碰生产模型 %s；如需替换用 --in-place，或走 /reload-model?model_path=）"
              % baseline)

    hdr("完成")
    print("  总耗时 %.1fs" % (time.time() - t0))
    return 0 if n_fail == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
