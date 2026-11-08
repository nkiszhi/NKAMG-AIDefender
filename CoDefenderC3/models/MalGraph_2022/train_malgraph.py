# -*- coding: utf-8 -*-
"""MalGraph 训练（吃 rebuild_smda.py 产出的 .pt）。

仓库里原本**没有** MalGraph 的训练脚本（只有特征抽取 + .pt 转换），
而 BN → SMDA 切换后特征口径全变、旧权重已作废 —— 必须补上训练环节。

模型结构与推理侧默认保持一致（engine/app.py::DEFAULT_MALGRAPH_PARAMS）：

    gnn_type=graphsage, pool=global_max_pool, acfg_init_dims=11,
    cfg_filters=128-128-128, fcg_filters=128-128-128, dropout=0.3

用法
----
    python models/MalGraph_2022/train_malgraph.py --epochs 30

产物：models/MalGraph_2022/saved/best_model.pt（含指纹）

2026-11-07
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

MALGRAPH_DIR = os.path.join(ROOT, "models", "MalGraph_2022")
SAVED_DIR = os.path.join(MALGRAPH_DIR, "saved")
PT_DIR = os.path.join(SAVED_DIR, "pt_files")
VOCAB_OUT = os.path.join(SAVED_DIR, "train_external_function_name_vocab.jsonl")
CKPT_OUT = os.path.join(SAVED_DIR, "best_model.pt")

# 与 engine/app.py::DEFAULT_MALGRAPH_PARAMS 保持一致
DEFAULT_PARAMS = {
    "gnn_type": "graphsage",
    "pool_type": "global_max_pool",
    "acfg_init_dims": 11,
    "cfg_filters": "128-128-128",
    "fcg_filters": "128-128-128",
    "number_classes": 2,
    "dropout_rate": 0.3,
    "ablation_models": "none",
}


def load_samples(pt_dir: str):
    """读 .pt 样本（跳过没有本地函数的空样本）。"""
    import torch
    from torch_geometric.data import Data

    out = []
    names = sorted(f for f in os.listdir(pt_dir) if f.endswith(".pt"))
    for fn in names:
        try:
            d = torch.load(os.path.join(pt_dir, fn), weights_only=False)
        except Exception as e:
            print("[load] 跳过 %s: %s" % (fn, e))
            continue
        if not getattr(d, "local_acfgs", None):
            continue
        out.append(d)
    return out


def split_samples(samples, val_ratio: float, seed: int = 20261107):
    """按标签分层切分（确定性）。"""
    rng = random.Random(seed)
    by_label = {}
    for s in samples:
        lab = int(s.targets.item()) if hasattr(s.targets, "item") else int(s.targets)
        by_label.setdefault(lab, []).append(s)
    train, val = [], []
    for lab, items in sorted(by_label.items()):
        items = list(items)
        rng.shuffle(items)
        n_val = int(round(len(items) * val_ratio))
        val += items[:n_val]
        train += items[n_val:]
    return train, val


def make_batch(batch_samples, device):
    """把若干样本拼成模型 forward 需要的四件套。"""
    import torch
    from torch_geometric.data import Batch

    local = []
    for s in batch_samples:
        local.extend(list(s.local_acfgs))
    local_batch = Batch.from_data_list(local).to(device)

    positions = [0]
    for s in batch_samples:
        positions.append(positions[-1] + len(s.local_acfgs))

    names = []
    for s in batch_samples:
        nm = getattr(s, "external_names", None)
        if nm is None:
            # 老 .pt 只有索引 —— 模型要的是**名字**（word2idx）
            nm = []
        names.append(list(nm))

    edges = []
    for s in batch_samples:
        fe = getattr(s, "function_edges", [[], []])
        edges.append(fe)
    return local_batch, positions, names, edges


def forward_batch(model, batch_samples, device):
    local_batch, positions, names, edges = make_batch(batch_samples, device)
    out = model(
        real_local_batch=local_batch,
        real_bt_positions=positions,
        bt_external_names=names,
        bt_all_function_edges=edges,
        local_device=device,
    )
    return out


def evaluate(model, samples, device, batch_size=8):
    import torch
    from sklearn.metrics import roc_auc_score

    model.eval()
    ys, ps = [], []
    with torch.no_grad():
        for i in range(0, len(samples), batch_size):
            chunk = samples[i:i + batch_size]
            out = forward_batch(model, chunk, device)
            p = out.reshape(-1).cpu().numpy()
            y = torch.stack([torch.as_tensor(s.targets).reshape(-1)[0].float()
                             for s in chunk]).cpu().numpy()
            ps.extend(p.tolist())
            ys.extend(y.tolist())
    res = {"n": len(ys)}
    if not ys:
        return res
    res["auc"] = float(roc_auc_score(ys, ps)) if len(set(ys)) > 1 else float("nan")
    pred = [1 if p >= 0.5 else 0 for p in ps]
    res["acc"] = sum(1 for a, b in zip(pred, ys) if a == b) / len(ys)
    tp = sum(1 for a, b in zip(pred, ys) if a == 1 and b == 1)
    fp = sum(1 for a, b in zip(pred, ys) if a == 1 and b == 0)
    fn = sum(1 for a, b in zip(pred, ys) if a == 0 and b == 1)
    tn = sum(1 for a, b in zip(pred, ys) if a == 0 and b == 0)
    res["tp"], res["fp"], res["fn"], res["tn"] = tp, fp, fn, tn
    res["recall"] = tp / max(tp + fn, 1)
    res["precision"] = tp / max(tp + fp, 1)
    res["fpr"] = fp / max(fp + tn, 1)
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description="训练 MalGraph（HierarchicalGNN）")
    ap.add_argument("--pt-dir", default=PT_DIR)
    ap.add_argument("--vocab", default=VOCAB_OUT)
    ap.add_argument("--out", default=CKPT_OUT)
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--weight-decay", type=float, default=1e-5)
    ap.add_argument("--val-ratio", type=float, default=0.2)
    ap.add_argument("--max-vocab-size", type=int, default=10000)
    ap.add_argument("--device", default="cuda" if os.environ.get("CUDA_VISIBLE_DEVICES") else "cpu")
    ap.add_argument("--seed", type=int, default=20261107)
    args = ap.parse_args(argv)

    import torch
    import torch.nn.functional as F
    from models.MalGraph_2022.ParameterClasses import ModelParams
    from models.MalGraph_2022.Vocabulary import Vocab
    from models.MalGraph_2022.malgraph import HierarchicalGraphNeuralNetwork
    from models.MalGraph_2022.artifact_guard import (
        current_backend, make_fingerprint, read_manifest, write_manifest,
    )

    torch.manual_seed(args.seed)
    random.seed(args.seed)
    device = torch.device(args.device)
    print("=" * 70)
    print("MalGraph 训练  |  device=%s  backend=%s"
          % (device, current_backend()))
    print("=" * 70)

    samples = load_samples(args.pt_dir)
    if not samples:
        print("没有可用的 .pt 样本（%s）—— 先跑 rebuild_smda.py" % args.pt_dir)
        return 2
    print("[data] %d 个样本" % len(samples))
    train_s, val_s = split_samples(samples, args.val_ratio, args.seed)
    print("[data] train=%d val=%d" % (len(train_s), len(val_s)))

    # 词表必须与推理侧一致：同一份文件 + 同一 max_vocab_size
    vocab = Vocab(freq_file=args.vocab, max_vocab_size=args.max_vocab_size)
    params = ModelParams(**DEFAULT_PARAMS)
    import logging
    logger = logging.getLogger("codefender.malgraph.train")
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)
    model = HierarchicalGraphNeuralNetwork(params, vocab, logger).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr,
                           weight_decay=args.weight_decay)

    best_auc = -1.0
    best_state = None
    hist = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        idx = list(range(len(train_s)))
        random.shuffle(idx)
        tot_loss = 0.0
        nbatch = 0
        t0 = time.time()
        for i in range(0, len(idx), args.batch_size):
            chunk = [train_s[j] for j in idx[i:i + args.batch_size]]
            out = forward_batch(model, chunk, device)
            y = torch.stack([torch.as_tensor(s.targets).reshape(-1)[0].float()
                             for s in chunk]).to(device).reshape(-1, 1)
            loss = F.binary_cross_entropy(out.reshape(-1, 1), y)
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            opt.step()
            tot_loss += float(loss.detach())
            nbatch += 1
        val = evaluate(model, val_s, device, args.batch_size)
        auc = val.get("auc", float("nan"))
        hist.append({"epoch": epoch, "loss": tot_loss / max(nbatch, 1),
                     "val": val})
        print("[epoch %2d] loss=%.4f  val_auc=%s acc=%.3f recall=%.3f fpr=%.3f  (%.1fs)"
              % (epoch, tot_loss / max(nbatch, 1),
                 ("%.4f" % auc) if auc == auc else "n/a",
                 val.get("acc", 0), val.get("recall", 0), val.get("fpr", 0),
                 time.time() - t0))
        if auc == auc and auc > best_auc:
            best_auc = auc
            best_state = {k: v.detach().cpu().clone()
                          for k, v in model.state_dict().items()}

    if best_state is None:
        print("没有有效的验证 AUC，不保存权重")
        return 1

    fp = make_fingerprint(
        backend=current_backend(),
        built_at=datetime.now().isoformat(timespec="seconds"),
        extra={"n_train": len(train_s), "n_val": len(val_s),
               "best_val_auc": best_auc, "params": DEFAULT_PARAMS,
               "max_vocab_size": args.max_vocab_size})
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    torch.save({"state_dict": best_state, "_codefender_meta": fp}, args.out)
    print("[ckpt] %s  (val_auc=%.4f)" % (args.out, best_auc))

    man = read_manifest(SAVED_DIR) or {}
    man.update(fp)
    write_manifest(SAVED_DIR, man)
    with open(os.path.join(SAVED_DIR, "train_history.json"), "w",
              encoding="utf-8") as fw:
        json.dump(hist, fw, ensure_ascii=False, indent=2)
    print("[history] %s" % os.path.join(SAVED_DIR, "train_history.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
