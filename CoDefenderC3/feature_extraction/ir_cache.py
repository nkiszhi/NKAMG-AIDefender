# -*- coding: utf-8 -*-
"""IR 缓存：PE → IR → D/E 特征。

这是 Phase 1 第 5 步 —— 用 IR 替代 .bndb 作为 D/E 抽取的中间产物。

与 .bndb 路径的差异
--------------------
| | .bndb 路径（现状） | IR 路径（本模块） |
|---|---|---|
| 中间产物 | BN 私有数据库 .bndb | 后端中立的 ir.json.gz |
| 单样本体积 | 6.0 MB（最大 36.9 MB） | 105 KB（最大 1.4 MB）→ 小 58 倍 |
| 抽特征是否需要 BN | 需要（要能打开 .bndb） | 不需要（IR 是纯数据） |
| 能否换后端 | 不能（格式是 BN 私有） | 能（SMDA 也能产 IR） |

两个 API 与 bndb 路径一一对应：

* generate_irs_batch(pe_ir_pairs, ...)        ≡ generate_bndbs_batch
* extract_de_from_ir_batch(pe, ir, npz, ...) ≡ extract_de_from_bndb_batch

超时/重试/进度/失败原因的语义与 bndb 路径保持一致。
"""
from __future__ import annotations

import os
import sys
import time


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (ValueError, TypeError):
        return default


def generate_irs_batch(pe_ir_pairs, n_workers=4, batch_size=20,
                       per_file_timeout=None, timeout_base=None):
    """批量 PE → IR 文件。每个子进程处理 batch_size 个文件。

    返回 (ok_set, fail_reasons)：ok_set 是成功的 PE 路径集合，
    fail_reasons 是 {PE 路径: 失败原因}。

    超时预算：单文件 per_file_timeout 秒 + 固定缓冲 timeout_base 秒；
    为 None 时读环境变量 CODEFENDER_IR_TIMEOUT_PER_FILE（默认同 BNDB 的 120）
    与 CODEFENDER_IR_TIMEOUT_BASE（默认 30）。
    """
    from concurrent.futures import ThreadPoolExecutor
    import subprocess as sp, threading

    total = len(pe_ir_pairs)
    if total == 0:
        return set(), {}

    _pf = (per_file_timeout if per_file_timeout is not None
           else _env_int("CODEFENDER_IR_TIMEOUT_PER_FILE",
                         _env_int("CODEFENDER_BNDB_TIMEOUT_PER_FILE", 120)))
    _base = (timeout_base if timeout_base is not None
             else _env_int("CODEFENDER_IR_TIMEOUT_BASE",
                           _env_int("CODEFENDER_BNDB_TIMEOUT_BASE", 30)))

    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "_ir_worker.py")
    if not os.path.exists(script_path):
        raise RuntimeError("缺少 worker 脚本: %s" % script_path)

    lock = threading.Lock()
    progress = [0]
    ok_count = [0]
    fail_count = [0]
    t0 = time.time()
    first_error_printed = [False]
    ok_set = set()
    fail_reasons = {}

    def _run_batch(batch):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False, encoding="utf-8") as tf:
            for pe, ir in batch:
                tf.write("%s\t%s\n" % (pe, ir))
            args_file = tf.name

        pe_set = {pe for pe, _ in batch}
        batch_timeout = _pf * len(batch) + _base
        cflags = 0x08000000 if sys.platform == "win32" else 0
        try:
            proc = sp.run([sys.executable, script_path, args_file],
                          capture_output=True, timeout=batch_timeout,
                          creationflags=cflags)
            stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
            stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
        except sp.TimeoutExpired as e:
            stdout = (e.stdout or b"").decode("utf-8", errors="replace")
            stderr = "TIMEOUT after %ds" % batch_timeout
        except Exception as e:
            stdout = ""
            stderr = str(e)
        finally:
            try: os.remove(args_file)
            except Exception: pass

        reported = set()
        # Windows worker 输出 CRLF；split("\n") 会把 \r 留在路径尾部，
        # 导致成功文件不属于 pe_set，被误报崩溃甚至删除。
        for line in stdout.splitlines():
            parts = line.split("\t", 2)
            if len(parts) >= 2 and parts[1] in pe_set:
                reported.add(parts[1])
                with lock:
                    progress[0] += 1
                    if parts[0] == "OK":
                        ok_count[0] += 1
                        ok_set.add(parts[1])
                    else:
                        fail_count[0] += 1
                        fail_reasons[parts[1]] = (parts[2] if len(parts) > 2
                                                  else "unknown")
                        if not first_error_printed[0]:
                            first_error_printed[0] = True
                            print("\n    首个FAIL: %s" % fail_reasons[parts[1]])
                            if stderr.strip():
                                print("    stderr: %s" % stderr.strip()[:800])

        n_unreported = 0
        timed_out = "TIMEOUT" in stderr
        for pe, ir in batch:
            if pe not in reported:
                with lock:
                    progress[0] += 1
                    fail_count[0] += 1
                    n_unreported += 1
                    fail_reasons[pe] = ("TIMEOUT after %ds" % batch_timeout
                                        if timed_out else "子进程崩溃(unreported)")
                if os.path.exists(ir) \
                        and os.environ.get("CODEFENDER_KEEP_IR") != "1":
                    try: os.remove(ir)
                    except Exception: pass

        if n_unreported > 0 and not first_error_printed[0]:
            first_error_printed[0] = True
            print("\n    %s (%d 个未报告)" % ("子进程超时" if timed_out else "子进程崩溃",
                                             n_unreported))
            if stderr.strip():
                print("    stderr: %s" % stderr.strip()[:800])

        with lock:
            done = progress[0]
            if done % 100 == 0 or done >= total:
                elapsed = time.time() - t0
                rate = done / max(elapsed, 0.01)
                eta = (total - done) / max(rate, 0.01)
                print("\r    IR [%d/%d] %.1f%% (%.1f/s, ETA %.0fs, ok=%d, fail=%d)"
                      % (done, total, done / total * 100.0, rate, eta,
                         ok_count[0], fail_count[0]), end="", flush=True)

    batches = [pe_ir_pairs[i:i + batch_size] for i in range(0, total, batch_size)]
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futs = [pool.submit(_run_batch, b) for b in batches]
        for f in futs:
            f.result()
    print()
    return ok_set, fail_reasons


def _kill(p):
    try:
        p.kill()
    except Exception:
        pass


def extract_de_from_ir_batch(pe_paths, ir_paths, npz_paths, n_workers=4,
                            on_ok=None):
    """从已有 IR 文件批量提取 D+E 并追加进 npz。

    与 extract_de_from_bndb_batch 等价，但有三个差别：

    1. worker 不加载 BinaryNinja（IR 是纯数据）→ 启动快、无 BN 内存泄漏，
       所以不需要「每 N 个文件重启 worker」那套机制；
    2. 抽特征不再依赖 BN 许可 —— 这是 IR 路径最大的运维价值；
    3. 单文件超时时用看门狗杀 worker（读行随之返回 EOF），然后重启重试。

    参数:
        on_ok: 可选回调 on_ok(pe_path)，每个文件成功后立即调用（断点续传日志用）。
    """
    import subprocess as sp, threading, queue as queue_mod

    total = len(pe_paths)
    if total == 0:
        return set(), {}

    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "_ir_de_worker.py")
    if not os.path.exists(script_path):
        raise RuntimeError("缺少 worker 脚本: %s" % script_path)

    task_q = queue_mod.Queue()
    for t in zip(pe_paths, ir_paths, npz_paths):
        task_q.put(t)

    PER_FILE_TIMEOUT = _env_int("CODEFENDER_DE_PER_FILE_TIMEOUT", 180)

    lock = threading.Lock()
    ok_set = set()
    fail_reasons = {}
    progress = [0]
    ok_count = [0]
    fail_count = [0]
    t0 = time.time()

    def _spawn():
        cflags = 0x08000000 if sys.platform == "win32" else 0
        return sp.Popen([sys.executable, script_path], stdin=sp.PIPE,
                        stdout=sp.PIPE, stderr=sp.DEVNULL,
                        text=True, encoding="utf-8", errors="replace",
                        creationflags=cflags)

    def _report(pe, status, reason=""):
        with lock:
            progress[0] += 1
            if status == "OK":
                ok_count[0] += 1
                ok_set.add(pe)
                if on_ok is not None:
                    try:
                        on_ok(pe)
                    except Exception:
                        pass
            else:
                fail_count[0] += 1
                if pe:
                    fail_reasons[pe] = reason
            done = progress[0]
            if done % 20 == 0 or done == 1 or done >= total:
                elapsed = time.time() - t0
                rate = done / max(elapsed, 0.01)
                eta = (total - done) / max(rate, 0.01)
                print("\r    D+E(IR) [%d/%d] %.1f%% (%.1f/s, ETA %.0fs, ok=%d, fail=%d)"
                      % (done, total, done / total * 100.0, rate, eta,
                         ok_count[0], fail_count[0]), end="", flush=True)

    def _worker():
        proc = None
        try:
            while True:
                try:
                    pe, ir, npz = task_q.get_nowait()
                except queue_mod.Empty:
                    return
                done = False
                for attempt in range(2):
                    try:
                        if proc is None or proc.poll() is not None:
                            proc = _spawn()
                            proc.stdout.readline()          # READY
                        proc.stdin.write("%s\t%s\t%s\n" % (pe, ir, npz))
                        proc.stdin.flush()
                        watchdog = threading.Timer(PER_FILE_TIMEOUT, _kill, [proc])
                        watchdog.daemon = True
                        watchdog.start()
                        try:
                            line = proc.stdout.readline()
                        finally:
                            watchdog.cancel()
                        if not line:
                            proc = None              # worker 没了 → 重启重试
                            continue
                        parts = line.rstrip("\n").split("\t")
                        if parts and parts[0] == "OK":
                            _report(pe, "OK")
                        else:
                            _report(pe, "FAIL",
                                    parts[2] if len(parts) > 2 else "unknown")
                        done = True
                        break
                    except Exception as e:
                        _report(pe, "FAIL", "%s: %s" % (type(e).__name__, e))
                        done = True
                        break
                if not done:
                    _report(pe, "FAIL", "worker 连续失败")
        finally:
            if proc is not None:
                try:
                    proc.stdin.write("EXIT\n")
                    proc.stdin.flush()
                except Exception:
                    pass
                try:
                    proc.terminate()
                except Exception:
                    pass

    threads = [threading.Thread(target=_worker, daemon=True)
               for _ in range(max(1, n_workers))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print()
    return ok_set, fail_reasons
