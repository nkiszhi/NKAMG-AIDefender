# -*- coding: utf-8 -*-
"""开发/生产档位隔离回归探针（CoDefenderC3）

验证「本机开发可纯模型、Docker 生产必全引擎」这条约束在代码层是硬的：

  A. config 层（进程内，快）
     1  默认档位 = dev，覆盖文件可读写
     2  dev 档：runtime_config.json 生效（本机测试纯模型链路靠它/靠脚本）
     3  prod 档：**同一份文件被忽略**（HASH_DB_ENABLED 保持默认 True）
     4  CODEFENDER_RUNTIME_CFG_DISABLE=1：dev 档下也被忽略
     5  prod 档：save_runtime_cfg_file() 拒绝落盘（PermissionError）
     6  prod 档逃生阀：CODEFENDER_RUNTIME_CFG_ALLOW=1 恢复可读
     7  容器自动检测：/.dockerenv 存在且未显式设档位 → 自动按 prod 处理
     8  _env_truthy 值域：'0'/'false'/'no'/'' → False，'1'/'yes' → True

  B. app 层（子进程 import engine.app，验证启动期硬校验）
     9  REQUIRE_HASH_DB=1 + HASH_DB_ENABLED=0        → 拒绝启动
     10 REQUIRE_HASH_DB=1 + 空签名库目录            → 拒绝启动（报缺失族）
     11 prod + REQUIRE_HASH_DB=1 + 有效签名库
        且目录放一份 '关预检' 的 runtime_config.json  → 正常启动、预检开启、文件被忽略
     12 dev + 同一份 runtime_config.json             → 覆盖生效、engine_mode=model_only

用法：
    cd CoDefenderC3
    PYTHONIOENCODING=utf-8 python -u _probe_env_profile.py
退出码 0 = 全部断言通过。
"""
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

_PASS = 0
_FAIL = 0


def check(cond, msg):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  ✅ {msg}")
    else:
        _FAIL += 1
        print(f"  ❌ {msg}")
    return bool(cond)


# ──────────────────────────────────────────────────────────────────
print("=" * 74)
print("A. config 层：档位与运行时覆盖文件的可见性")
print("=" * 74)

import config  # noqa: E402   （先按当前环境导入，后面用 reload 切换环境）

_ENV_KEYS = ("CODEFENDER_ENV", "CODEFENDER_RUNTIME_CFG_FILE",
             "CODEFENDER_RUNTIME_CFG_DISABLE", "CODEFENDER_RUNTIME_CFG_ALLOW",
             "CODEFENDER_HASH_DB_ENABLED", "CODEFENDER_REQUIRE_HASH_DB")


def reload_with(**env):
    """在指定环境变量下重新导入 config（None = 删除该变量）。"""
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        return importlib.reload(config)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


tmpdir = tempfile.mkdtemp(prefix="cf_envprobe_")
cfg_file = os.path.join(tmpdir, "runtime_config.json")
with open(cfg_file, "w", encoding="utf-8") as f:
    json.dump({"overrides": {"HASH_DB_ENABLED": False}}, f)


def _clear_env():
    for k in _ENV_KEYS:
        os.environ.pop(k, None)


# ── 1. 默认档位 ──────────────────────────────────────────────────
print("\n[1] 默认（未设任何档位变量）")
_clear_env()
m = reload_with()
check(m.ENV_PROFILE == "dev", f"ENV_PROFILE = {m.ENV_PROFILE!r}（期望 'dev'）")
check(m.RUNTIME_CFG_FILE_ENABLED is True, "RUNTIME_CFG_FILE_ENABLED = True")
check(m.REQUIRE_HASH_DB is False, "REQUIRE_HASH_DB = False（开发默认允许降级）")

# ── 2. dev 档：覆盖文件生效 ──────────────────────────────────────
print("\n[2] dev 档 + 覆盖文件（本机测试纯模型链路）")
m = reload_with(CODEFENDER_ENV="dev", CODEFENDER_RUNTIME_CFG_FILE=cfg_file)
check(m.HASH_DB_ENABLED is False, f"文件里的 HASH_DB_ENABLED=False 生效 → {m.HASH_DB_ENABLED}")
check(m.RUNTIME_CFG_APPLIED == ["HASH_DB_ENABLED"],
      f"RUNTIME_CFG_APPLIED = {m.RUNTIME_CFG_APPLIED}")
check(m.RUNTIME_CFG_SKIPPED is False, "RUNTIME_CFG_SKIPPED = False")

# ── 3. prod 档：同一文件被忽略 ───────────────────────────────────
print("\n[3] prod 档 + 同一份覆盖文件（Docker 生产）")
m = reload_with(CODEFENDER_ENV="prod", CODEFENDER_RUNTIME_CFG_FILE=cfg_file)
check(m.HASH_DB_ENABLED is True, f"文件被忽略 → HASH_DB_ENABLED 保持默认 {m.HASH_DB_ENABLED}")
check(m.RUNTIME_CFG_APPLIED == [], f"RUNTIME_CFG_APPLIED = {m.RUNTIME_CFG_APPLIED}")
check(m.RUNTIME_CFG_FILE_ENABLED is False, "RUNTIME_CFG_FILE_ENABLED = False")
check(m.RUNTIME_CFG_SKIPPED is True, "RUNTIME_CFG_SKIPPED = True（启动日志会喊出来）")
check("环境档位=prod" in m.RUNTIME_CFG_DISABLED_REASON,
      f"禁用原因可读: {m.RUNTIME_CFG_DISABLED_REASON}")

# ── 4. 显式 DISABLE 开关（dev 档也拦） ───────────────────────────
print("\n[4] dev 档 + CODEFENDER_RUNTIME_CFG_DISABLE=1")
m = reload_with(CODEFENDER_ENV="dev", CODEFENDER_RUNTIME_CFG_FILE=cfg_file,
                CODEFENDER_RUNTIME_CFG_DISABLE="1")
check(m.HASH_DB_ENABLED is True, "覆盖文件被 DISABLE 拦下 → HASH_DB_ENABLED 仍为默认")
check(m.RUNTIME_CFG_DISABLED_REASON.startswith("CODEFENDER_RUNTIME_CFG_DISABLE"),
      f"禁用原因 = {m.RUNTIME_CFG_DISABLED_REASON}")

# ── 5. prod 档拒绝落盘 ───────────────────────────────────────────
print("\n[5] prod 档调用 save_runtime_cfg_file()")
m = reload_with(CODEFENDER_ENV="prod", CODEFENDER_RUNTIME_CFG_FILE=cfg_file)
try:
    m.save_runtime_cfg_file()
    check(False, "应当抛 PermissionError，但没有")
except PermissionError as e:
    check("被禁用" in str(e), f"拒绝落盘且原因清晰: {str(e)[:60]}…")
except Exception as e:                                    # noqa: BLE001
    check(False, f"抛了非预期异常 {type(e).__name__}: {e}")

# ── 6. 逃生阀 ALLOW ─────────────────────────────────────────────
print("\n[6] prod 档 + CODEFENDER_RUNTIME_CFG_ALLOW=1（逃生阀）")
m = reload_with(CODEFENDER_ENV="prod", CODEFENDER_RUNTIME_CFG_FILE=cfg_file,
                CODEFENDER_RUNTIME_CFG_ALLOW="1")
check(m.RUNTIME_CFG_FILE_ENABLED is True, "显式允许后覆盖文件重新生效")
check(m.HASH_DB_ENABLED is False, f"HASH_DB_ENABLED 被文件覆盖 → {m.HASH_DB_ENABLED}")

# ── 7. 容器自动检测 ─────────────────────────────────────────────
print("\n[7] 容器自动检测（未显式设档位，/.dockerenv 存在）")
_clear_env()
os.environ["CODEFENDER_RUNTIME_CFG_FILE"] = cfg_file
_real_exists = os.path.exists
os.path.exists = lambda p: True if p == "/.dockerenv" else _real_exists(p)
try:
    m = importlib.reload(config)
finally:
    os.path.exists = _real_exists
    os.environ.pop("CODEFENDER_RUNTIME_CFG_FILE", None)
check(m.ENV_PROFILE == "prod", f"自动判定档位 = {m.ENV_PROFILE!r}（容器内 = prod）")
check(m.RUNTIME_CFG_FILE_ENABLED is False, "容器内覆盖文件默认不加载（即使文件就在旁边）")

# ── 8. 布尔解析值域 ─────────────────────────────────────────────
print("\n[8] _env_truthy 值域")
os.environ["_PROBE_BOOL"] = "0"
check(config._env_truthy("_PROBE_BOOL") is False, "'0' → False")
os.environ["_PROBE_BOOL"] = "  false "
check(config._env_truthy("_PROBE_BOOL") is False, "'  false ' → False（带空格也认）")
os.environ["_PROBE_BOOL"] = "1"
check(config._env_truthy("_PROBE_BOOL") is True, "'1' → True")
os.environ["_PROBE_BOOL"] = ""
check(config._env_truthy("_PROBE_BOOL") is False, "'' → False")
os.environ.pop("_PROBE_BOOL", None)
check(config._env_truthy("_PROBE_NOT_SET", default=True) is True, "未设置 → default")

# 复位：回到本机默认档位，避免影响后续（同进程）代码
_clear_env()
config = importlib.reload(config)
check(config.ENV_PROFILE == "dev" and config.HASH_DB_ENABLED is True,
      "已复位回 dev 档默认状态")

# ──────────────────────────────────────────────────────────────────
print()
print("=" * 74)
print("B. app 层：启动期硬校验（子进程 import engine.app）")
print("=" * 74)

APP_SNIPPET = textwrap.dedent("""
    import json, sys
    try:
        import config
        import engine.app as A
    except Exception as e:
        print("IMPORT_FAIL:" + type(e).__name__ + ":" + str(e))
        sys.exit(7)
    print("OK:" + json.dumps({
        "env": config.ENV_PROFILE,
        "hash_db_enabled": config.HASH_DB_ENABLED,
        "require_hash_db": config.REQUIRE_HASH_DB,
        "cfg_file_enabled": config.RUNTIME_CFG_FILE_ENABLED,
        "cfg_applied": config.RUNTIME_CFG_APPLIED,
        "cfg_skipped": config.RUNTIME_CFG_SKIPPED,
        "engine_mode": A._engine_mode(),
        "hash_db": A._hash_db_state(),
    }, ensure_ascii=False))
""")


def run_app(extra_env, timeout=600):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    for k in _ENV_KEYS:
        env.pop(k, None)
    env.update(extra_env)
    p = subprocess.run([PY, "-u", "-c", APP_SNIPPET], cwd=HERE, env=env,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout)
    out = (p.stdout or "") + (p.stderr or "")
    info = {}
    for line in (p.stdout or "").splitlines():
        if line.startswith("OK:"):
            info = json.loads(line[3:])
    return p.returncode, info, out


empty_dir = os.path.join(tmpdir, "empty_sig")
os.makedirs(empty_dir, exist_ok=True)

# ── 9. REQUIRE_HASH_DB=1 但预检被关掉 ────────────────────────────
print("\n[9] REQUIRE_HASH_DB=1 + HASH_DB_ENABLED=0 → 必须拒绝启动")
rc, info, out = run_app({"CODEFENDER_ENV": "prod", "CODEFENDER_REQUIRE_HASH_DB": "1",
                         "CODEFENDER_HASH_DB_ENABLED": "0"})
check(rc != 0, f"退出码 {rc}（期望非 0）")
check("不允许纯模型模式" in out, "报错点明『生产档位不允许纯模型模式』")
check("dev_model_only" in out, "报错给出本机开发纯模型的正确做法")

# ── 10. REQUIRE_HASH_DB=1 但签名库目录是空的 ────────────────────
print("\n[10] REQUIRE_HASH_DB=1 + 空签名库目录 → 必须拒绝启动")
rc, info, out = run_app({"CODEFENDER_ENV": "prod", "CODEFENDER_REQUIRE_HASH_DB": "1",
                         "CODEFENDER_HASH_DB_ENABLED": "1",
                         "CODEFENDER_FUZZY_DB_ENABLED": "1",
                         "CODEFENDER_HASH_DB_DIR": empty_dir})
check(rc != 0, f"退出码 {rc}（期望非 0）")
check("缺失" in out and "sha256" in out, "报错列出缺失的族（sha256/md5/fuzzy）")
check(":/app/signatures" in out or "/app/signatures" in out, "报错给出容器挂载示例")

# ── 11. prod：旁边的『纯模型』覆盖文件必须无效 ──────────────────
print("\n[11] prod + REQUIRE_HASH_DB=1 + 有效签名库（同目录放着关预检的覆盖文件）")
rc, info, out = run_app({"CODEFENDER_ENV": "prod", "CODEFENDER_REQUIRE_HASH_DB": "1",
                         "CODEFENDER_RUNTIME_CFG_FILE": cfg_file})
check(rc == 0, f"退出码 {rc}（期望 0 = 正常启动）")
check(info.get("hash_db_enabled") is True, f"HASH_DB_ENABLED={info.get('hash_db_enabled')}（文件被忽略）")
check(info.get("cfg_skipped") is True, "cfg_skipped=True")
check(info.get("engine_mode") == "hash_db+model",
      f"engine_mode={info.get('engine_mode')!r}（期望 hash_db+model）")
check(info.get("hash_db", {}).get("sha256"), "sha256 计数非空（确实装载了库）")
check("已忽略" in out, "启动日志喊出『文件存在但当前档位不加载』")

# ── 12. dev：同一份文件必须生效（本机纯模型链路） ───────────────
print("\n[12] dev + 同一份覆盖文件 → 覆盖必须生效（本机测试纯模型用）")
rc, info, out = run_app({"CODEFENDER_ENV": "dev", "CODEFENDER_RUNTIME_CFG_FILE": cfg_file})
check(rc == 0, f"退出码 {rc}（期望 0）")
check(info.get("hash_db_enabled") is False, "HASH_DB_ENABLED=False 生效")
check(info.get("cfg_applied") == ["HASH_DB_ENABLED"],
      f"cfg_applied={info.get('cfg_applied')}")
check(info.get("engine_mode") == "model_only",
      f"engine_mode={info.get('engine_mode')!r}（期望 model_only）")
check(info.get("hash_db", {}).get("sha256") is None, "三库计数为 null")

shutil.rmtree(tmpdir, ignore_errors=True)

# ──────────────────────────────────────────────────────────────────
print()
print("=" * 74)
print(f"结果：通过 {_PASS} 项，失败 {_FAIL} 项")
print("=" * 74)
sys.exit(0 if _FAIL == 0 else 1)
