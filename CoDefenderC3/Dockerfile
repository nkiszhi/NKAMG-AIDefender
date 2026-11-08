# =============================================================================
#  CoDefenderC3 —— 推理服务镜像（代码 + 签名库 + ensemble.pkl 全部内嵌）
# =============================================================================
#  ⚠ 2026-11-07：BinaryNinja → SMDA
#
#    · 基础镜像：公开的 python:3.10-slim-bookworm
#      （原 multiscan_basic_v3:with_binja 是内网镜像，且自带 BN 运行时）
#    · 反汇编后端：**SMDA**（BSD-3，无需商业授权）
#      D/E 特征（D01-D07 / E03-E04）与 MalGraph 的 CFG/FCG 全部由它产出
#    · 不再 COPY BinaryNinja 的 license.dat —— 商业密钥既不该进镜像，
#      更不该进版本库（仓库里的 license.txt 已删）
#    · BN 仍作为**可选的旧后端**保留（feature_extraction/backend_bn.py），
#      只在做 A/B 对照时用：装 binaryninja + 提供 license.dat +
#      设 CODEFENDER_DISASM_BACKEND=bn
#
#  构建（两步 —— 签名库不是直接从 signatures/ 拷的，见第 7 段说明）：
#
#      python docker/stage_signatures.py       # ① 解析 current → 暂存 .docker_build/signatures/
#      docker build -t codefender-c3:v8 .      # ② 在本目录构建
#
#    或直接： bash docker/build.sh codefender-c3:v8
#
#  ⚠ 想看清「下载进度」必须两件事一起做（缺一个就只能看到长时间无输出）：
#     ① 命令加 --progress=plain —— 否则 buildx 的 TUI 把每层 stdout 折叠成一行；
#     ② Dockerfile 里给 pip 加 --progress-bar raw 并把 PYTHONUNBUFFERED=1
#        提前到 pip 层**之前**（见第 0 / 1 段）—— RUN 步骤没有 TTY，pip 默认的
#        auto 在无 TTY 时只在下载结束后渲染一帧，过程中没有任何输出。
#
#  ══ 层序：按「改动频率」从低到高排 ═════════════════════════════════════
#      base → ENV(PYTHONUNBUFFERED) → pip 依赖 → ensemble.pkl(736MB) → 签名库(~985MB)
#           → 生产代码(~2.8MB) → 脚本/配置 → ENV(运行期) → 构建期自检
#      （ENV(PYTHONUNBUFFERED) 必须夹在 base 与 pip 之间，见第 0 段）
#
#  ⚠ 为什么代码必须排在大件**之后**：Docker 的缓存是「某层失效 → 其后所有层
#    全部重做」。把最常改的代码放最后，改一行 .py 只需重做「代码层 + 自检」；
#    若把代码排在大件之前，改一行 .py 会连带重做 736MB 模型 + 1GB 签名库两层。
#    代码层只有 ~2.8MB 是刻意的：训练产物 / 文档 / 备份脚本全被 .dockerignore
#    挡在上下文之外（详见 .dockerignore 末段）。
#
#  ★ 改一行 .py 到底会重做哪些层（照着这张表核对，别凭感觉）：
#      会重做 → COPY engine/ · COPY core/ · COPY models/ · COPY scaner/ ·
#               COPY feature_extraction/ · 脚本/配置 · ENV · 自检
#              合计 ≈2.8MB，COPY 本身秒级；自检要 import 全部模型，+10~30s。
#      不会重做 → base · ENV(PYTHONUNBUFFERED) · 三条 pip · ensemble.pkl(736MB)
#               · signatures(~1GB)
#
#  ══ 零运行时挂载 ═══════════════════════════════════════════════════════
#    代码 / ensemble.pkl / sha256·md5·fuzzy 三族签名库**全部**在构建期打进镜像，
#    docker run 不需要任何 -v（也不要挂，见文件末「运行 / 持久化 / 回滚」）。
#    签名库在容器内是**扁平**布局 /app/signatures/<base>.db.shards|bloom，
#    没有 current / releases —— 这正是 engine/app.py::_active_sig_dir() 的
#    第三个分支「首次部署 / 未做过版本化发布」的合法形态。
#
#  三条真踩过的坑（写在这里，省得下次再查一遍）：
#   1) 代码是 COPY 进镜像的：改宿主 .py 对运行中的容器零影响，必须「重建镜像 +
#      重建容器」(docker rm 后重新 run)。docker restart 既不会重读代码，
#      也不会重读 -e（env 在 docker run 时就固化了）。
#   2) 原来的 COPY config.py data_loader.py model_registry.py ember_vectorizer.py
#      会直接失败 —— data_loader.py / ember_vectorizer.py 已迁到 train/；
#      更隐蔽的是 scaner/ 漏拷：engine/app.py 会把 /app/scaner 插进 sys.path
#      再 import scanner，缺目录 → 启动即 ImportError，容器永远不健康。
#   3) RUN 里裸写 torch>=2.0 不加引号会被 /bin/sh 当成重定向（torch > =2.0），
#      结果是版本约束被静默吞掉，还在 WORKDIR 留一个名叫 =2.0 的垃圾文件。
# =============================================================================

FROM python:3.10-slim-bookworm

# 可 --build-arg 覆盖：换模型文件 / 换签名库暂存目录（便于两版模型共存）
ARG MODEL_FILE=ensemble.pkl
ARG SIG_STAGE=.docker_build/signatures

WORKDIR /app

# ── 0. 让下载/安装过程「看得见」（必须在 pip 层之前）──────────────────
#  PYTHONUNBUFFERED=1：不加这句，pip 的 python 进程走块缓冲，输出会攒成
#    8KB 一坨才吐一次 —— 在 docker build --progress=plain 里表现成
#    「几分钟没有任何输出」，看着像卡死，其实在下 180MB 的 torch wheel。
#  PYTHONHASHSEED=0：把 str.__hash__ 的 secret 固定下来。
#    CPython 默认每进程随机 → 任何还用了内置 hash() 的代码（第三方库、
#    将来新增的代码）在训练子进程与推理主进程之间会算出不同的桶号。
#    项目自身的 feature hashing 已改用 feature_extraction/_stable_hash.py 的
#    crc32（纯函数，天然跨进程一致），这一行是**兜底**：防止有人再引入
#    内置 hash() 时无声退化。
ENV PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

# ── 1. 系统依赖 ──────────────────────────────────────────────────────
#  build-essential / python3-dev：ppdeep、yara-python 需要现场编译（装完即卸载）
#  libgomp1：torch 的 CPU wheel 依赖 libgomp.so.1（OpenMP 运行时）
#  ca-certificates / curl：pip 走 https 源要证书
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential python3-dev libgomp1 ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*

# ── 2. torch + torchvision（CPU 版）───────────────────────────────────
#  必须加引号：见文件头第 3 条坑
#  --progress-bar raw：RUN 步骤没有 TTY，而 pip 默认的 auto 在无 TTY 时只在
#    下载**结束**后渲染一帧（你看到的是一行静态 ---- 1.8/1.8 MB 8.6 MB/s），
#    过程中没有任何输出。raw 是专给非 TTY 用的纯文本进度，按 chunk 逐行吐。
#  ⚠ torch 与 torchvision 是**强耦合的一对**（共享同一个 C++ ABI），必须同代：
#    混装（cpu/cuda 风味混装）不致命，但**代际错配**会炸：
#    "operator torchvision::nms does not exist"
#    本项目里就表现为 /health 返回 status=error。
#    （触发点不是调用 nms —— 全仓没有任何一处调它 —— 而是
#      models/InceptionV3_2020/InceptionV3.py:29 的 import torchvision.models：
#      torchvision/__init__.py 顶部 from torchvision import _meta_registrations
#      会去 register_fake("torchvision::nms")，_C.so 与 torch 不匹配时当场炸。）
#  两条防线：
#   ① --upgrade --force-reinstall —— 让 torch 与 torchvision **无条件成对重装到同一代**。
#      - 只有 --upgrade：基础镜像里若已存在旧的一对，pip 见到「已满足」会跳过 torch，
#        留下旧 torchvision 去配新装的 torch；
#      - 补 --force-reinstall：连「同一 site-packages 里已有一份错的」也一并抹掉重来。
#   ② 构建期自证 —— 装完立刻真调一次 torchvision::nms。这样这类 ABI 错配在
#      docker build 阶段就红掉，而不是等容器起来打 /health 才发现。
RUN set -eu; \
    pip3 install --no-cache-dir --timeout 300 --progress-bar raw \
        --find-links https://mirrors.aliyun.com/pytorch-wheels/cpu \
        -i https://mirrors.cloud.tencent.com/pypi/simple \
        --trusted-host mirrors.cloud.tencent.com \
        --upgrade --force-reinstall "torch>=2.0" torchvision; \
    python3 -c "import torch, torchvision; from torchvision.ops import nms; \
print('   torch=%s  torchvision=%s' % (torch.__version__, torchvision.__version__)); \
print('   torch    ->', torch.__file__); \
print('   tvison   ->', torchvision.__file__); \
_b = torch.tensor([[0., 0., 10., 10.], [0., 0., 9., 9.]]); _s = torch.tensor([0.9, 0.8]); \
print('   torchvision::nms OK ->', nms(_b, _s, 0.5).tolist())"

# ── 3. torch_geometric + supervisor（进程管理）────────────────────────
RUN pip3 install --no-cache-dir --timeout 300 --progress-bar raw \
        -i https://mirrors.cloud.tencent.com/pypi/simple \
        --trusted-host mirrors.cloud.tencent.com \
        torch_geometric supervisor

# ── 4. 运行时依赖 + SMDA 反汇编后端 ───────────────────────────────────
#  smda 在 requirements.txt 里（§2 检测链路）—— 它是**默认后端**，
#  所以是"启用"状态而不是注释状态。capstone / lief 是 smda 的依赖，
#  pip 会一起带进来。
COPY requirements.txt ./
RUN pip3 install --no-cache-dir --timeout 300 --progress-bar raw \
        -i https://mirrors.cloud.tencent.com/pypi/simple \
        --trusted-host mirrors.cloud.tencent.com \
        -r requirements.txt

# 卸载编译工具（减小镜像）
RUN set -eux; \
    apt-get purge -y build-essential python3-dev; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

# ── 5. 构建期自检（早）：torch/torchvision ABI + smda 可用 ─────────────
#  放在签名库/模型之前 —— 这两项坏了就没必要再下 1.7GB 了。
RUN python3 -c "import torch, torchvision; from torchvision.ops import nms; \
print('   torch=%s torchvision=%s' % (torch.__version__, torchvision.__version__)); \
_b = torch.tensor([[0., 0., 10., 10.], [0., 0., 9., 9.]]); _s = torch.tensor([0.9, 0.8]); \
print('   torchvision::nms OK ->', nms(_b, _s, 0.5).tolist())" && \
    python3 -c "import smda; print('   smda', getattr(smda, '__version__', 'ok'))"
# ── 6. 大件①：集成模型（~736MB）──────────────────────────────────────
#  放在代码**之前**：模型重训频率远低于改代码，且它是 736MB 的大层，
#  排在代码前面才能保证「改代码不重做模型」。
#  不论 --build-arg MODEL_FILE 叫什么，镜像内统一落到 /app/ensemble.pkl：
#  ENV CODEFENDER_MODEL_PATH 和 codefender.ini 的 environment= 都指向这个固定路径，
#  这样换模型只改构建参数，不动任何配置。
COPY ${MODEL_FILE} ./ensemble.pkl

# ── 7. 大件②：签名库（~985MB）─────────────────────────────────────────
#  暂存目录由 docker/stage_signatures.py 生成，内容 = 当前生效的那一套
#  （按 HASH_DB_DIR/current → releases/CURRENT → HASH_DB_DIR 的优先级解析），
#  且已剔除 -wal / -shm / *.legacy 等旁挂半成品。
#
#  为什么不在 Dockerfile 里直接 COPY signatures/：
#   宿主 signatures/ 同时躺着三份 —— 扁平展开的旧副本、releases/v<ts> 新副本、
#   以及 current 符号链接（内容是绝对宿主路径，跨构建上下文不可解析）。
#   直接 COPY 会(a)体积翻倍 (b)可能 COPY 到旧的那一份（旧副本缺 imphash /
#   authentihash / rich_header_hash 这些 bloom，fuzzy 预检覆盖率会掉）。
#
#  这一层能命中缓存的前提是「暂存目录内容逐字节不变」，所以暂存器把
#  staged_at / host 这类每次运行都变的字段挪到了 COPY 源**之外**
#  （.docker_build/staging_run.json），库没变时这一层就是 CACHED。
COPY ${SIG_STAGE}/ ./signatures/
# 把暂存清单挪出库目录：既是溯源凭据（这个镜像装的是哪一版库 / 文件集指纹），
# 也顺带断言暂存步骤确实跑过（缺文件 → mv 失败 → 构建中止）
RUN mv /app/signatures/_staging_manifest.json /app/SIGNATURES_SOURCE.json

# ── 8. 生产代码（改动最频繁 → 必须排在两个大件之后）──────────────────
#  原则：只带「运行期 import 闭包」内的代码，其余一律不进镜像。
#  判定依据：docker/check_requirements.py 对 engine/app.py 做 AST 导入闭包分析。
#  ⚠ models/ 必须**整目录**在位，不能按闭包挑文件：几十个模型实现类不在静态
#    闭包里 —— 它们由 model_registry.py 用 importlib 按 "models.<pkg>.<module>"
#    动态加载，AST 根本看不见。
#  scaner 特别说明：目录名故意写成 scaner（不是 scanner），避免与内部的
#    scanner.py 同名遮蔽；app.py 把 config.ROOT/scaner 插进 sys.path 后顶层导入
#    scanner 与 staticinfo（后者提供 ssdeep/tlsh 等模糊哈希，缺 ppdeep/pefile
#    时自动降级），因此 scaner/ 必须整目录在位。
#
#  ── 已从镜像移除的 5 项：都不是运行期代码（逐条给证据，别顺手加回来）──
#   train/   训练工具链（build_dataset / train_all / verify_*）。
#            运行期对它零 import、零 sys.path 注入，服务也没有训练类端点。
#   _tools/  ember 回退目录（内容只有一个残缺 .git 与一个无法解压的 ember.zip）。
#   update/  单个示例 CSV，全仓无任何引用。
#   docs/    文档；README.md 同理 —— 都不参与运行。
#  要在容器里做训练 / 自检，请从宿主挂载对应目录，不要塞回镜像。
COPY config.py model_registry.py ./
COPY engine/             ./engine/
COPY core/               ./core/
COPY models/             ./models/
COPY scaner/             ./scaner/
COPY feature_extraction/ ./feature_extraction/

# ── 9. 启动脚本 / supervisor / 诊断工具 ───────────────────────────────
#  ⚠ 不再 COPY BinaryNinja 的 license.dat：商业密钥不该进镜像，更不该进
#    版本库（仓库里的 license.txt 已删）。BN 只在 A/B 对照时按需外挂。
COPY start_codefender.sh ./
#  统一行尾：Windows 检出的 CRLF 会让 #!/bin/bash\r 失效（exec ENOENT）
RUN sed -i 's/\r$//' /app/start_codefender.sh && chmod +x /app/start_codefender.sh
#  构建期/运维期诊断工具：模型模块导入探针（第 11 段会真调它）。
#  镜像里也留一份 → 容器内可随时手跑 python3 /app/docker/check_model_imports.py
#  看「哪些模型真能加载、哪些被静默跳过」。脚本自带 sys.path 兜底，不需要设 PYTHONPATH。
COPY docker/check_model_imports.py /app/docker/check_model_imports.py
COPY supervisord.conf    /etc/supervisord.conf
COPY codefender.ini      /etc/supervisord.d/codefender.ini
COPY MultiScanPoint.ini  /etc/supervisord.d/MultiScanPoint.ini
RUN mkdir -p /var/log/supervisor /etc/supervisord.d /home/SCAN

# ── 10. 环境变量 ─────────────────────────────────────────────────────
#  线程数：限制 OpenBLAS/OMP 线程，避免容器进程数限制报错
#  PYTHONUNBUFFERED / PYTHONIOENCODING：日志实时落 stdout（supervisord 抓取），
#  且中文日志不因 locale 缺失而 UnicodeEncodeError
#  CODEFENDER_DISASM_BACKEND=smda：反汇编/D-E/MalGraph 全部走 SMDA
#    （不再有 BN 许可依赖，也不会有 BN 挂死样本）
#  分析/请求/硬杀三级超时：必须满足 分析 < 请求 < 硬杀
ENV OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONHASHSEED=0 \
    CODEFENDER_MODEL_PATH=/app/ensemble.pkl \
    CODEFENDER_HASH_DB_DIR=/app/signatures \
    CODEFENDER_DISASM_BACKEND=smda \
    CODEFENDER_ANALYSIS_TIMEOUT=600 \
    CODEFENDER_REQUEST_TIMEOUT=900 \
    CODEFENDER_HARD_TIMEOUT=960 \
    CODEFENDER_MAX_CONCURRENT=8

# ── 11. 生产档位：容器必须跑全引擎，绝不允许「纯模型模式」───────────────
#   CODEFENDER_ENV=prod              → 声明生产档位（不读 runtime_config.json）
#   CODEFENDER_RUNTIME_CFG_DISABLE=1 → 双保险：覆盖文件既不加载也不落盘，
#                                      本机开发留下的调试开关进不了容器
#   CODEFENDER_HASH_DB_ENABLED=1     → 显式开启四级哈希预检（不依赖「没设=开」）
#   CODEFENDER_FUZZY_DB_ENABLED=1    → 显式开启 fuzzy/tlsh 预检
#   CODEFENDER_REQUIRE_HASH_DB=1     → 签名库缺一即拒绝启动（响的失败，不是静默降级）
# 想临时做纯模型对照：docker run 时 -e CODEFENDER_REQUIRE_HASH_DB=0
#                     -e CODEFENDER_HASH_DB_ENABLED=0，或直接用 /admin/config
#                     （内存内、重启即恢复）
ENV CODEFENDER_ENV=prod \
    CODEFENDER_RUNTIME_CFG_DISABLE=1 \
    CODEFENDER_HASH_DB_ENABLED=1 \
    CODEFENDER_FUZZY_DB_ENABLED=1 \
    CODEFENDER_REQUIRE_HASH_DB=1

# ── 12. 构建期自检 ────────────────────────────────────────────────────
#  成本约 1 分钟，换掉「上生产后才发现 engine_mode 是 model_only」的静默降级。
#  放在最后 = 前面的 COPY 全部完成，这一步的产物只有几百字节。
#
#  ⚠ 这里分两层，第二层才是关键：
#    ① import engine.app —— 只证明「应用入口 + 标注过的目录」在位。
#       它**不会**加载任何模型：几十个模型类是 models/ensemble.py 用
#       importlib 按 "models.<pkg>.<module>" 字符串动态加载的，AST 看不见、
#       顶层 import 也走不到。所以历史上构建全绿、容器 /health 却报
#       operator torchvision::nms does not exist，就是因为这一层太浅。
#    ② docker/check_model_imports.py —— 把 model_registry.REGISTRY 里的每个
#       模型模块真 import 一遍，判定口径与运行期 _load_model_class() 逐字对齐
#       （ImportError 系 → 只告警不阻断；其它异常 → 直接让构建失败）。
RUN set -eu; \
    echo "── 关键产物 ──"; \
    ls -l /app/ensemble.pkl /app/SIGNATURES_SOURCE.json; \
    echo "── 三族签名库 ──"; \
    for fam in sha256 md5 fuzzy; do \
        sdir="/app/signatures/$fam.db.shards"; \
        bdir="/app/signatures/$fam.db.bloom"; \
        test -d "$sdir" || { echo "FATAL: 缺 $sdir"; exit 1; }; \
        test -d "$bdir" || { echo "FATAL: 缺 $bdir"; exit 1; }; \
        n=$(ls "$sdir" | wc -l); \
        b=$(ls "$bdir" | wc -l); \
        test "$n" -ge 2 || { echo "FATAL: $sdir 为空"; exit 1; }; \
        test "$b" -ge 1 || { echo "FATAL: $bdir 为空"; exit 1; }; \
        printf '   %-7s shards=%-5s bloom=%-5s\n' "$fam" "$n" "$b"; \
    done; \
    echo "── 布局断言 ──"; \
    test ! -e /app/signatures/current  || { echo "FATAL: 残留 current 符号链接"; exit 1; }; \
    test ! -e /app/signatures/releases || { echo "FATAL: 不该带 releases/ 进镜像"; exit 1; }; \
    test ! -e /app/signatures/build    || { echo "FATAL: 不该带 build/ 进镜像"; exit 1; }; \
    python3 -c "import os, config; \
assert os.path.realpath(config.HASH_DB_DIR) == '/app/signatures', config.HASH_DB_DIR; \
assert config.MODEL_PATH == '/app/ensemble.pkl', config.MODEL_PATH; \
assert config.ENV_PROFILE == 'prod', config.ENV_PROFILE; \
assert config.REQUIRE_HASH_DB and config.HASH_DB_ENABLED and config.FUZZY_DB_ENABLED; \
print('   config 解析 OK: HASH_DB_DIR=%s  MODEL_PATH=%s  ENV=%s' % (config.HASH_DB_DIR, config.MODEL_PATH, config.ENV_PROFILE))"; \
    echo "── 导入自检 ① 应用入口（验证 scaner / core / models / feature_extraction 都在位）──"; \
    python3 -c "import engine.app; print('   engine.app 导入 OK')"; \
    echo "── 导入自检 ② 全部模型模块（把「改代码改坏了」提前到这里红掉）──"; \
    python3 /app/docker/check_model_imports.py

# ── 端口 ────────────────────────────────────────────────────────────
EXPOSE 8000

# ── 健康检查 ────────────────────────────────────────────────────────
#  start-period 给到 300s：首次 /health 会触发 736MB 集成模型加载 + 三族布隆库
#  装载，CPU 容器上 1~3 分钟很正常；这期间失败不计入 retries。
#  断言只卡「必须成立」的两项（status=ok 且模型确实装上了），engine_mode 只打印
#  不判定 —— 免得运维临时用 REQUIRE_HASH_DB=0 做纯模型对照时被误判为不健康。
HEALTHCHECK --interval=30s --timeout=60s --start-period=300s --retries=5 \
    CMD python3 -c "import json, urllib.request, sys; \
d = json.load(urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=45)); \
print('health:', d.get('status'), '| engine_mode =', d.get('engine_mode'), \
'| models =', d.get('model_count'), '| sig_dir =', d.get('hash_db', {}).get('dir')); \
sys.exit(0 if d.get('status') == 'ok' and (d.get('model_count') or 0) > 0 else 1)"

# ── 启动 ────────────────────────────────────────────────────────────
CMD ["/usr/local/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]

# =============================================================================
#  运行 / 持久化 / 回滚
# =============================================================================
#  ★ 零挂载启动（自包含镜像，不需要任何 -v）：
#      docker run -d --name codefender -p 8000:8000 codefender-c3:v8
#
#  ★ 不要再挂 /app/signatures：镜像里已经带了完整三族库（sha256 / md5 / fuzzy），
#    挂卷只会让容器读到卷里的旧库、与镜像版本脱钩。也**严禁**把宿主 VMware
#    共享目录（hgfs）挂进 /app/signatures —— SQLite 分片库的 POSIX 锁在 hgfs 上
#    不可靠。
#
#  ★ 在线更新（POST /update-signatures）写的是 /app/signatures：
#      没挂卷 → 改动落在**容器可写层**，容器重启仍在，docker rm 即回滚到
#      镜像里那一版；要**固化**就重建镜像：
#          python docker/stage_signatures.py && docker build -t codefender-c3:v8.1 .
#      这也是推荐路径 —— 换库 = 换镜像，可回滚、可追溯、多副本一致。
#
#  ★ 验证库真的生效了（别只看日志）：
#      curl -s localhost:8000/health | python -m json.tool
#      期望：env=prod, engine_mode=hash_db+model, require_hash_db=true,
#            hash_db.sha256/md5/fuzzy 三个 count 均非 null
#
#  ★ 代码/模型/库改了就重建镜像 + 重建容器（旧容器 rootfs 固化，不会自动更新）：
#      python docker/stage_signatures.py && docker build -t codefender-c3:v8 .
#      docker rm -f codefender && docker run -d --name codefender -p 8000:8000 codefender-c3:v8
#    重复构建时若源码与暂存目录都没变，各层会全 CACHED，秒级完成。
# =============================================================================
