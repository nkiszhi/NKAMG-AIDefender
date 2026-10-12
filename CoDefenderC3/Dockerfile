# =============================================================================
#  CoDefenderC3 —— 推理服务镜像（代码 + 签名库 + ensemble.pkl 全部内嵌）
# =============================================================================
#  说明：这里**故意不写 `# syntax=docker/dockerfile:1`** —— 本条 Dockerfile
#  没有用到任何 BuildKit 专属语法（没有 RUN --mount / COPY --link / heredoc），
#  而写了这条会在构建前额外从 docker.io 拉一次 frontend 镜像；本机/内网构建
#  环境下这属于白送一个失败点。
#
#  构建（两步 —— 签名库不是直接从 signatures/ 拷的，见第 3 段说明）：
#
#      python docker/stage_signatures.py       # ① 解析 current → 暂存 .docker_build/signatures/
#      docker build -t codefender-c3:v8 .      # ② 在本目录构建
#
#    或直接： bash docker/build.sh codefender-c3:v8
#
#  ⚠ 想看清「下载进度」必须两件事一起做（缺一个就只能看到长时间无输出）：
#     ① 命令加 `--progress=plain` —— 否则 buildx 的 TUI 把每层 stdout 折叠成一行；
#     ② Dockerfile 里给 pip 加 `--progress-bar raw` 并把 PYTHONUNBUFFERED=1
#        提前到 pip 层**之前**（见第 0 / 1 段）—— RUN 步骤没有 TTY，pip 默认
#        的 auto 在无 TTY 时只在下载结束后渲染一帧，过程中没有任何输出。
#    注意 Docker 自身的进度只覆盖 FROM 拉基底 / push 层；RUN 里 pip 下的字节数
#    Docker 一律不解析，`--progress=rawjson` 也看不到，只能靠 pip 自己打印。
#
#  ══ 层序：按「改动频率」从低到高排 ═════════════════════════════════════
#      base → ENV(PYTHONUNBUFFERED) → pip 依赖 → ensemble.pkl(736MB) → 签名库(~985MB)
#           → 生产代码(~2.8MB) → 脚本/配置 → ENV(运行期) → 构建期自检
#      （ENV(PYTHONUNBUFFERED) 必须夹在 base 与 pip 之间，见第 0 段）
#
#  ⚠ 为什么代码必须排在大件**之后**：Docker 的缓存是「某层失效 → 其后所有层
#    全部重做」。把最常改的代码放最后，改一行 .py 只需重做「代码层 + 自检」；
#    若把代码排在大件之前，改一行 .py 会连带重做 736MB 模型 + 1GB 签名库两层。
#    反过来换库/换模型只影响它自己那层及其后的代码层，代价很小。
#    代码层只有 ~2.8MB 是刻意的：训练产物 / 文档 / 备份脚本全被 .dockerignore
#    挡在上下文之外（详见 .dockerignore 末段），否则光 MalGraph 的
#    features.jsonl（103MB）就会把这一层撑到 116MB。
#    （实测：docker/check_context.py 报告 config+6 目录 = 2.77MB / 95 个文件）
#
#  ★ 改一行 .py 到底会重做哪些层（照着这张表核对，别凭感觉）：
#      会重做 → COPY engine/ · COPY core/ · COPY models/ · COPY scaner/ ·
#               COPY feature_extraction/ · 脚本/配置 · ENV · 自检
#              合计 ≈2.8MB，COPY 本身秒级；自检要 import 全部模型，+10~30s。
#      不会重做 → base · ENV(PYTHONUNBUFFERED) · 三条 pip · ensemble.pkl(736MB)
#               · signatures(~1GB)
#    ⚠ 上面这条「不会重做」有两个前提，缺一条大件层就会**每轮**都 cache miss：
#      ① COPY 源里不能有「每轮运行都变」的文件 —— __pycache__/*.pyc 已在
#         .dockerignore 里挡掉；暂存器的易变字段（staged_at/host）也被刻意
#         挪出了 COPY 源（见 docker/stage_signatures.py）。
#      ② 暂存树每轮是**整个重建**的（新目录 → 新目录 mtime）。BuildKit 算本地源
#         校验和时会带上目录 mtime，所以脚本末尾必须把目录 mtime 归一到稳定值
#         （docker/stage_signatures.py::normalize_mtimes）。少了这一步，即使库
#         一个字节没变，那 ~1GB 的层也照样每轮重拷一遍。
#    （另一条隐蔽的 cache 杀手：COPY 源里躺着空的 __init__.py 之类，内容没变但
#      mtime 变了 —— 本仓库的 6 个代码目录都不存在这种文件，已逐目录核过。）
#
#  ══ 零运行时挂载 ═══════════════════════════════════════════════════════
#    代码 / ensemble.pkl / sha256·md5·fuzzy 三族签名库**全部**在构建期打进镜像，
#    `docker run` 不需要任何 -v（也不要挂，见文件末「运行 / 持久化 / 回滚」）。
#    签名库在容器内是**扁平**布局 /app/signatures/<base>.db.shards|bloom，
#    没有 current / releases —— 这正是 engine/app.py::_active_sig_dir() 的
#    第三个分支「首次部署 / 未做过版本化发布」的合法形态。
#
#  三条真踩过的坑（写在这里，省得下次再查一遍）：
#   1) 代码是 COPY 进镜像的：改宿主 .py 对运行中的容器零影响，必须「重建镜像 +
#      重建容器」(`docker rm` 后重新 `run`)。`docker restart` 既不会重读代码，
#      也不会重读 `-e`（env 在 docker run 时就固化了）。
#   2) 原来的 COPY config.py data_loader.py model_registry.py ember_vectorizer.py
#      会直接失败 —— data_loader.py / ember_vectorizer.py 已迁到 train/；
#      更隐蔽的是 scaner/ 漏拷：engine/app.py 会把 /app/scaner 插进 sys.path
#      再 `import scanner`，缺目录 → 启动即 ImportError，容器永远不健康。
#   3) RUN 里裸写 torch>=2.0 不加引号会被 /bin/sh 当成重定向（`torch > =2.0`），
#      结果是版本约束被静默吞掉，还在 WORKDIR 留一个名叫 `=2.0` 的垃圾文件。
# =============================================================================

FROM multiscan_basic_v3:with_binja

# 可 --build-arg 覆盖：换模型文件 / 换签名库暂存目录（便于两版模型共存）
ARG MODEL_FILE=ensemble.pkl
ARG SIG_STAGE=.docker_build/signatures

WORKDIR /app

# ── 0. 让下载/安装过程「看得见」（必须在 pip 层之前）──────────────────
#  PYTHONUNBUFFERED=1：不加这句，pip 的 python 进程走块缓冲，输出会攒成
#    8KB 一坨才吐一次 —— 在 `docker build --progress=plain` 里表现成
#    「几分钟没有任何输出」，看着像卡死，其实在下 180MB 的 torch wheel。
#  ⚠ 第 6 段的 ENV 里也有 PYTHONUNBUFFERED，那是给运行期 supervisor 抓日志用的；
#    这里必须**再提前设一份**，因为第 1 段的 pip 跑在第 6 段之前。重复设置无害。
ENV PYTHONUNBUFFERED=1

# ── 1. Python 运行时依赖 ──────────────────────────────────────────────
#  必须加引号：见文件头第 3 条坑
#  --progress-bar raw：RUN 步骤没有 TTY，而 pip 默认的 auto 在无 TTY 时只在
#  下载**结束**后渲染一帧（你看到的是一行静态 `---- 1.8/1.8 MB 8.6 MB/s`），
#  过程中没有任何输出。raw 是专给非 TTY 用的纯文本进度，按 chunk 逐行吐
#  `Progress <已下字节> of <总字节>`（本机 pip 26.0.1 实测；取值 [auto,on,off,raw]）。
#  ⚠ 代价是行数多：每 256KB 一行，180MB 的 torch wheel ≈ 700 行。构建日志嫌吵可以：
#      docker build --progress=plain ... 2>&1 | grep -E "Progress|Downloading|Collecting|Successfully"
#  ⚠ torch 与 torchvision 是**强耦合的一对**（共享同一个 C++ ABI），必须同代：
#    （实测：cpu/cuda 风味混装**不致命**——torch 2.12.0+cu126 + torchvision 0.27.0+cpu
#      也能正常调用 nms；只有**代际错配**才会炸。排查先比版本号，别先追风味。）
#    torchvision 的扩展模块 torchvision/_C.so 会把 nms / roi_align / deform_conv2d
#    等算子注册进 torch 的 dispatcher。两者对不上时注册失败，**一 import 就抛**
#        RuntimeError: operator torchvision::nms does not exist
#    本项目里就表现为 /health 返回
#        {"status":"error","model_path":"/app/ensemble.pkl",
#         "reason":"operator torchvision::nms does not exist"}
#    （触发点不是调用 nms —— 全仓没有任何一处调它 —— 而是
#      models/InceptionV3_2020/InceptionV3.py:29 的 `import torchvision.models`：
#      torchvision/__init__.py 顶部 `from torchvision import _meta_registrations`
#      会去 register_fake("torchvision::nms")，_C.so 与 torch 不匹配时当场炸。）
#  两条防线（实测现场：容器 Python 3.12.13，报错栈落在
#  torchvision/_meta_registrations.py:163 @torch.library.register_fake("torchvision::nms")
#  → torch/_library/... → RuntimeError: operator torchvision::nms does not exist）：
#   ① --upgrade --force-reinstall —— 让 torch 与 torchvision **无条件成对重装到同一代**。
#      - 只有 --upgrade：基础镜像里若已存在旧的一对，pip 见到「已满足」会跳过 torch，
#        留下旧 torchvision 去配新装的 torch；
#      - 补 --force-reinstall：连「同一 site-packages 里已有一份错的」也一并抹掉重来
#        （pip 会先卸载旧 distribution 再落地，不会残留旧 _C.so）。
#      ⚠ 它只管 /usr/local/lib64/python3.12/site-packages 这一份。若调试发现实际
#        import 到的 torch 来自另一个目录（如 /usr/lib64/...），那是基础镜像里的
#        第二份 torch，属于 sys.path 重影，本层管不到，需要在更早的位置清理。
#   ② 构建期自证 —— 装完立刻真调一次 torchvision::nms。这样这类 ABI 错配在
#      docker build 阶段就红掉，而不是等容器起来打 /health 才发现。
#      （断言里的 print 只在构建日志；失败即该层失败，构建中止。）
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

RUN pip3 install --no-cache-dir --timeout 300 --progress-bar raw \
        -i https://mirrors.cloud.tencent.com/pypi/simple \
        --trusted-host mirrors.cloud.tencent.com \
        torch_geometric

COPY requirements.txt .
RUN pip3 install --no-cache-dir --timeout 300 --progress-bar raw \
        -i https://mirrors.cloud.tencent.com/pypi/simple \
        --trusted-host mirrors.cloud.tencent.com \
        -r requirements.txt

# ── 2. 大件①：集成模型（~736MB）──────────────────────────────────────
#  放在代码**之前**：模型重训频率远低于改代码，且它是 736MB 的大层，
#  排在代码前面才能保证「改代码不重做模型」。
#  不论 --build-arg MODEL_FILE 叫什么，镜像内统一落到 /app/ensemble.pkl：
#  ENV CODEFENDER_MODEL_PATH 和 codefender.ini 的 environment= 都指向这个固定路径，
#  这样换模型只改构建参数，不动任何配置。
COPY ${MODEL_FILE} ./ensemble.pkl

# ── 3. 大件②：签名库（~985MB）─────────────────────────────────────────
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
#  把暂存清单挪出库目录：既是溯源凭据（这个镜像装的是哪一版库 / 文件集指纹），
#  也顺带断言暂存步骤确实跑过（缺文件 → mv 失败 → 构建中止）
RUN mv /app/signatures/_staging_manifest.json /app/SIGNATURES_SOURCE.json

# ── 4. 生产代码（改动最频繁 → 必须排在两个大件之后）──────────────────
#  原则：只带「运行期 import 闭包」内的代码，其余一律不进镜像。
#  判定依据：docker/check_requirements.py 对 engine/app.py 做 AST 导入闭包分析，
#  闭合到的本地模块仅 29 个，全部落在 config.py / model_registry.py 与下列 6 个
#  目录里。
#  ⚠ models/ 必须**整目录**在位，不能按闭包挑文件：几十个模型实现类不在静态
#    闭包里 —— 它们由 model_registry.py 用 importlib 按 "models.<pkg>.<module>"
#    动态加载，AST 根本看不见。
#  scaner 特别说明：目录名故意写成 scaner（不是 scanner），避免与内部的
#  scanner.py 同名遮蔽；app.py 把 config.ROOT/scaner 插进 sys.path 后顶层导入
#  `scanner` 与 `staticinfo`（后者提供 ssdeep/tlsh 等模糊哈希，缺 ppdeep/pefile
#  时自动降级），因此 scaner/ 必须整目录在位。
#
#  ── 已从镜像移除的 5 项：都不是运行期代码（逐条给证据，别顺手加回来）──
#   train/   训练工具链（build_dataset / train_all / verify_* / _fix_de_gap）。
#            运行期对它零 import、零 sys.path 注入，服务也没有训练类端点。
#   _tools/  ember 回退目录。实际内容只有一个残缺 .git 与一个**无法解压**的
#            ember.zip；unified.py 期望的 _tools/ember/ember/features.py
#            并不存在 → 该回退分支在镜像里本就是死代码。
#   update/  单个示例 CSV（cn_vt9-11_21_part001.csv），全仓无任何引用。
#   docs/    文档（README/TESTING/PAPERS/…）；README.md 同理 —— 都不参与运行。
#  要在容器里做训练 / 自检，请从宿主挂载对应目录，不要塞回镜像。
COPY config.py model_registry.py ./
COPY engine/             ./engine/
COPY core/               ./core/
COPY models/             ./models/
COPY scaner/             ./scaner/
COPY feature_extraction/ ./feature_extraction/

# ── 5. 启动脚本 / supervisor / BinaryNinja 许可 / 诊断工具 ─────────────
COPY start_codefender.sh ./
RUN chmod +x /app/start_codefender.sh
#  构建期/运维期诊断工具：模型模块导入探针（第 7 段会真调它）。
#  镜像里也留一份 → 容器内可随时手跑 `python3 /app/docker/check_model_imports.py`
#  看「哪些模型真能加载、哪些被静默跳过」。脚本自带 sys.path 兜底，不需要设 PYTHONPATH。
COPY docker/check_model_imports.py /app/docker/check_model_imports.py
COPY license.txt /root/.binaryninja/license.dat
COPY supervisord.conf    /etc/supervisord.conf
COPY codefender.ini      /etc/supervisord.d/codefender.ini
COPY MultiScanPoint.ini  /etc/supervisord.d/MultiScanPoint.ini
RUN mkdir -p /var/log/supervisor /etc/supervisord.d /home/SCAN

# ── 6. 环境变量 ──────────────────────────────────────────────────────
#  线程数：限制 OpenBLAS/OMP 线程，避免容器进程数限制报错
#  PYTHONUNBUFFERED / PYTHONIOENCODING：日志实时落 stdout（supervisord 抓取），
#  且中文日志不因 locale 缺失而 UnicodeEncodeError（本机踩过）
#  （PYTHONUNBUFFERED 已在第 0 段为 pip 提前设过一次；ENV 是幂等的，这里重复
#    设置只为让「运行期环境变量」这一段自解释、不依赖读者回翻上文。）
ENV OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    CODEFENDER_MODEL_PATH=/app/ensemble.pkl \
    CODEFENDER_HASH_DB_DIR=/app/signatures

# ── 生产档位：容器必须跑全引擎，绝不允许「纯模型模式」───────────────
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

# ── 7. 构建期自检 ────────────────────────────────────────────────────
#  成本约 1 分钟，换掉「上生产后才发现 engine_mode 是 model_only」的静默降级。
#  放在最后 = 前面的 COPY 全部完成，这一步的产物只有几百字节。
#
#  ⚠ 这里分两层，第二层才是关键（2026-10-09 补）：
#    ① `import engine.app` —— 只证明「应用入口 + 标注过的目录」在位。
#       它**不**会加载任何模型：几十个模型类是 models/ensemble.py 用
#       importlib 按 "models.<pkg>.<module>" 字符串动态加载的，AST 看不见、
#       顶层 import 也走不到。所以历史上构建全绿、容器 /health 却报
#       `operator torchvision::nms does not exist`，就是因为这一层太浅。
#    ② docker/check_model_imports.py —— 把 model_registry.REGISTRY 里的每个
#       模型模块真 import 一遍，判定口径与运行期 _load_model_class() 逐字对齐
#       （ImportError 系 → 只告警不阻断；其它异常 → 直接让构建失败）。
#       于是「改代码改坏了」在 docker build 阶段就红，不用等启动容器。
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
#      没挂卷 → 改动落在**容器可写层**，容器重启仍在，`docker rm` 即回滚到
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
