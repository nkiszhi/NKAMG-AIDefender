"""
CoDefenderC3 — 配置文件
========================
所有配置通过此文件或环境变量指定，无启发式推断。

改配置的三种途径与生效边界（见文件末尾「运行时配置覆盖」一节）：
  a) 环境变量        → 只在进程 import 时读一次，必须重启**真正在跑的那个进程**
  b) 改本文件默认值  → 同上；容器里代码是 COPY 进镜像的，改宿主机文件无效，需重建镜像
  c) runtime_config.json / POST /admin/config → 无需重启，运行时可热切换
"""
import json
import os

# ── 路径配置 (通过环境变量或直接修改) ──
DATA_DIR   = os.environ.get("CODEFENDER_DATA_DIR",
                            os.path.join(r"E:\nkproject\test_samples", "CoDefenderC3_data"))
ROOT       = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(ROOT, "results")
MODEL_PATH = os.environ.get("CODEFENDER_MODEL_PATH",
                            os.path.join(ROOT, "ensemble.pkl"))
CACHE_DIR  = os.path.join(ROOT, ".cache")

# ── 实验参数 ──
RUN_ABLATION = True
SAVE_MODEL   = True
N_WORKERS    = int(os.environ.get("CODEFENDER_N_WORKERS",
                                  min(max(os.cpu_count() or 8, 8), 16)))
ALPHA, DELTA_THR = 0.05, 0.50
WS, WR = 0.6, 0.4
BASELINE_MONTHS = 3
DACP_ALPHA = 0.10
SEED = 42

# ── EMBER 特征范围 (由数据集 metadata.json 的 feature_ranges 字段决定) ──
EMBER_RANGES_V2 = {
    "ByteHistogram": (0, 256),     "ByteEntropy":   (256, 512),
    "StringInfo":    (512, 616),   "GeneralInfo":   (616, 626),
    "HeaderInfo":    (626, 688),   "SectionInfo":   (688, 943),
    "ImportInfo":    (943, 2223),  "ExportInfo":    (2223, 2351),
    "DataDirs":      (2351, 2381),
}

EMBER_RANGES_V3 = {
    "ByteHistogram": (0, 256),     "ByteEntropy":   (256, 512),
    "StringInfo":    (512, 616),   "GeneralInfo":   (616, 636),
    "HeaderInfo":    (636, 738),   "SectionInfo":   (738, 1043),
    "ImportInfo":    (1043, 2323), "ExportInfo":    (2323, 2451),
    "DataDirs":      (2451, 2491), "RichHeader":    (2491, 2531),
    "Authenticode":  (2531, 2551), "ParseWarnings": (2551, 2568),
}

# 兼容旧引用
EMBER_RANGES = EMBER_RANGES_V2

def get_ember_ranges(ndim=2381):
    """根据特征维度返回对应的 EMBER 特征范围映射。
    注意: 优先使用 metadata.json 中的 feature_ranges 字段。"""
    if ndim >= 2568:
        return EMBER_RANGES_V3
    if ndim < 512:
        # 非 EMBER 数据集 (如 MalMem 55d): 全量映射到单视角
        return {"ByteHistogram": (0, ndim)}
    return EMBER_RANGES_V2


# ═══════════════════════════════════════════════════════════════
# 33 Models × 16 View Groups — 完整架构定义
# ═══════════════════════════════════════════════════════════════
#
# 运行时, ensemble.py 根据数据加载器提供的 views 选择可用的视角组。
# 不存在 "ember 模式" vs "full 模式" — 可用数据决定可用模型。
#
# 每个 view group 包含:
#   - ember_ranges (可选): EMBER 预提取特征的范围名列表
#   - binja_features (可选): BinaryNinja 提取的特征 ID 列表
#   - models: 该视角下的模型列表

VIEW_GROUPS = {
    "V1_byte": {
        "label": "Byte-Level", "attck": "T1027.002",
        "binja_features": ["B01"],
        "models": [
            ("MalConv",         "Raff et al. 2018 (AAAI-WS)",
             "models/MalConv_2017 | Embedding\u2192GatedConv\u2192GlobalMaxPool\u2192FC"),
            ("MalConv2",        "Raff et al. 2021 (MalConvGCT)",
             "models/MalConv2_2021 | MalConvML+GCT: GLU\u2192GlobalContext\u2192LowMemConv"),
            ("ByteTransformer", "Vaswani+Custom 2023",
             "models/ByteTransformer_2023 | 4-layer Transformer: d=128,nhead=4"),
        ],
    },
    "V2_byte_stat": {
        "label": "ByteStat", "attck": "T1027.002",
        "binja_features": ["B02", "B03", "B04", "B05"],
        "ember_ranges": ["ByteHistogram", "ByteEntropy"],
        "models": [
            ("SaxeBerlinDNN", "Saxe & Berlin 2015 (IEEE ISI)",
             "models/SaxeBerlinDNN_2015 | MLP(1024,512,256)+BN+Dropout"),
            ("EmberDNN",      "Anderson & Roth 2018 (EMBER)",
             "models/EmberDNN_2018 | MLP(300,300)+BN+Dropout"),
            ("NatarajKNN",    "Nataraj et al. 2011 (VizSec)",
             "models/NatarajKNN_2011 | kNN(k=5,distance-weighted)"),
        ],
    },
    "V3_pe_struct": {
        "label": "PE-Struct", "attck": "T1036.005",
        "binja_features": ["A01", "A02", "A03", "A04", "A05"],
        "ember_ranges": ["GeneralInfo", "HeaderInfo", "SectionInfo"],
        "models": [
            ("DrebinSVM",  "Arp et al. 2014 (NDSS)",
             "models/DREBIN_2014 | LinearSVM+Platt on PE structural features"),
            ("DL4MD",      "Hardy et al. 2016 (DMIN)",
             "models/DL4MD_2016 | StackedDenoisingAE(400,300,200,100)\u2192FC"),
            ("PEMinerRF",  "Shafiq et al. 2009 (RAID)",
             "models/PEMiner_2009 | RandomForest(200 trees,depth=15)"),
        ],
    },
    "V4_import": {
        "label": "Import", "attck": "T1027.007",
        "binja_features": ["A06", "A07", "A08_A15"],
        "ember_ranges": ["ImportInfo"],
        "models": [
            ("DrebinImport", "Arp et al. 2014 (NDSS)",
             "models/DREBIN_2014 | LinearSVM+Platt on import features"),
            ("ALOHANet",     "Aghakhani et al. 2020 (USENIX Sec)",
             "models/ALOHANet_2020 | MLP(512,256,128)+BN+L2-reg"),
            ("EmberGBDT_Import", "Anderson & Roth 2018 (EMBER)",
             "models/EmberGBDT_2018 | GBDT on import features"),
        ],
    },
    "V5_string": {
        "label": "String", "attck": "T1027",
        "binja_features": ["C01", "C02", "C03", "C04"],
        "ember_ranges": ["StringInfo"],
        "models": [
            ("RaffFeatureNet", "Raff et al. 2018 (AAAI-WS)",
             "models/RaffFeatureNet_2018 | MLP(256,128) feature baseline"),
            ("DrebinString",   "Arp et al. 2014 (NDSS)",
             "models/DREBIN_2014 | LinearSVM+Platt on string features"),
        ],
    },
    "V6_opcode_seq": {
        "label": "OpcodeSeq", "attck": "T1027.004",
        "binja_features": ["D01"],
        "models": [
            ("OpcodeLSTM",        "McLaughlin et al. 2017 (IEEE TIFS)",
             "models/OpcodeLSTM_2017 | BiLSTM(128\u00d72)\u2192FC"),
            ("OpcodeTransformer", "Ren et al. 2020 (IEEE Access)",
             "models/OpcodeTransformer_2020 | 4-layer Transformer on opcodes"),
        ],
    },
    "V6_opcode_stat": {
        "label": "OpcodeStat", "attck": "T1027.004",
        "binja_features": ["D02", "D03", "D04", "D05", "D06"],
        "models": [
            ("OpcodeStatNet",     "Ahmadi et al. 2016 (MS BIG)",
             "models/MicrosoftBIG_2016 | MLP(256,128) on n-gram+category dist"),
        ],
    },
    "V6_func_embed": {
        "label": "FuncEmbed", "attck": "T1027.004",
        "binja_features": ["D07"],
        "models": [
            ("AsmEmbedNet",       "Ding et al. 2019 (IEEE S&P, Asm2Vec)",
             "models/Asm2Vec_2019 | Embedding+LSTM on assembly functions"),
        ],
    },
    "V7_graph": {
        "label": "Graph", "attck": "T1027.004",
        "binja_features": ["E01", "E02", "E03", "E04"],
        "models": [
            ("MalGraph",     "Chen et al. 2022 (MalGraph)",
             "models/MalGraph_2022 | HierarchicalGNN [SPECIAL_PIPELINE]"),
            ("CFGGAT",       "Yan et al. 2019 (IEEE DSC)",
             "models/CFG_GAT_2019 | 3-layer GAT: heads=[8,8,1]"),
            ("CFGGCN",       "Kipf & Welling 2017 (ICLR)",
             "models/GCN_2017 | 3-layer GCN(64\u219232\u219216)\u2192ReadOut"),
            ("CFGDGCNN",     "Zhang et al. 2018 (AAAI)",
             "models/DGCNN_2018 | DGCNN: SortPool(k=30)\u21921D-CNN"),
            ("CallGraphGNN", "Li et al. 2019 (ICSE)",
             "models/CallGraphGNN_2019 | GraphSAGE on function call graph"),
            ("GraphStatNet", "Hybrid (MLP on graph stats)",
             "models/GraphStatNet_2022 | MLP(128,64) on CFG+CallGraph statistics"),
        ],
    },
    "V8_gray": {
        "label": "GrayVis", "attck": "T1027",
        "binja_features": ["F01"],
        "models": [
            ("GrayscaleCNN", "Nataraj et al. 2011 (VizSec)",
             "models/GrayscaleCNN_2011 | ResNet-style CNN on grayscale image"),
            ("InceptionV3",  "Nataraj-style 2020 (InceptionV3)",
             "models/InceptionV3_2020 | InceptionV3(pretrained)\u2192FC(2048\u21922)"),
        ],
    },
    "V8_color": {
        "label": "ColorVis", "attck": "T1027",
        "binja_features": ["F02"],
        "models": [
            ("IMCFN",        "Vasan et al. 2020 (Computer Networks)",
             "models/IMCFN_2020 | VGG16(pretrained)+FineTune"),
            ("ColorCNN",     "Liu & Wang 2019",
             "models/ColorCNN_2019 | Same CNN architecture, RGB input"),
        ],
    },
    "V8_markov": {
        "label": "MarkovVis", "attck": "T1027",
        "binja_features": ["F03"],
        "models": [
            ("MarkovCNN",    "Ni et al. 2018 (Computers & Security)",
             "models/MarkovCNN_2018 | CNN-3 on 256\u00d7256 Markov transition image"),
        ],
    },
    "V8_entropy": {
        "label": "EntropyVis", "attck": "T1027",
        "binja_features": ["F04"],
        "models": [
            ("EntropyMapCNN","Conti et al. 2018 (VizSec)",
             "models/EntropyMapCNN_2018 | CNN-3 on 256\u00d7256 entropy heatmap"),
        ],
    },
    "V9_hash": {
        "label": "Hash", "attck": "T1036",
        "binja_features": ["G01", "G02", "G03", "G04"],
        "models": [
            ("HashEmbedNet", "Pagani et al. 2019 (CCS Workshop)",
             "models/HashEmbedNet_2019 | Embedding(hash\u219264)\u00d74\u2192MLP"),
        ],
    },
    "V10_metadata": {
        "label": "Metadata", "attck": "T1036",
        "binja_features": ["H01", "H02", "H03"],
        # V2: ExportInfo+DataDirs=158d; V3额外含 RichHeader/Authenticode/ParseWarnings
        "ember_ranges": ["ExportInfo", "DataDirs", "RichHeader", "Authenticode", "ParseWarnings"],
        "models": [
            ("MetadataNet", "Shafiq et al. 2009 (RAID)",
             "models/MetadataNet_2009 | MLP(128,64) on version/resource/manifest"),
            ("ResourceNet", "Ahmadi et al. 2016 (MS BIG)",
             "models/MicrosoftBIG_2016 | MLP(64,32) on resource features"),
        ],
    },
    "V11_ensemble": {
        "label": "Full", "attck": "Multiple",
        "binja_features": [],
        "ember_ranges": ["__ALL__"],
        "models": [
            ("Ember_NDF",      "Anderson & Roth 2018 (EMBER)",
             "models/Ember_2018 | NeuralDecisionForest(SoftTrees\u00d710)"),
            ("EmberGBDT",      "Anderson & Roth 2018 (EMBER)",
             "models/EmberGBDT_2018 | LightGBM(leaves=2048,depth=15,n=1000)"),
        ],
    },
}

# 兼容旧引用
VIEW_GROUPS_FULL = VIEW_GROUPS
VIEW_GROUPS_EMBER = {k: v for k, v in VIEW_GROUPS.items() if "ember_ranges" in v}

# ── 视角可用性策略 (PE_RAW 训练) ──────────────────────────────────
# V6_opcode_* / V6_func_embed / V7_graph 依赖 BinaryNinja 反汇编 (D/E 特征)。
# 若 BN 不可用 (例如 Personal 许可不支持 headless), 这些视角永远提取不出来。
#
#   VIEWS_REQUIRE_ALL = 1 (严格/旧行为)
#       缺任何一个视角 → 该样本被整个排除。
#       在 BN 不可用的机器上会导致"所有样本都被排除" → train_months 全空 → 无法训练。
#   VIEWS_REQUIRE_ALL = 0 (默认/自适应)
#       构建月度缓存时先探测 .npz 实际含有哪些 feature_id, 把本数据集根本取不到的
#       视角从 active_views 中剔除 (对应模型不参与集成), 样本**不丢**。
#       仍然对"保留下来的视角"严格要求: 任一缺失 → 该样本排除 (防止半残样本污染训练)。
#
# 环境变量覆盖: CODEFENDER_VIEWS_REQUIRE_ALL=1
VIEWS_REQUIRE_ALL = os.environ.get("CODEFENDER_VIEWS_REQUIRE_ALL", "0") != "0"

# ═══════════════════════════════════════════════════════════════
# nkrepo 哈希库（SHA256 + MD5 预检）
# ═══════════════════════════════════════════════════════════════
# 说明：构造参数必须与建库时一致（layout=hex + fp_rate=0.01 + max_open_shards=16），
# 否则 HashSignatureDB._sync_layout 会触发全量重分片（62M 条约 311s）。
HASH_DB_ENABLED = os.environ.get("CODEFENDER_HASH_DB_ENABLED", "1") != "0"
HASH_DB_DIR     = os.environ.get("CODEFENDER_HASH_DB_DIR", os.path.join(ROOT, "signatures"))
HASH_DB_LAYOUT  = os.environ.get("CODEFENDER_HASH_DB_LAYOUT", "hex")
HASH_DB_SHARDS  = int(os.environ.get("CODEFENDER_HASH_DB_SHARDS", "4"))   # hex 布局下内部固定 256 片
HASH_DB_FP_RATE = float(os.environ.get("CODEFENDER_HASH_DB_FP_RATE", "0.01"))
HASH_DB_MAX_OPEN = int(os.environ.get("CODEFENDER_HASH_DB_MAX_OPEN", "16"))

# ── fuzzy 模糊哈希库（第三级预检: sha256 → md5 → fuzzy）─────────────
# ssdeep 为纯 Python 实现 (ppdeep), 耗时随输入近线性 (1MB≈24s):
# 预检是同步路径, 默认只对 ≤256KB 的文件算 ssdeep; 超限只算
# PE 类哈希 (imphash/authentihash, pefile 解析毫秒级)。
FUZZY_DB_ENABLED  = os.environ.get("CODEFENDER_FUZZY_DB_ENABLED", "1") != "0"
FUZZY_DB_MAX_OPEN = int(os.environ.get("CODEFENDER_FUZZY_DB_MAX_OPEN", "16"))
FUZZY_DB_MAX_BYTES = int(os.environ.get("CODEFENDER_FUZZY_DB_MAX_BYTES", str(256 * 1024)))

# ── tlsh 第四级预检限流 (仅在前三级全未命中时才计算) ─────────────────
# 实测本地 tlsh.py (纯 Python) ≈ 0.53 MB/s → 256KB≈0.5s / 1MB≈1.9s / 2MB≈3.8s / 16MB≈30s。
# 库内 292 万条 tlsh 签名的大小分布: ≤256K 19.2% | ≤1M 39.2% | ≤2M 57.9% | ≤4M 81.9%。
# 在线单文件 (/predict-single) 默认 1MB = "覆盖率 × 同步延迟"的折中 (≤1.9s/文件);
# 离线批量 (/predict-directory) 用独立档位, 默认 2MB (覆盖率 ≈58%, 单文件 ≤3.8s 可接受)。
# 注意: _hash_precheck_file 的 fuzzy 级读文件硬上限 64MB, 两个档位都受它约束。
FUZZY_DB_TLSH_MAX_BYTES = int(os.environ.get(
    "CODEFENDER_FUZZY_DB_TLSH_MAX_BYTES", str(1024 * 1024)))
FUZZY_DB_TLSH_MAX_BYTES_OFFLINE = int(os.environ.get(
    "CODEFENDER_FUZZY_DB_TLSH_MAX_BYTES_OFFLINE", str(2 * 1024 * 1024)))


# ═══════════════════════════════════════════════════════════════
# 运行时配置覆盖 —— 解决「改了配置不生效」
# ═══════════════════════════════════════════════════════════════
# 本文件所有常量都在 **import 时** 从 os.environ 读一次并固化。所以"改配置不生效"
# 的根因从来不是读取逻辑，而是**改了的东西没有传给正在运行的进程**：
#   · 改了 shell 变量但没重启进程 / 重启的是另一个进程（端口被旧进程占着）
#   · 容器场景：env 在 `docker run` 时固化，`docker restart` 不会重新读 -e；
#     代码是 COPY 进镜像的，改宿主机 config.py 更是完全无关 → 必须重建镜像
#   · supervisord 托管：kill 后按自己的 environment= 拉起，shell 里的变量丢失
#
# 本节提供与 env 无关的旁路，优先级：
#       运行时 API (POST /admin/config) > runtime_config.json > 环境变量 > 默认值
# 其中 runtime_config.json 在 import 时自动加载，因此「改 JSON 文件 → 重启」也能生效，
# 不用再和 CMD/PowerShell 的环境变量语法搏斗。
#
# ⚠️ 但这条旁路是**开发期便利**，不是生产机制：本机开发经常需要"纯模型模式"
# 做对照（A/B 测模型真实性能、误报溯源、训练集打标），生产容器**绝不能**因为
# 一份被一起带进去的调试配置就悄悄退化成纯模型 —— 那是漏检，且日志只有一行 info。
# 故引入"环境档位"，见下方「开发/生产档位隔离」。

RUNTIME_CFG_FILE = os.environ.get(
    "CODEFENDER_RUNTIME_CFG_FILE", os.path.join(ROOT, "runtime_config.json"))


# ═══════════════════════════════════════════════════════════════
# 开发/生产档位隔离 —— 本机可纯模型，容器必须全引擎
# ═══════════════════════════════════════════════════════════════
# 目标：`本机开发测试单独走模型链路` 与 `Docker 生产不走纯模型` 同时成立，且
# 开发期怎么折腾都不会被带进镜像。三层防护，任一层单独成立即生效：
#   ① 构建期：.dockerignore 排除 runtime_config.json；Dockerfile 只 COPY 指定文件
#   ② 运行期：容器内 / CODEFENDER_ENV=prod 时不读、也不写运行时覆盖文件
#      → 即使把整个项目目录挂载进容器、或镜像里就带着它，都不会生效
#   ③ 启动期：CODEFENDER_REQUIRE_HASH_DB=1 → 三库缺一即**拒绝启动**（响的失败）
#
# 本机开发默认 dev 档位：覆盖文件照常加载，行为与引入档位前完全一致（零迁移成本）。

def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("", "0", "false", "no", "off", "n", "f")


def detect_container() -> bool:
    """是否运行在容器里（Docker/K8s/Podman）——只用于把开发期覆盖文件关在容器外。"""
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", "r") as f:
            blob = f.read(4096)
        if any(t in blob for t in ("docker", "containerd", "kubepods", "podman")):
            return True
    except OSError:
        pass
    return False


# 环境档位：显式 CODEFENDER_ENV=dev|prod；未指定时"容器内=prod，否则=dev"
ENV_PROFILE = (os.environ.get("CODEFENDER_ENV") or "").strip().lower()
if ENV_PROFILE not in ("dev", "prod"):
    ENV_PROFILE = "prod" if detect_container() else "dev"

# runtime_config.json 是否参与加载/落盘（本机开发 True，生产容器 False）
RUNTIME_CFG_FILE_ENABLED = True
RUNTIME_CFG_DISABLED_REASON = ""
if _env_truthy("CODEFENDER_RUNTIME_CFG_DISABLE"):
    RUNTIME_CFG_FILE_ENABLED = False
    RUNTIME_CFG_DISABLED_REASON = "CODEFENDER_RUNTIME_CFG_DISABLE=1"
elif ENV_PROFILE != "dev" and not _env_truthy("CODEFENDER_RUNTIME_CFG_ALLOW"):
    RUNTIME_CFG_FILE_ENABLED = False
    RUNTIME_CFG_DISABLED_REASON = (
        f"环境档位={ENV_PROFILE}"
        + ("（检测到容器环境）" if detect_container() else "")
        + "；运行时覆盖文件仅在本机开发档位(CODEFENDER_ENV=dev)生效")

# 过滤引擎是否为"硬要求"：1 → 三库缺一/被关闭即拒绝启动（生产建议 1）。
# 现有实现遇到库缺失是**静默降级为纯模型**（服务照常 200、只是预检不再命中），
# 开发期很方便，生产期就是漏检 —— 生产要响的失败，不要静悄悄的降级。
REQUIRE_HASH_DB = _env_truthy("CODEFENDER_REQUIRE_HASH_DB")

# name → (环境变量名, 类型, 是否可运行时热生效)
#   hot=True  : 使用方都是"调用时读 config.X"，模块属性一改立刻有用
#   hot=False : 仅启动期读取一次（如数据集构建期开关），改完必须重启进程
_RUNTIME_SPEC = {
    "HASH_DB_ENABLED":                 ("CODEFENDER_HASH_DB_ENABLED", "bool", True),
    "FUZZY_DB_ENABLED":                ("CODEFENDER_FUZZY_DB_ENABLED", "bool", True),
    "HASH_DB_DIR":                     ("CODEFENDER_HASH_DB_DIR", "str", True),
    "FUZZY_DB_MAX_BYTES":              ("CODEFENDER_FUZZY_DB_MAX_BYTES", "int", True),
    "FUZZY_DB_TLSH_MAX_BYTES":         ("CODEFENDER_FUZZY_DB_TLSH_MAX_BYTES", "int", True),
    "FUZZY_DB_TLSH_MAX_BYTES_OFFLINE": ("CODEFENDER_FUZZY_DB_TLSH_MAX_BYTES_OFFLINE", "int", True),
    "VIEWS_REQUIRE_ALL":               ("CODEFENDER_VIEWS_REQUIRE_ALL", "bool", False),
}
RUNTIME_SPEC = _RUNTIME_SPEC  # 公开别名（供 engine/app.py 校验入参使用）

_TRUE_TOKENS = ("1", "true", "yes", "on", "y", "t")
_FALSE_TOKENS = ("0", "false", "no", "off", "n", "f", "")


def parse_runtime_value(name: str, raw):
    """把外部输入（JSON 值 / 字符串）解析成 spec 声明的类型；非法值抛异常。"""
    key = str(name).upper()
    if key not in _RUNTIME_SPEC:
        raise KeyError(f"不支持运行时覆盖的配置项: {key}")
    typ = _RUNTIME_SPEC[key][1]
    if typ == "bool":
        if isinstance(raw, bool):
            return raw
        s = str(raw).strip().lower()
        if s in _TRUE_TOKENS:
            return True
        if s in _FALSE_TOKENS:
            return False
        raise ValueError(f"{key}: 无法解析为布尔值 ({raw!r})，应为 1/0/true/false")
    if typ == "int":
        return int(raw)
    return str(raw)


def runtime_cfg_state() -> dict:
    """每个可覆盖项的当前值 / 来源 / 是否支持热生效，供 GET /admin/config 输出。"""
    out = {}
    for name, (env, typ, hot) in _RUNTIME_SPEC.items():
        ov = _RUNTIME_OVERRIDES.get(name)
        if ov is not None:
            origin = f"runtime:{ov[1]}"
        elif os.environ.get(env) is not None:
            origin = "env"
        else:
            origin = "default"
        out[name] = {
            "value": globals().get(name),
            "origin": origin,
            "type": typ,
            "env": env,
            "env_raw": os.environ.get(env),
            "baseline": _BASELINE.get(name),
            "hot_reload": hot,
        }
    return out


def apply_runtime_overrides(overrides, origin="api", persist=False, path=None):
    """应用覆盖（直接改写模块属性 → 所有 `config.X` 使用方立刻可见）。

    Args:
        overrides: {"HASH_DB_ENABLED": False, ...}，键大小写不敏感
        origin:    来源标记，仅用于状态展示（"api" / "file"）
        persist:   True 时把当前覆盖集合写回 runtime_config.json
    """
    # 先全部解析校验、再统一赋值 —— 保证原子性：任一项非法则一项都不生效，
    # 避免"改了一半"这种最难排查的中间态。
    parsed = {}
    for k, raw in overrides.items():
        key = str(k).upper()
        parsed[key] = parse_runtime_value(key, raw)
    for key, val in parsed.items():
        globals()[key] = val
        _RUNTIME_OVERRIDES[key] = (val, origin)
    if persist:
        save_runtime_cfg_file(path)
    return parsed


def reset_runtime_overrides(names=None):
    """把指定（默认全部）覆盖项恢复成 import 时的基线（env 或默认值）。"""
    if names is None:
        names = list(_RUNTIME_OVERRIDES)
    keys = [str(k).upper() for k in names]
    bad = [k for k in keys if k not in _RUNTIME_SPEC]
    if bad:                       # 先校验再动手，保证原子性
        raise KeyError(f"不支持运行时覆盖的配置项: {bad}")
    restored = {}
    for key in keys:
        _RUNTIME_OVERRIDES.pop(key, None)
        old = globals().get(key)
        globals()[key] = _BASELINE[key]
        restored[key] = {"from": old, "to": _BASELINE[key]}
    return restored


def save_runtime_cfg_file(path=None) -> str:
    """把当前运行时覆盖集合落盘（原子写：先写 .tmp 再 os.replace）。

    生产档位（容器 / CODEFENDER_ENV=prod）直接拒绝：落盘会在容器里留下一个
    跨重启的调试开关，而 ①容器文件在重启后仍在（若挂了宿主机目录）、
    ②生产要改配置应走 codefender.ini 的 environment=，可审计、可回滚。
    免重启的**内存内**热切换不受影响（不落盘、重启即恢复）。
    """
    p = path or RUNTIME_CFG_FILE
    if not RUNTIME_CFG_FILE_ENABLED:
        raise PermissionError(
            f"运行时覆盖文件在当前档位被禁用（{RUNTIME_CFG_DISABLED_REASON}）。"
            f"生产请改用环境变量（codefender.ini 的 environment= 行）；"
            f"确需启用：CODEFENDER_ENV=dev 或 CODEFENDER_RUNTIME_CFG_ALLOW=1")
    doc = {
        "_comment": "CoDefenderC3 运行时配置覆盖（仅本机开发档位生效）。改此文件后："
                    "重启进程即生效，或 POST /admin/config {\"reload_file\": true} "
                    "免重启生效。删除本文件 = 回到环境变量/默认值。",
        "_warning": "本文件是开发期便利，不会进 Docker 镜像、容器内也不会加载它。"
                    "生产改配置请用 codefender.ini 的 environment=。",
        "overrides": {k: v for k, (v, _o) in sorted(_RUNTIME_OVERRIDES.items())},
    }
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, p)
    return p


def load_runtime_cfg_file(path=None, origin="file"):
    """读取覆盖文件并应用。返回 (applied_dict, error_str)；不存在/被禁用返回 ({}, "")。"""
    p = path or RUNTIME_CFG_FILE
    if not RUNTIME_CFG_FILE_ENABLED:      # 生产档位：连读都不读
        return {}, ""
    if not os.path.isfile(p):
        return {}, ""
    try:
        with open(p, "r", encoding="utf-8") as f:
            doc = json.load(f)
        if isinstance(doc, dict):
            ov = doc.get("overrides")
            if ov is None:
                ov = {k: v for k, v in doc.items() if not str(k).startswith(("_", "//"))}
        else:
            ov = {}
        if not isinstance(ov, dict):
            raise ValueError("overrides 必须是对象")
        return apply_runtime_overrides(ov, origin=origin), ""
    except Exception as e:
        return {}, f"{type(e).__name__}: {e}"


# ── import 收尾：先快照基线，再应用覆盖文件 ───────────────────────
_BASELINE = {name: globals().get(name) for name in _RUNTIME_SPEC}
_RUNTIME_OVERRIDES = {}
RUNTIME_CFG_ERROR = ""
RUNTIME_CFG_APPLIED = []

RUNTIME_CFG_EXISTS = os.path.isfile(RUNTIME_CFG_FILE)
# 文件存在却被档位拦下 —— 必须让启动日志喊出来，否则"我明明放了配置却没生效"
# 又会变成一次纯靠人肉的排查。
RUNTIME_CFG_SKIPPED = bool(RUNTIME_CFG_EXISTS and not RUNTIME_CFG_FILE_ENABLED)

_loaded, RUNTIME_CFG_ERROR = load_runtime_cfg_file()
if _loaded:
    RUNTIME_CFG_APPLIED = sorted(_loaded)
