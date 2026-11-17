# P0：显式切分加载、行对齐与版本化缓存

日期：2026-11-13。承接 R0 清单工具，仅完成推荐顺序中的 data_loader/缓存这一项，**不是开训批准**。

## 1. 交付范围

- 新增 \train\retrain_contract.py、retrain_cache.py、retrain_loader.py。
- 新增 \train\retrain_feature_builder.py、retrain_feature_worker.py：每个样本独立子进程，静态分析，不执行 PE。
- 修改旧 create_loader 的 keyword-only opt-in 接口；默认旧入口仍拒绝 retrain-four-split-v1。旧 month-only 数据集保持原行为。
- 所有源码位于 D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/train/。

## 2. 明确角色，不伪造月份

只接受 train / model_val / calibration / test；没有 eval、val、月份或 get_range 别名。
加载时核对 R0 物化目录中的选择清单、计划、路径审计哈希及链路；metadata.jsonl 必须与已验证清单的 SHA/标签/组/真实日期/来源/大小等一致，路径只能在数据目录内。
重复 SHA、跨角色或跨标签组、越界路径、时间和计数偏差均拒绝。每次提取或读取矩阵还重新核对实际文件大小和 SHA，而不是仅检查 mtime。

样本按 SHA256 排序。返回的 SplitBatch 同时保存：

- sample_ids 与 labels：对应实际包含的特征行；
- requested_ids：原始请求分母；
- report：覆盖、纳入/排除 ID 和失败原因；
- feature/view/matrix 三类指纹。

get_split 不提取特征。默认覆盖不足抛 CoverageError（包含完整 report）；allow_partial=True 仅供显式诊断，不能据此默默缩小训练或验收分母。有效全零特征不被自动丢弃。

## 3. 特征与缓存契约

FeatureContract 要求完整有限 JSON、明确 backend/version/config、源码 SHA256、依赖精确版本、每个原始 feature 的 shape/dtype，以及每个 view 的有序 feature IDs、dtype、截断长度和显式 mask。
无缺项补零、维度推断、右填充或环境自动 mask。raw schema 允许既有提取器在**其已声明特征语义内**填充（例如固定 B01）；view 拼装不再额外猜测尺寸。

- 原始 NPZ：内容 SHA + 特征指纹 + analysis_status=ok。后端、代码、依赖、配置、原始 schema 改变即失效。
- 视图指纹：原始特征身份 + 有序视图/feature IDs + dtype/截断/mask。只改视图可复用原始 NPZ。
- 矩阵：成员身份/标签/组/时间等 + 精确原始 payload 校验和，保存只读 mmap NPY 与 ID/标签数组。
- 相同内容改名或搬目录可复用共享 cache_dir；同一路径即使大小与 mtime 不变，只要内容变化也拒绝复用。
- NPZ allow_pickle=False，拒绝缺项/额外项、对象数组、错 shape/dtype、非有限值、身份或校验和不符。
- 每键跨进程锁，临时文件写后原子替换；矩阵全部完成后才发布 current.json。失败的 generation 不参与读取，不递归删旧目录。
- current.json 不存在才视为正常 miss；已发布 generation 缺文件、损坏或行错位应报错，而不是偷偷重建。

这些哈希用于一致性和误损坏检测，**不是签名或防恶意篡改的信任根**。应保护清单、源码、契约和缓存的写权限。

## 4. 独立进程提取：目前允许的范围

SubprocessFeatureBuilder 每样本创建新进程和私有字节快照，显式 Python 与可选 package_paths。继承的 CODEFENDER_*、BN_*、PYTHONPATH/PYTHONHOME 被清除；额外包路径必须显式传入。硬超时终止并等待直接 worker；SMDA 本身的分析预算另行声明。

- fast：审计后的 _extract_byte_stats，B01–B07；不调用 extract_fast 中吞掉阶段异常的循环。
- smda：上述 B 特征 + D01–D07、E03/E04。必须明确 intel 后端（本地 SMDA 5.0.2 的架构后端参数）、API name style、>=30 秒 native budget 和正硬超时。
- E01/E02 拓扑、A/C/F/G/H 等未审计阶段**尚未开放**；请求它们报错，不用零特征冒充完整输出。这不是全模型可训练数据入口。
- worker 检查源码组合 SHA 和 Python/NumPy 精确版本；SMDA 还绑定 smda/capstone/lief/demangle/dncil/dnfile/purepdb/pefile 版本。
- native report 只有 status=ok 才继续 D/E 转换；timeout/error/未知状态、无指令/函数、缺项或 schema 不符均不写成功 NPZ。
- source_revision() 是上述关键源码字节的组合哈希，不依赖未提交的 Git HEAD。契约应在实验开始前冻结，不要每次加载自动重算并覆盖已有契约。

## 5. API 示例（仅已由 R0 核验并物化的数据目录）

从 D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/ 导入；以下绝对数据路径仅为示例，须替换为实际已验证目录。

```python
from train.data_loader import create_loader
from train.retrain_feature_builder import SubprocessFeatureBuilder

loader, kind = create_loader(
    r"D:\retrain-materialized",
    split_aware=True,
    feature_contract=r"D:\retrain-materialized\feature_contract.json",
    cache_dir=r"D:\retrain-feature-cache",
)
assert kind == "PE_RAW_SPLIT"

# 此调用只提取 train。model_val/calibration/test 不会顺带被读取或提取。
status = loader.ensure_features("train", SubprocessFeatureBuilder())
train = loader.get_split("train", views=["V1_byte"])
assert train.report["covered"] == train.report["requested"]
# 将 sample_ids、labels、report 与三类指纹一起保存在未来训练产物中。
```

契约示例所用的特征 schema 应人工冻结，而非从第一条样本推断。对于 B01，原始为 uint8[2097152]，V1_byte 可以显式声明 int32、length=32768、masked_features=[]。backend fast.version 应为 retrain-byte-stats-v1，config 只包含 hard_timeout_seconds；extractor.revision 来自 source_revision()，packages 来自 runtime_packages("fast")。正式模型所需额外 views/schema 必须另行审计。

## 6. 验证和未完成项

- 回归套件：R0 21 项 + 本项 37 项，共 58 项；测试证据以 JSON 记录和最终日志为准。
- 合成 fixture 使用真实 SHA 的最小 PE 头，共 10 条，四角色均有两类；只做静态 byte-stat 提取和缓存，不训练。
- 已实测 fast 独立进程 B01/B02、硬进程超时、跨进程锁、cache hit、遮罩/布局失效、严格覆盖与部分报告。
- SMDA timeout/error/未知报告门禁是注入测试。实际 native 导入在当前 Python 环境因 LIEF DLL 加载失败而被拒绝；**没有成功的真实 PE D/E 分析验证**。没有安装/替换生产依赖。
- R0 真实选择的 24,904 个样本仍未通过既有 manifest 路径定位；不能推断它们在整台机器上不存在。未重新扫描或改写 R0 大规模证据。
- 未启动训练，未修改 ensemble.pkl / 生产权重 / HTTP 决策。
- 下一 P0：train_all 的外部 model_val、独立 calibration、禁止 test 参与选权重、失败覆盖门禁及产物追踪。随后才是共享 prediction_policy 与模型序列化契约。

记录：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/docs/test-records/retrain_split_cache_p0_2026-11-13.json。
证据目录：D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-13/p0-split-cache/。
