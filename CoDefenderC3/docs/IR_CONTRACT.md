# 非 MalGraph ProgramIR 候选契约

更新：2026-11-10。本文件描述本次定向合并的实际实现，不延用 test_lm 文档中的历史验收结论。

## 1. 范围与开关


test_lm 的后端中立 IR 仅作为 **D01–D07、E03–E04** 的候选实现接入。默认 `CODEFENDER_NON_MALGRAPH_IR=0`，沿用 main 原路径；显式设为 1 才启用候选。旧开关 `CODEFENDER_DE_CACHE=ir` 不开启候选，也不迁移旧缓存。

流程：PE → BN/SMDA features profile → ProgramIR → D/E 数值特征。A/B/C/F/G/H 继续由 main fast 路径产生，尤其 C01 保持 main count/max 归一化。

**MalGraph 不消费 ProgramIR**：模型目录、权重、词表、图提取、运行时和训练缓存均保留 main。IR 保留的 keywords/constant_count/call_sites 等扩展字段只保证完整往返，不代表接入 test_lm MalGraph。

## 2. 不变量与 schema

当前 schema：**codefender-ir/2**。不将旧 v1 缓存当作兼容命中；v2 修复了额外字段序列化丢失的问题。

| 对象 | 必须保留的内容 |
|---|---|
| ProgramIR | 有序 functions、imports、arch、bitness、backend、backend_version |
| Function | start、size、有序 blocks/callees、callees_known、name、有序 call_sites |
| BasicBlock | start、length、有序 instructions/successors、constant_count、n_outgoing、keywords |
| CallSite | address、target、name、kind |

1. functions/blocks/instructions/callees 的遍历顺序是语义，不排序去重。
2. callees 保留重复；未知 callees 与已知空 callees 不等价。
3. 地址为整数，集合字段使用 tuple，数据类 frozen。
4. 助记符在适配器中过滤空串、规范为小写；CFG 后继顺序原样保留。
5. n_outgoing 是原始边数，可能不同于能解析目标地址的 successors 数；缺失时才退化为 successors 长度。
6. IR validate 是结构检查；特征入口还要求非空函数/指令，9 个 D/E 特征齐全且有限，D01 非零、D05 函数计数有效。不能把非空字典中的全零分析当成功。

序列化使用规范 JSON、助记符表及 gzip；所有上述字段必须往返不丢失。运行时缓存另加身份元数据和 payload SHA256，不只信任扩展名或文件存在。

## 3. 两层缓存

默认根：引擎目录下 `.cache/non-malgraph-ir-v1`；可用 `CODEFENDER_IR_CACHE_DIR` 指定独立根。目录名中的 v1 是缓存命名空间名，**不是 IR schema**。

IR 身份包含：样本内容 SHA256、后端名称及实际版本、analysis config、features profile、adapter revision、IR schema、cache schema。特征层再加入 FEATURE_SCHEMA；当前为 `non-malgraph-de/1-main-fast-crc32`。

- 同路径内容变化得到新键；相同内容移动路径不改变内容身份。
- IR 与数值特征分别缓存；特征 schema 变更不复用旧数值数组。
- 线程锁 + OS 文件锁；独立临时文件、fsync、完整校验后原子替换。
- 不采用 append/旧成员跳过协议，不将半写 NPZ 当成成功。
- 损坏文件隔离为 `*.corrupt-<uuid>`，不批量删除用户缓存。
- 生成 IR/特征期间内容变化拒绝成功写入；空分析、超时、崩溃不留下成功标记。
- 不读取 main 的 path-MD5、bndb、旧 NPZ 或 MalGraph 缓存作为候选命中。

## 4. 接口与训练接线

推理通过 main 的隔离分析 worker，仅替换非 MalGraph D/E 部分；图样本仍由 main worker 和 main MalGraph utils 生成。

训练的 candidate 分支使用逐样本 worker、内容身份和独立 namespace。成功逐样本记 de_done；硬失败记 de_fail；超时/异常退出记 de_retry。失败日志包含内容身份，不因同名旧失败永久屏蔽已修改文件。

候选当前**每次重建月矩阵**，仅复用校验后的逐样本缓存；不读取 main 的 basename 黑名单，不自动丢弃缺失视图。默认关闭时 main 训练逻辑保持。

## 5. 验证边界

本轮有 IR 结构/往返、空分析、稳定散列、缓存身份/损坏/并发/原子写入、候选训练编排的自动化回归，详见合并实施记录和 JSON 证据。

本轮**没有**完成真实 BN/SMDA 后端的逐位差分、全量训练、精度/性能测量。test_lm 历史文档中的 288/288、缓存体积倍数等结论未在当前代码与环境复测，不能作为本次上线证据。更不能用合成 IR 测试证明旧模型权重与候选特征数值分布兼容。

启用候选前需要独立黄金集、后端及权重指纹、特征逐位/容差差分、模型覆盖率与召回等评估；验收前不得默认切生产。
