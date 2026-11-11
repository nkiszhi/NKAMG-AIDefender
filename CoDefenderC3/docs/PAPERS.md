# 模型清单与参考材料

核对日期：2026-11-11。以工作区 [config.py](../config.py)、[model_registry.py](../model_registry.py)、[模型装载](../models/ensemble.py)和[在线流程](../engine/app.py)为准。此页是实现导航，不承诺严格复现论文架构、数据集或指标；目录中的年份及模型名称不是论文出处的核验证据。

## 1. 当前部署范围

- 配置包含 16 个视图组 / 35 个模型名，其中 `V11_ensemble` 的 `Ember_NDF`、`EmberGBDT` 为候选，不计入当前默认部署。
- 当前默认部署为 **33 个模型 / 15 个视图**：24 个 PyTorch、8 个 NumPy、1 个专用 MalGraph 流程。启动失败、权重缺失、特征缺失时，实际成功数会减少；以 `GET /model-info` 及扫描覆盖信息为准。
- 当前生产/开发扫描策略对成功模型分数等权取均值，严格大于 0.5 判恶意；并非“多数投票”，也不自动采用训练生成的 AUC 权重。Web 兼容返回口径见 [接口指南](README.md#4-接口返回数据差异)。
- `include_de=false` 跳过 10 个 D/E 依赖模型：OpcodeLSTM、OpcodeTransformer、OpcodeStatNet、AsmEmbedNet 及 V7 的全部 6 个模型。23 个剩余模型仍可能因样本或依赖失败，不能预先保证全部成功。

## 2. 部署模型与代码入口

下表“注册输入”是通用注册器的 `FeatureType`，不是所有路径实际拼接后的 PE_RAW 视图维度。不能仅凭模型名称推断运行时输入、完整拓扑或论文同构性；须结合特征适配器及权重检查。

| 视图组 | 模型名 | 装载类型 | 注册输入 | 实现入口 / 类 |
|---|---|---|---|---|
| `V1_byte` | `MalConv` | PyTorch | `RAW_BYTES` | [Malconv](../models/MalConv_2017/malconv.py) |
| `V1_byte` | `MalConv2` | PyTorch | `RAW_BYTES` | [MalConvGCT](../models/MalConv2_2021/malconv2.py) |
| `V1_byte` | `ByteTransformer` | PyTorch | `RAW_BYTES` | [ByteTransformer](../models/ByteTransformer_2023/byte_transformer.py) |
| `V2_byte_stat` | `SaxeBerlinDNN` | PyTorch | `EMBER_BYTEHIST` | [SaxeBerlinDNN](../models/SaxeBerlinDNN_2015/saxe_berlin.py) |
| `V2_byte_stat` | `EmberDNN` | PyTorch | `EMBER_BYTEHIST` | [EmberDNN](../models/EmberDNN_2018/ember_dnn.py) |
| `V2_byte_stat` | `NatarajKNN` | NumPy | `EMBER_BYTEHIST` | [NatarajKNN](../models/NatarajKNN_2011/nataraj_knn.py) |
| `V3_pe_struct` | `DrebinSVM` | NumPy | `EMBER_PE_STRUCT` | [DrebinLinear](../models/DREBIN_2014/drebin.py) |
| `V3_pe_struct` | `DL4MD` | PyTorch | `EMBER_PE_STRUCT` | [DL4MD](../models/DL4MD_2016/dl4md.py) |
| `V3_pe_struct` | `PEMinerRF` | NumPy | `EMBER_PE_STRUCT` | [PEMinerRF](../models/PEMiner_2009/peminer.py) |
| `V4_import` | `DrebinImport` | NumPy | `EMBER_IMPORT` | [DrebinLinear](../models/DREBIN_2014/drebin.py) |
| `V4_import` | `ALOHANet` | PyTorch | `EMBER_IMPORT` | [ALOHANet](../models/ALOHANet_2020/aloha.py) |
| `V4_import` | `EmberGBDT_Import` | NumPy | `EMBER_IMPORT` | [EmberGBDT](../models/EmberGBDT_2018/ember_gbdt.py) |
| `V5_string` | `RaffFeatureNet` | PyTorch | `EMBER_STRING` | [RaffFeatureNet](../models/RaffFeatureNet_2018/raff_feature.py) |
| `V5_string` | `DrebinString` | NumPy | `EMBER_STRING` | [DrebinLinear](../models/DREBIN_2014/drebin.py) |
| `V6_opcode_seq` | `OpcodeLSTM` | PyTorch | `OPCODE_SEQ` | [OpcodeLSTM](../models/OpcodeLSTM_2017/opcode_lstm.py) |
| `V6_opcode_seq` | `OpcodeTransformer` | PyTorch | `OPCODE_SEQ` | [OpcodeTransformer](../models/OpcodeTransformer_2020/opcode_transformer.py) |
| `V6_opcode_stat` | `OpcodeStatNet` | NumPy | `EMBER_BYTEHIST` | [OpcodeStatNet](../models/MicrosoftBIG_2016/ahmadi.py) |
| `V6_func_embed` | `AsmEmbedNet` | PyTorch | `FUNC_EMBEDDINGS` | [AsmEmbedNet](../models/Asm2Vec_2019/asm_embed.py) |
| `V7_graph` | `MalGraph` | 专用图流程 | 非通用注册项 | [MalGraph](../models/MalGraph_2022/) |
| `V7_graph` | `CFGGAT` | PyTorch | `GRAPH_STAT` | [CFGGAT](../models/CFG_GAT_2019/cfg_gat.py) |
| `V7_graph` | `CFGGCN` | PyTorch | `GRAPH_STAT` | [CFGGCN](../models/GCN_2017/cfg_gcn.py) |
| `V7_graph` | `CFGDGCNN` | PyTorch | `GRAPH_STAT` | [CFGDGCNN](../models/DGCNN_2018/cfg_dgcnn.py) |
| `V7_graph` | `CallGraphGNN` | PyTorch | `GRAPH_STAT` | [CallGraphGNN](../models/CallGraphGNN_2019/callgraph_gnn.py) |
| `V7_graph` | `GraphStatNet` | PyTorch | `GRAPH_STAT` | [GraphStatNet](../models/GraphStatNet_2022/graph_stat.py) |
| `V8_gray` | `GrayscaleCNN` | PyTorch | `GRAY_IMAGE` | [GrayscaleCNN](../models/GrayscaleCNN_2011/grayscale_cnn.py) |
| `V8_gray` | `InceptionV3` | PyTorch | `GRAY_IMAGE` | [InceptionV3Model](../models/InceptionV3_2020/InceptionV3.py) |
| `V8_color` | `IMCFN` | PyTorch | `COLOR_IMAGE` | [IMCFN](../models/IMCFN_2020/Imcfn.py) |
| `V8_color` | `ColorCNN` | PyTorch | `COLOR_IMAGE` | [ColorCNN](../models/ColorCNN_2019/color_cnn.py) |
| `V8_markov` | `MarkovCNN` | PyTorch | `MARKOV_IMAGE` | [MarkovCNN](../models/MarkovCNN_2018/markov_cnn.py) |
| `V8_entropy` | `EntropyMapCNN` | PyTorch | `ENTROPY_IMAGE` | [EntropyMapCNN](../models/EntropyMapCNN_2018/entropy_cnn.py) |
| `V9_hash` | `HashEmbedNet` | PyTorch | `EMBER_BYTEHIST` | [HashEmbedNet](../models/HashEmbedNet_2019/hash_embed.py) |
| `V10_metadata` | `MetadataNet` | PyTorch | `EMBER_METADATA` | [MetadataNet](../models/MetadataNet_2009/metadata.py) |
| `V10_metadata` | `ResourceNet` | NumPy | `EMBER_METADATA` | [ResourceNet](../models/MicrosoftBIG_2016/ahmadi.py) |

MalGraph 走专用图提取、词表和推理流程，不在通用注册器中。CFGGAT、CFGGCN、CFGDGCNN、CallGraphGNN 和 GraphStatNet 当前通用注册输入均为 `GRAPH_STAT`；这不等于证明每条运行路径都消费真实 CFG/FCG 拓扑。后端切换及特征兼容性见 [SMDA](SMDA_BACKEND.md)、[BN](BINARYNINJA_OPTIMIZATION_GUIDE.md)和 [IR 契约](IR_CONTRACT.md)。

## 3. 候选模型

| 配置组 | 模型 | 实现 |
|---|---|---|
| `V11_ensemble` | `Ember_NDF` | [models/Ember_2018/ember.py](../models/Ember_2018/ember.py) |
| `V11_ensemble` | `EmberGBDT` | [models/EmberGBDT_2018/ember_gbdt.py](../models/EmberGBDT_2018/ember_gbdt.py) |

候选配置/代码存在不代表已被默认在线流程启用或接受质量验收。训练特殊模型、缺失视图和输出发布的限制见 [训练指南](../train/README.md)。

## 4. 仓库内参考材料

下列 PDF 按现有文件整理。它们是背景材料，**不是逐模型严格复现声明**；同一材料可能对应多个改造实现，部分实现没有单独 PDF（例如 MalGraph、GraphStatNet、ColorCNN、MetadataNet、ResourceNet）。原文的作者、题名、版本与实验结论应由阅读者在 PDF 内核对，本文不沿用旧文档中未经核验的 DOI、性能或理论保证。

- **V1_字节级**：[ByteTransformer](../papers/V1_%E5%AD%97%E8%8A%82%E7%BA%A7/ByteTransformer.pdf)；[MalConv](../papers/V1_%E5%AD%97%E8%8A%82%E7%BA%A7/MalConv.pdf)；[MalConv2 (MalConvGCT)](../papers/V1_%E5%AD%97%E8%8A%82%E7%BA%A7/MalConv2%20%28MalConvGCT%29.pdf)
- **V2_字节统计**：[EmberDNN](../papers/V2_%E5%AD%97%E8%8A%82%E7%BB%9F%E8%AE%A1/EmberDNN.pdf)；[NatarajKNN](../papers/V2_%E5%AD%97%E8%8A%82%E7%BB%9F%E8%AE%A1/NatarajKNN.pdf)；[SaxeBerlinDNN](../papers/V2_%E5%AD%97%E8%8A%82%E7%BB%9F%E8%AE%A1/SaxeBerlinDNN.pdf)
- **V3_PE结构**：[DL4MD](../papers/V3_PE%E7%BB%93%E6%9E%84/DL4MD.pdf)；[DREBIN](../papers/V3_PE%E7%BB%93%E6%9E%84/DREBIN.pdf)；[PEMiner](../papers/V3_PE%E7%BB%93%E6%9E%84/PEMiner.pdf)
- **V4_导入导出**：[ALOHANet](../papers/V4_%E5%AF%BC%E5%85%A5%E5%AF%BC%E5%87%BA/ALOHANet.pdf)；[EmberGBDT](../papers/V4_%E5%AF%BC%E5%85%A5%E5%AF%BC%E5%87%BA/EmberGBDT.pdf)
- **V5_字符串**：[RaffFeatureNet](../papers/V5_%E5%AD%97%E7%AC%A6%E4%B8%B2/RaffFeatureNet.pdf)
- **V6_操作码**：[AsmEmbedNet](../papers/V6_%E6%93%8D%E4%BD%9C%E7%A0%81/AsmEmbedNet.pdf)；[OpcodeLSTM](../papers/V6_%E6%93%8D%E4%BD%9C%E7%A0%81/OpcodeLSTM.pdf)；[OpcodeStatNet](../papers/V6_%E6%93%8D%E4%BD%9C%E7%A0%81/OpcodeStatNet.pdf)；[OpcodeTransformer](../papers/V6_%E6%93%8D%E4%BD%9C%E7%A0%81/OpcodeTransformer.pdf)
- **V7_图拓扑**：[CFG-DGCNN](../papers/V7_%E5%9B%BE%E6%8B%93%E6%89%91/CFG-DGCNN.pdf)；[CFG-GAT](../papers/V7_%E5%9B%BE%E6%8B%93%E6%89%91/CFG-GAT.pdf)；[CFG-GCN](../papers/V7_%E5%9B%BE%E6%8B%93%E6%89%91/CFG-GCN.pdf)；[CallGraph-GNN](../papers/V7_%E5%9B%BE%E6%8B%93%E6%89%91/CallGraph-GNN.pdf)
- **V8_可视化**：[EntropyMapCNN](../papers/V8_%E5%8F%AF%E8%A7%86%E5%8C%96/EntropyMapCNN.pdf)；[IMCFN](../papers/V8_%E5%8F%AF%E8%A7%86%E5%8C%96/IMCFN.pdf)；[InceptionV3](../papers/V8_%E5%8F%AF%E8%A7%86%E5%8C%96/InceptionV3.pdf)；[MarkovCNN](../papers/V8_%E5%8F%AF%E8%A7%86%E5%8C%96/MarkovCNN.pdf)
- **V9_哈希**：[Towards interpreting ML-based automated malware](../papers/V9_%E5%93%88%E5%B8%8C/Towards%20interpreting%20ML-based%20automated%20malware.pdf)
- **V11_全特征集成**：[Ember NDF](../papers/V11_%E5%85%A8%E7%89%B9%E5%BE%81%E9%9B%86%E6%88%90/Ember%20NDF.pdf)

完整文档分类见 [INDEX](INDEX.md)。
