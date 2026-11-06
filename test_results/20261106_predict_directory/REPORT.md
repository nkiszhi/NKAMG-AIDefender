# CoDefenderC3 批量扫描测试报告

- 数据集：`D:\样本\DataSet_test`（benign 300 + malicious 300，共 600 个 PE 样本）
- 接口：`POST /predict-directory?directory=<目录>&recursive=true&include_de=false`
- 服务：`D:\conda\envs\ml\python.exe -u -m uvicorn engine.app:app --host 0.0.0.0 --port 8000`（dev 档，PID 36400）
- 模型：`ensemble.pkl`（md5 6cb4c2b9861d189f8d8e59f1677d3300，33 个子模型 / 15 视角）
- 签名库：SHA256 3,571,778 条、MD5 3,440,677 条、Fuzzy 5,731,983 条（ssdeep/tlsh/imphash/authentihash）
- 时间：2026-11-06 21:26 - 21:40 (Asia/Shanghai)
- 全量扫描两次：模式 A = 默认（哈希预检 + 模型）；模式 B = 纯模型（POST /admin/config 设 hash_db_enabled=false，跑完已恢复）

## 一、总体指标

| 指标 | 模式 A：哈希预检+模型（默认） | 模式 B：纯模型 |
|---|---|---|
| TP / FN / FP / TN | 300 / 0 / 27 / 273 | 256 / 44 / 27 / 273 |
| Accuracy | **95.5%** | 88.17% |
| Precision（恶意类） | 91.74% | 90.46% |
| Recall（恶意类） | **100%** | **85.33%** |
| Specificity（良性类） | 91% | 91% |
| F1 | 95.69% | 87.82% |
| ErrorCount / Timeout | 0 / 0 | 0 / 0 |

## 二、最关键的结论

**模式 A 的 100% 召回完全来自签名库，不是模型能力。**

- 模式 A 中 malicious 侧 300 个样本的 VirusName 全部为 `Malicious`（哈希命中路径的统一标签），说明 300/300 都是签名库短路直出，模型一次都没跑。
- 模式 B 关掉哈希预检后，模型只认出 256/300 个恶意样本，**漏报 44 个**（全部判为 `Benign`）。
- 两模式逐文件比对：判定不一致的正好 44 个文件，且全部是「A=恶意(签名库) / B=良性(模型)」——即这 44 个是**签名库独有**的捕获能力。
- 耗时对比也印证：模式 A 的 malicious 侧 300 个样本只用了 **5.8 秒**（全是哈希短路），模式 B 同样 300 个用了 **222 秒**（逐个跑模型）。

## 三、误报分析（27 个，两模式完全一致，属模型侧问题）

模式 A 与模式 B 的 27 个误报是同一批文件 → 都是模型判出来的，不是签名库误伤。

| 分项 | 数量 |
|---|---|
| 合计 FP | 27 |
| 标签 Generic.ML.Low（0.500 ≤ 聚合分 < 0.620） | 25 |
| 标签 Generic.ML.Medium（0.620 ≤ 聚合分 < 0.780） | 2 |
| 其中判定为加壳 | 27（packer: Unknown(petite), , Unknown(.xda1), Unknown(.xda2)） |
| 其中未加壳 | 0 |

**判读**：27 个误报全部落在 Generic.ML.Low / Medium 区间，没有一个是 High，说明聚合分集中在 0.50-0.62 的低分段、刚过判定线 0.500。加壳样本（petite / .xda1 / .xda2）误报率明显更高——加壳会抬高字节级与熵特征，触发 EMBER 系列模型；与第二节的漏报可能同源于特征分布问题。

## 四、漏报分析（模式 B 特有，44 个）

- 全部被判为 `Benign`（聚合分 < 0.500），无一误判为恶意
- 未加壳 0 个、加壳 44 个（含 1 个 UPX）
- 完整清单见 `per_file_modelonly.csv`（truth=1 且 pred=0 的行）

## 五、产出文件

| 文件 | 说明 |
|---|---|
| raw_benign.json / raw_malicious.json | 模式 A 的接口原始响应（投影后字段） |
| raw_benign_modelonly.json / raw_malicious_modelonly.json | 模式 B 的接口原始响应 |
| per_file.csv | 模式 A 逐文件结果（dir,file,truth,pred,label,sha256,md5,packed,packer） |
| per_file_modelonly.csv | 模式 B 逐文件结果 |
| metrics.json | 两种模式的混淆矩阵与指标 |

## 六、复现命令

```bash
# 模式 A（默认）
curl -X POST "http://127.0.0.1:8000/predict-directory?directory=D%3A%5C%E6%A0%B7%E6%9C%AC%5CDataSet_test%5Cbenign&recursive=true&include_de=false"

# 模式 B（纯模型）
curl -X POST -H "Content-Type: application/json" -d '{"hash_db_enabled":false,"fuzzy_db_enabled":false}' http://127.0.0.1:8000/admin/config
# ... 再调 predict-directory ...
curl -X POST -H "Content-Type: application/json" -d '{"reset":["HASH_DB_ENABLED","FUZZY_DB_ENABLED"]}' http://127.0.0.1:8000/admin/config
```

## 七、注意事项

1. `MAX_BATCH_FILES=500`（CODEFENDER_MAX_BATCH_FILES），600 个样本一次调用会返回 400，因此按子目录分两次扫。
2. 本机未安装 BinaryNinja，include_de=false 生效，D/E（反汇编/图）视角特征缺失，V7_graph 等图模型视角实际不可用——这会同时压低恶意侧召回。要评估完整能力需装 BN 商业库后用 include_de=true 重跑。
3. ensemble.pkl 是 W0 稳定哈希修复**之前**训练的权重（见 docs/FEATURE_HASH_STABILITY.md 的强制重训清单）；若特征哈希口径已变更，权重与当前特征存在语义错配，可能是上述误报/漏报的根因之一。
4. 服务当前仍运行在 8000 端口，签名库已在模式 B 测试后恢复为开启状态（engine_mode=hash_db+model）。
