# 重训 R0 数据工具与安全门禁

日期：2026-11-13（Asia/Shanghai）。对应评估建议的第一项 P0；不是正式训练或发布验收。

## 当前范围

- analyze_retrain_manifests.py：六份原始 CSV 的流式审计；SQLite 索引、输入 SHA256、字段覆盖、规模、精确重复、跨标签冲突。
- plan_retrain_split.py：保留实际观测日期，输出 train/model_val/calibration/test；另存 source_ood 与逐行排除账本。
- verify_retrain_manifest.py：定位样本，只读取字节、SHA256、尺寸、PE 结构头；不执行、不加载、不解包 PE。
- build_retrain_dataset.py：只按已核验白名单物化；不二次按数量截断，不提取特征，不启动训练。
- 旧 PELoader 已增加拒绝门禁：显式 split 不允许被旧 month 逻辑悄悄合并。**四角色矩阵加载和训练循环尚待下一项 P0 实现。**

所有输出目录必须是新目录或空目录，无覆盖选项。不要使用旧 build_minimal_dataset.py 将这份白名单重新随机分桶。

## 切分规则与局限

1. 恶意：2026-01~03 train；2026-04 的组用固定种子分到 model_val/calibration；2026-05 test。
2. 不回迁未来内容。更早窗口出现过的精确组，后续记录标记 seen_group_in_earlier_window。
3. SHA 去重、SHA 跨标签或元数据冲突、跨标签精确 ssdeep 组，全部先隔离再采样；组内只取一个代表。
4. Sophos-ReversingLabs 独立留出；其全部组禁止参与主数据集，即便另一个来源在早期见过该组。
5. 良性无真实出现时间。按组哈希 70/10/10/10 分配四角色，**不是良性时间外推**，也不以 created_at/updated_at 冒充真实出现时间。
6. 分配角色后才按 filetype × size_bucket 格内 1:1 匹配；不借用其他留出集供给。pair-cap 是每个角色的配对预算，不是全局数量。
7. 尺寸桶使用 KiB/MiB（1024 进制），半开边界；默认尺寸上限 16MiB，等于上限的文件允许入选。
8. 分组是 SHA + 精确 ssdeep 字符串，**不是近似相似度/TLSH 聚类，也不是完整软件谱系去重**。规则版本和局限写入报告。
9. date 字段/文件名前缀只记录为来源语义尚未确认的观测时间；原清单标签也不被自动升级为可信标签。
10. filetype=pe 的主集记录先隔离为待解析，不猜测 EXE/DLL；OOD 可以保留待解析记录，但不能据此宣称已具备模型覆盖。

## 重建清单（PowerShell）

以下示例输出路径仅作后续复跑示例，存在时请换新名称。

    $repo = 'D:\VM_Share\NKAMG-AIDefender\NKAMG-AIDefender'
    $py = 'C:\Users\lenovo\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    $mal = 1..5 | ForEach-Object { Join-Path $repo ('retrain\malicious_pe_2026_0{0}.csv' -f $_) }
    & $py -B -X utf8 "$repo\CoDefenderC3\train\plan_retrain_split.py" --benign "$repo\retrain\benign.csv" --malicious $mal --out "$repo\outputs\retrain-r0-rerun" --seed 20261113

仅审计时改用 analyze_retrain_manifests.py，参数为 --benign / --malicious / --out。工具不依赖 torch、sklearn 或 pefile。

输出：manifest_audit.json、split_plan.json、selection_manifest.csv、source_ood_manifest.csv、exclusion_ledger.csv、manifest.sqlite3。
报告含输入与工具 SHA256；selection_manifest 的 SHA256 固定后再做路径校验。

## 路径定位与校验

原始恶意 CSV 没有本机样本路径；良性 CSV 的 /home/... 路径也不自动映射为本机目录。必须提供真实样本根或 sha256,path 映射。

    python D:\VM_Share\NKAMG-AIDefender\NKAMG-AIDefender\CoDefenderC3\train\verify_retrain_manifest.py --manifest <selection_manifest.csv绝对路径> --sample-root <真实样本根绝对路径> --out <新校验目录绝对路径>
    python D:\VM_Share\NKAMG-AIDefender\NKAMG-AIDefender\CoDefenderC3\train\verify_retrain_manifest.py --manifest <selection_manifest.csv绝对路径> --path-map <sha256,path映射CSV绝对路径> --out <新校验目录绝对路径>

每个 sample-root 查找：root/sha、root/samples/sha、root/benign或malicious/sha、root/a/b/c/d/e/sha（SHA 前五位）、root/前两位/再两位/sha。不做全盘递归搜索。
映射文件路径相对值以映射 CSV 所在目录为基准；显式映射是权威路径，写错时不悄悄回退。

只要有缺失、尺寸/哈希/PE 类型不符，或任何角色缺一类，退出码为 2、build_allowed=false。失败行仍留在 verified_selection_manifest.csv 和 path_audit.csv，**不静默减少分母**。

字节全部核验通过只意味着可物化，不意味着可以训练；标签、近重复、时间含义和输入契约仍待核验。

## 白名单物化

    python D:\VM_Share\NKAMG-AIDefender\NKAMG-AIDefender\CoDefenderC3\train\build_retrain_dataset.py --manifest <verified_selection_manifest.csv绝对路径> --plan <split_plan.json绝对路径> --audit <path_audit.json绝对路径> --out <新数据集目录绝对路径>

可选 --link 优先硬链接，失败回退复制；只有确认源样本不再修改时才使用。默认复制。

物化前验证 plan→原 selection→path audit→verified manifest 的指纹链，再次全量校验源字节；复制后再校验目标 SHA256。
metadata.jsonl 保留 YYYY-MM 和 split，不把角色编码成 month=1/2/3。metadata.json 明确 training_ready=false、feature_extraction_performed=false。

## 下一实施顺序

1. P0：split-aware loader/matrix，样本 ID 与特征行严格对齐，版本化内容/特征缓存；替换当前拒绝门禁。
2. P0：PyTorch 使用外部 model_val 早停；calibration 独立用于权重/工作点，test 不出现在训练入口；checkpoint 与发布模型状态门禁。
3. P0：离线/HTTP 共用显式 weights/allowlist/calibration/threshold 决策包，绑定输入 schema/维度指纹。
4. P1：同源 full/masked 变换、统一低误报评测、失败状态和发布回滚。

没有实际原始样本根、没有可靠良性软件谱系/额外验收集、没有有效特征契约时，不启动正式 T2。

## 本轮实际结果（固定版本）

- 工程回归 21/21 通过；4 个 CLI --help 通过；7 个新增/修改 Python 源文件 AST 语法通过。未验证真实模型训练、特征提取或 HTTP。
- 全量原始输入 2,707,563 行：良性 40,000，恶意 2,667,563；4 个跨标签 SHA256，4 个跨标签精确 ssdeep 组。
- 训练 18,926（每类 9,463），model_val 2,046（每类 1,023），calibration 2,006（每类 1,003），test 1,926（每类 963）。合计 24,904。
- source_ood 205,293 个精确组代表；逐行排除账本 2,477,366 行。所有输入行均已入账。不是原计划的未去重 OOD 数量，也不是完整恶意总体评测。
- 10 行因跨标签/元数据冲突组隔离，122,594 行因更早时间窗口已见组隔离，1,056 行主来源成员保留给 source_ood。其余排除原因见 split_plan.json。
- 独立重读三份 CSV 确认所有格内 1:1、主集/OOD SHA 和精确组唯一、跨资产精确组重叠 0、时间无回迁、输入/输出/工具 SHA256 对齐。
- 未提供 sample-root/path-map，按当前 manifest 原路径 24,904 条全部未找到字节：path audit 退出码 2、build_allowed=false。**不能推断这些文件在整台电脑上都不存在**。
- 当前 test 仅 963 个良性样本，且软件谱系独立性未验证；不作为低误报上线承诺的验收集。
- 原计划/生产权重未修改，未启动特征提取、训练、热更新。

固定证据路径：

- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-13/final-plan/split_plan.json
- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-13/final-plan/selection_manifest.csv
- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-13/final-plan/exclusion_ledger.csv
- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-13/independent_validation.json
- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/outputs/retrain-implementation-2026-11-13/path-audit/path_audit.json
- D:/VM_Share/NKAMG-AIDefender/NKAMG-AIDefender/CoDefenderC3/docs/test-records/retrain_r0_2026-11-13.json

full-plan 与 full-plan-v2 是保留的、已终止的开发中间产物；不用于验收。所有大型派生产物已加入本轮专用 .gitignore 规则，避免误提交。
