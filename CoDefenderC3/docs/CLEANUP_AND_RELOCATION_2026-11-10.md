# 已验证代码回迁与清理（2026-11-10）

目标目录：D:\VM_Share\CoDefenderC3_v9；引擎在其 CoDefenderC3 子目录。
来源：main-test-lm-integration 工作区的已验证代码，包含默认 SMDA、main MalGraph/V1/V8、双接口契约及开发响应裁剪。

## 当前状态

- 来源工作区已完成代码清理和回归验证。
- D 盘直接替换的两次权限申请均因自动审核超时未执行；截至本次提交，未确认目标目录已替换，不能把以下回迁步骤当作已完成的部署验收。
- 用户要求将合并代码推送至 GitHub main。原始目录扫描响应保留在本机 scan-results/，不随源码提交；标准化回归证据保留在 docs/test-records/。

## 操作原则

- 不 reset/checkout 目标 Git，不删除 .git 或其他工作树；迁移属于文件级同步，旧目标 HEAD 可仍为 126a4ef。
- 用户已明确确认自己完成备份，要求直接替换，不再由代理创建或复制目标备份。覆盖、新建和删除均使用精确文件清单，并在操作前后核对 SHA256；需要恢复时依赖用户自己的已有备份，不使用目录镜像删除。
- 顶层 web、main MalGraph 代码/权重/词表、smda_extract.py 与来源逐文件一致。旧 test_lm MalGraph 训练缓存、图数据和额外权重按已核对清单从活动目录删除，不混入 main 模型目录；如需恢复，请使用用户已有备份。
- 不复制 .git/.venv/.feature_cache，不扫描或执行恶意样本；历史接口响应作为证据原样复制。
- 目标签名库、训练运行目录、实验结果、原始样本、构建缓存、本地配置覆盖文件、其他工作树及项目外工具不清理。
- 目标重新创建 --system-site-packages 的项目 .venv，复用同机 D:\conda\envs\ml，并离线复制已验证的 smda/dncil/dnfile 包；不复制带旧绝对路径的虚拟环境启动器。

## 明确删除的来源无用文件（16 个）

- engine/app copy.py、models/ensemble copy.py：未引用的旧副本。
- engine/_fix_import.py、_patch_app.py、_patch_v2.py、_patch_v3.py：已失效的一次性源码改写脚本，部分硬编码 v7 目录。
- engine/_verify.txt：历史临时输出。
- 根目录 _probe_csv_update.py、_probe_hashbase_update.py、_probe_pure_model.py、_probe_sig_update.py、_probe_tlsh_import.py。
- scaner/_probe_engine_tlsh.py、_probe_find_db_hit_sample.py、_probe_ssdeep_conv.py、_probe_tlsh_wire.py。

后两组是无外部引用的临时探针，功能验证由正式接口/运行测试承担。删除前已独立保存原文件内容及 SHA256。
保留有用途的回归脚本、训练脚本、BN 正式运行时与诊断工具，不按“没有 import”或文件名统一删除。

## 目标旧分支残留

- 旧命名器、bn_bootstrap 可选覆盖模块、被新契约回归替代的旧测试与基线 fixture，按回迁清单从活动代码树删除，防止混用两个版本。
- 旧 dev_bn.cmd 固定解释器、8000 对外监听且启动的是旧生产契约，从活动目录删除而不混入新开发启动方式。需要 BN 时对新 dev_model_only.cmd 显式设置 CODEFENDER_DISASM_BACKEND=bn。
- 旧 MalGraph 图/训练脚本以及配套缓存、权重与训练清单按用户已备份的确认直接删除；本次不再另建归档。
- 活动代码目录的旧 __pycache__/*.pyc 可再生成，按精确清单直接清理。

## 回迁后验证

在目标引擎目录使用本地 .venv/Scripts/python.exe：

    python -B -X utf8 tools/run_merge_regression.py --working-tree-only --report docs/test-records/relocated_regression_2026-11-10.json
    python -B -X utf8 tools/verify_merge_freeze.py --working-tree-only

默认冻结模式仍校验提交链、索引和工作区。新增 --working-tree-only 专供未改 Git HEAD 的文件部署，逐个核验 main 冻结 blob、缺失/多余文件、受保护函数及原 Web formatter，不以旧 HEAD 代替实际文件校验。

生产入口：engine.app:app；开发入口：engine.dev.app:app；共享入口：python -m engine.serve。
开发接口保持隐藏 PerModelPreds、AggregatedModels、PerModelDetails。BN 显式选择能力保留，但本次仅验收 SMDA/CPU，不承诺 BN 授权或 Docker/GPU 部署已验证。
