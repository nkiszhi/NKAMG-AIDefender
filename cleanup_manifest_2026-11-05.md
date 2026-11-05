# 清理清单 — 2026-11-05

- 范围: D:\VM_Share\CoDefenderC3_v9\CoDefenderC3
- 安全网: D:\VM_Share\CoDefenderC3_v8\CoDefenderC3 (v8 完整副本, 可逐文件回拷)
- 注意: v9 的 git 仓库无任何提交 (unborn HEAD), 删除不可用 git 恢复

## A. 项目根一次性调试探针/日志 (20)
- _probe_batch_gap.log
- _probe_csv_flush.py
- _probe_csv_update.py
- _probe_flush.log
- _probe_fuzzy_gap.log
- _probe_fuzzy_gap.py
- _probe_fuzzy_gap2.log
- _probe_fuzzy_gap2.py
- _probe_hashbase_update.py
- _probe_missing.log
- _probe_missing.py
- _probe_pure_model.py
- _probe_retired_cap.py
- _probe_sig_update.py
- _probe_space_mgmt.py
- _probe_tlsh_import.py
- _probe_verify_vt.log
- _probe_verify_vt.py
- _probe_verify_vt2.log
- _probe_verify_vt2.py

## B. 临时目录 (4)
- .tmp_probe_flush/  (31 MB)
- .tmp_probe_retired/ (76 MB)
- .tmp_verify_vt/
- tmp7og7gucz_x/

## C. 死代码/重复副本 (9)
- feature_extraction/extract_feature111.py   <- extract_feature.py 的分叉副本, 迁移时必漏改
- engine/_fix_import.py, engine/_patch_app.py, engine/_patch_v2.py, engine/_patch_v3.py
- scaner/_probe_engine_tlsh.py, scaner/_probe_find_db_hit_sample.py, scaner/_probe_ssdeep_conv.py, scaner/_probe_tlsh_wire.py

## D. BN/bndb 专属探针 (8, SMDA 迁移后作废)
- train/_probe_bn_available.py, _probe_bn_de_e2e.py, _probe_bn_license.py, _probe_bn_license2.py
- train/_probe_bn_perfile.py, _probe_bn_pipeline_path.py
- train/_probe_bndb_fail.py, _probe_bndb_slow_retry.py

## E. 训练日志产物 (10, 保留 build_minimal_dataset.log —— docs 引用)
- train/logs/ 其余 10 个 .log

## F. Docker 构建残留
- .docker_build/signatures.old-1791890675/ (1008 MB)
- .docker_build/signatures.old-1791890842/ (1008 MB)
- .docker_build/signatures.old-1791961898/ (1008 MB)
(保留 .docker_build/signatures/ + staging_run.json —— 镜像构建缓存层)

## G. 工作区根 (2) + 全部 __pycache__
- _ali_cpu.html, _probe.html

## 文档同步修改
- train/README.md: 删除 7 行表格 + 8 行命令 (指向已删文件)
- train/_probe_de_coverage.py: 去掉对已删 _probe_bndb_fail.py 的引用

## 保留 (有引用 / 是回归断言 / 仍需使用)
- _probe_env_profile.py (41 断言), _probe_runtime_cfg.py (20 断言) —— README 记载的回归探针
- train/_probe_link_place.py (7 断言), train/_probe_de_coverage.py, train/_fix_de_gap.py
- feature_extraction/_bndb_worker.py —— 被 extract_feature.py:540 生产路径调用
- train/apply_bn_optimizations.py, benchmark_bn_optimization.py —— Phase 6 再废弃
- .feature_cache/, signatures/, runs/, experiments/, _tools/
