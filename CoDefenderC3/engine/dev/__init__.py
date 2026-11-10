"""
engine/dev — 开发接口（基于改造前快照）
==========================================
本目录保存「生产精简改造」之前的原始实现，用途只有三个：
  1) 改造前后 diff 的基准
  2) 新旧口径 A/B 双跑（同一批样本分别打 engine.app 与 engine.dev.app）
  3) 出问题时的快速对照/回退定位

⚠️ 本目录以原始快照为基础；2026-11-09 按开发接口需求统一了单文件/目录聚合。
   本次修复仅作用于 dev 入口，规则见 docs/DEV_PREDICTION_AGGREGATION.md。
   真正的回滚底座是 git（git diff / git checkout），本目录的独有价值是
   「同一环境下新旧口径并排跑」。

入口: uvicorn engine.dev.app:app --host 0.0.0.0 --port 8000
   （与生产 engine.app:app 同端口时需错开）

目录内容:
  app.py             ← 基于改造前实现，单文件/目录共用聚合规则
  result_formatter.py ← 改造前的 engine/result_formatter.py（未改 virus_namer，import 无需改写）
"""
