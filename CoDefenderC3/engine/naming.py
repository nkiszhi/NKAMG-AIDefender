"""
engine/naming — VirusName 命名与恶意度分档
==========================================
生产档命名规则（对外契约）:
  哈希库命中 (sha256/md5/fuzzy/tlsh 任一级) → "Malicious"
  ML 判定恶意, 按聚合分档              → "Generic.ML.{Low, Medium, High}"
  ML 判定良性                          → "Benign"

分档阈值来自 config.ML_TIER_*（阶段 A 口径 = 现有线上等权聚合分）。
⚠️ 阶段 A 未切换加权聚合 —— 这三个阈值是按「当前等权均值」定的；
   切到 AUC 加权聚合 (阶段 B) 后必须用留出月重新标定，否则档位全乱。
"""
from typing import Optional

import config


# 档位常量（对外字符串的一部分，不要随意改）
TIER_LOW = "Low"
TIER_MEDIUM = "Medium"
TIER_HIGH = "High"

# 哈希命中的固定标签
NAME_HASH_HIT = "Malicious"
# ML 判定良性的固定标签
NAME_BENIGN = "Benign"


def tier_of(score: float) -> Optional[str]:
    """按聚合分返回恶意度档位。

    Returns:
        "Low" / "Medium" / "High" —— 恶意档（IsMalicious=True）
        None —— 良性（IsMalicious=False，VirusName="Benign"）
    """
    if score < config.ML_TIER_BENIGN_MAX:
        return None
    if score < config.ML_TIER_LOW_MAX:
        return TIER_LOW
    if score < config.ML_TIER_MEDIUM_MAX:
        return TIER_MEDIUM
    return TIER_HIGH


def name_for_ml(score: float) -> str:
    """ML 路径的 VirusName: Benign / Generic.ML.Low|Medium|High。"""
    tier = tier_of(score)
    if tier is None:
        return NAME_BENIGN
    return "Generic.ML.%s" % tier


def name_for_hash_hit() -> str:
    """哈希库命中路径的 VirusName（固定 "Malicious"）。"""
    return NAME_HASH_HIT
