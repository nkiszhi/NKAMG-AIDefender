"""
engine/naming — VirusName 命名与恶意度分档
==========================================
生产档命名规则（对外契约）:
  SHA256 / MD5 / imphash / authentihash 命中 → "Malicious"
  TLSH / SSDeep 命中                       → "Suspicious"
  ML 判定恶意, 按聚合分档              → "Generic.ML.{Low, Medium, High}"
  ML 判定良性                          → "Benign"

分档阈值来自 config.ML_TIER_*，仅用于历史展示档位，不是新策略的校准保证。
显式传入 is_malicious 时，良恶性名称服从共享策略，不能按 0.5 重新判定。
新权重、阈值或校准器仍需独立验证展示档位，不能声称已重新标定。
"""
import math
from typing import Optional

import config


# 档位常量（对外字符串的一部分，不要随意改）
TIER_LOW = "Low"
TIER_MEDIUM = "Medium"
TIER_HIGH = "High"

# 哈希命中的展示标签；不改变 Status / IsMalicious / Score。
NAME_HASH_HIT = "Malicious"
NAME_SUSPICIOUS_HASH_HIT = "Suspicious"
# ML 判定良性的固定标签
NAME_BENIGN = "Benign"


def tier_of(score: float, *, is_malicious: Optional[bool] = None) -> Optional[str]:
    """按聚合分返回恶意度档位。

    Returns:
        "Low" / "Medium" / "High" —— 恶意档（IsMalicious=True）
        None —— 良性（IsMalicious=False，VirusName="Benign"）
    """
    if not math.isfinite(score):
        raise ValueError("non_finite_model_scores")
    if is_malicious is not None and type(is_malicious) is not bool:
        raise ValueError("explicit boolean decision required")
    # Fixed policies can use a threshold other than .5. Naming must follow
    # their binary decision; the remaining tiers are display-only.
    if is_malicious is False or (is_malicious is None and score <= config.ML_TIER_BENIGN_MAX):
        return None
    if score < config.ML_TIER_LOW_MAX:
        return TIER_LOW
    if score < config.ML_TIER_MEDIUM_MAX:
        return TIER_MEDIUM
    return TIER_HIGH


def name_for_ml(score: float, *, is_malicious: Optional[bool] = None) -> str:
    """ML 路径的 VirusName: Benign / Generic.ML.Low|Medium|High。"""
    tier = tier_of(score, is_malicious=is_malicious)
    if tier is None:
        return NAME_BENIGN
    return "Generic.ML.%s" % tier


def name_for_hash_hit(source: Optional[str] = None,
                      fuzzy_type: Optional[str] = None) -> str:
    """Name the actual matched hash, not the associated sample SHA256.

    Only TLSH/SSDeep matches from the fuzzy database change to Suspicious.
    Exact SHA256/MD5, other fuzzy types and legacy no-argument calls retain
    Malicious; numeric decisions and model naming are unaffected.
    """
    source = str(source or "").strip().lower()
    fuzzy_type = str(fuzzy_type or "").strip().lower()
    if source in {"fuzzy_db", "fuzzy"} and fuzzy_type in {"tlsh", "ssdeep"}:
        return NAME_SUSPICIOUS_HASH_HIT
    return NAME_HASH_HIT
