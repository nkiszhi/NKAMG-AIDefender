"""
engine/projection — 生产档响应字段裁剪
=======================================
对外契约只保留业务必需的字段，其余一律去掉:

  /predict-single  → MD5, SHA256, IsMalicious,
                     ScanResult{VirusName, Packed{IsPacked, PackerName, IsArchive, ArchiveName}}
  /predict-directory → Summary{5 个计数},
                     Results[]{MD5, SHA256, FilePath, IsMalicious,
                               ScanResult{同上}, Error}

被裁掉的字段（不再对外暴露）: Score, Status, StatusLabel, CRC32, FileSize,
PerModelScores, PerModelPreds, DriftEvidence, SampleDriftType, AnomalyScore,
IsDriftCandidate, ModelStats, Source, HashMatch, Summary.Timing 等。

⚠️ 裁掉 Score 之后，下游无法自行复核或调档。分档阈值见配置文件
   config.ML_TIER_* 和合并实施记录；/model-info 仍保持 main 的原契约。
"""
from typing import Any, Dict, List, Optional


# Summary 保留的计数字段
SUMMARY_KEYS = (
    "TotalFiles",
    "ScannedFiles",
    "MaliciousCount",
    "BenignCount",
    "ErrorCount",
)


def _project_packed(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """裁剪 Packed 块，保留 4 个字段。"""
    packed = scan_result.get("Packed") or {}
    return {
        "IsPacked": bool(packed.get("IsPacked", False)),
        "PackerName": packed.get("PackerName", "") or "",
        "IsArchive": bool(packed.get("IsArchive", False)),
        "ArchiveName": packed.get("ArchiveName", "") or "",
    }


def project_scan_result(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """裁剪 ScanResult: 只留 VirusName + Packed。"""
    return {
        "VirusName": scan_result.get("VirusName", "") or "",
        "Packed": _project_packed(scan_result),
    }


def project_single(result: Dict[str, Any]) -> Dict[str, Any]:
    """裁剪 /predict-single 的响应体。"""
    out: Dict[str, Any] = {
        "MD5": result.get("MD5", "") or "",
        "SHA256": result.get("SHA256", "") or "",
        "IsMalicious": bool(result.get("IsMalicious", False)),
    }
    scan_result = result.get("ScanResult")
    if scan_result is not None:
        out["ScanResult"] = project_scan_result(scan_result)
    return out


def project_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """裁剪 /predict-directory Results[] 中的单条。

    成功条目带 ScanResult；失败条目 (Status=-1) 无 ScanResult，改带 Error。
    """
    out: Dict[str, Any] = {
        "MD5": item.get("MD5", "") or "",
        "SHA256": item.get("SHA256", "") or "",
        "FilePath": item.get("FilePath", "") or "",
        "IsMalicious": bool(item.get("IsMalicious", False)),
    }
    scan_result = item.get("ScanResult")
    if scan_result is not None:
        out["ScanResult"] = project_scan_result(scan_result)
    else:
        out["Error"] = item.get("Error", "") or ""
    return out


def project_directory(payload: Dict[str, Any]) -> Dict[str, Any]:
    """裁剪 /predict-directory 的响应体。"""
    summary = payload.get("Summary") or {}
    return {
        "Summary": {key: (summary.get("ErrorCount", 0) + summary.get("TimeoutCount", 0)
                          if key == "ErrorCount" else summary.get(key, 0))
                    for key in SUMMARY_KEYS},
        "Results": [project_item(r) for r in (payload.get("Results") or [])],
    }
