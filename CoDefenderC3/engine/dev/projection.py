"""Trim redundant diagnostics at the development HTTP boundary only.

Keep the shared inference evidence and the main Web contract untouched. Hash
hits, model results and directory failures all pass through the same boundary.
"""
from typing import Any, Dict


def project_single(result: Dict[str, Any]) -> Dict[str, Any]:
    """Return a response copy without the three redundant model fields."""
    out = dict(result)
    scan_result = result.get("ScanResult")
    if isinstance(scan_result, dict):
        scan_result = dict(scan_result)
        scan_result.pop("PerModelPreds", None)
        scan_result.pop("PerModelDetails", None)
        model_stats = scan_result.get("ModelStats")
        if isinstance(model_stats, dict):
            model_stats = dict(model_stats)
            model_stats.pop("AggregatedModels", None)
            scan_result["ModelStats"] = model_stats
        out["ScanResult"] = scan_result
    return out


def project_directory(response: Dict[str, Any]) -> Dict[str, Any]:
    """Preserve directory counters/timing and trim each individual result."""
    out = dict(response)
    if isinstance(response.get("Results"), list):
        out["Results"] = [project_single(result) for result in response["Results"]]
    return out
