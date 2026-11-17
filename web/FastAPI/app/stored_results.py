"""Read saved model JSON without fabricating scores, votes or completed results."""
import json
import math
from typing import Any

MALICIOUS_LEVELS = {'Generic.ML.Low', 'Generic.ML.Medium', 'Generic.ML.High'}
COLLECTION_STATES = {'pending', 'running', 'completed', 'failed', 'partial', 'cancelled'}


def _decode(raw: Any):
    if raw is None or raw == '':
        return None
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > 32768:
            return {'status': 'invalid'}
        try: raw = raw.decode('utf8')
        except UnicodeError: return {'status': 'invalid'}
    if isinstance(raw, str):
        if len(raw) > 32768:
            return {'status': 'invalid'}
        try: raw = json.loads(raw)
        except (ValueError, RecursionError): return {'status': 'invalid'}
    if raw is None or raw == {} or raw == []:
        return None
    if isinstance(raw, str):
        return {'result': raw}
    return raw if isinstance(raw, dict) else {'status': 'invalid'}


def _score(raw):
    if isinstance(raw, bool):
        return None
    try: value = float(raw)
    except (ValueError, TypeError, OverflowError): return None
    return value if math.isfinite(value) and 0 <= value <= 1 else None


def _entry(raw, *, ensemble=False):
    item = _decode(raw)
    if item is None:
        return None
    label = item.get('display_result') or item.get('result')
    label = label if isinstance(label, str) else None
    canonical = 'Malicious' if label in MALICIOUS_LEVELS else label
    declared = item.get('result')
    # A saved score alone does not determine a model's threshold or verdict.
    valid = canonical in ('Malicious', 'Benign') and (ensemble or label not in MALICIOUS_LEVELS)
    if declared in ('Malicious', 'Benign') and valid and declared != canonical:
        valid = False
    reason = item.get('reason')
    reason = reason[:500] if isinstance(reason, str) else ''
    result = canonical if valid else ('检测失败' if item.get('status') in ('failed', 'error', 'timeout') else '未取得有效结果')
    out = {'result': result, 'probability': _score(item.get('probability')), 'reason': reason}
    if ensemble:
        out['source'] = 'stored'
        if valid: out['display_result'] = label
        for name in ('ok_models', 'total_models', 'excluded_models'):
            value = item.get(name)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 33:
                out[name] = value
    return out


def saved_model_payload(record, model_names):
    """Old-library and unknown records return no new fields for compatibility."""
    if not record or record.get('_source_db') != 'AIDefender_PE':
        return {}
    results = {}
    for name in model_names:
        entry = _entry(record.get(name))
        if entry is not None:
            results[name] = entry
    model_count = len(results)
    valid_count = sum(r['result'] in ('Malicious', 'Benign') for r in results.values())
    ensemble = _entry(record.get('codefender_result'), ensemble=True)
    if ensemble is not None:
        results['集成结果'] = ensemble
    state = record.get('detection_status')
    summary = {
        'available': bool(results), 'model_count': model_count, 'valid_model_count': valid_count,
        'unavailable_model_count': model_count - valid_count,
        'missing_model_count': len(model_names) - model_count, 'total_models': len(model_names),
        'collection_status': state if isinstance(state, str) and state in COLLECTION_STATES else 'unknown',
        'codefender_available': bool(ensemble and ensemble['result'] in ('Malicious', 'Benign')),
    }
    return {'stored_model_report': summary, 'exe_result': results, 'results': results}
