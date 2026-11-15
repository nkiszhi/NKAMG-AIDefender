"""Read-only lifecycle evidence. Web never controls Docker containers."""
import json
from pathlib import Path
import time
from app.config import settings

MEMORY_MESSAGE = '样本分析所需内存超出限制，分析失败。请勿重复上传。'


class ModelTaskFailure(RuntimeError):
    def __init__(self, detail, *, code='MODEL_CONNECTION_LOST', retryable=False,
                 endpoint=None, started_at=None, container_id=None):
        super().__init__(detail)
        self.code, self.retryable = code, retryable
        self.endpoint, self.started_at, self.container_id = endpoint, started_at, container_id


def read_snapshot():
    path = getattr(settings, 'model_monitor_path', None)
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        age = time.time() - float(data['updated_at'])
        if not 0 <= age <= settings.model_monitor_stale_seconds or not isinstance(data['nodes'], dict):
            return None
        if not isinstance(data.get('memory_available_bytes'), int) or data['memory_available_bytes'] < 0:
            return None
        if any(not isinstance(node, dict) for node in data['nodes'].values()):
            return None
        return data
    except (OSError, ValueError, TypeError, KeyError):
        return None


def node_evidence(endpoint):
    return (read_snapshot() or {}).get('nodes', {}).get(endpoint, {})


def generation(node):
    return (node.get('id'), node.get('started_at'))


def admission_status():
    if not getattr(settings, 'model_monitor_path', None):
        return True, ''
    snapshot = read_snapshot()
    if snapshot is None:
        return False, '模型运行监测暂不可用，任务已排队等待'
    available = snapshot.get('memory_available_bytes')
    if isinstance(available, int) and available < settings.model_min_available_bytes:
        return False, '服务器可用内存不足，暂停派发新任务'
    if not any(snapshot['nodes'].get(url, {}).get('ready') for url in settings.codefender_api_bases):
        return False, '模型服务正在恢复，任务已排队等待'
    return True, ''


def confirmed_oom(error):
    if not isinstance(error, ModelTaskFailure) or not error.endpoint or error.started_at is None:
        return False
    for event in node_evidence(error.endpoint).get('events', []):
        if (isinstance(event, dict) and event.get('kind') == 'oom' and isinstance(event.get('time'), (int, float)) and
                event['time'] >= error.started_at and error.container_id and
                event.get('container_id') == error.container_id):
            return True
    return False
