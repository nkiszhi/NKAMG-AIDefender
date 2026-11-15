"""Bounded SQLite jobs; one Web process owns each task directory."""
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timedelta
from contextlib import contextmanager
from pathlib import Path
from app import detection_metrics


class QueueFull(Exception):
    pass


class ExpiredRequest(Exception):
    pass


class DetectionTaskStore:
    def __init__(self, path: Path, ttl_seconds: int):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = max(60, ttl_seconds)
        self._lock = threading.Lock()
        with self._connect() as connection:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('''CREATE TABLE IF NOT EXISTS detection_tasks (
                task_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                filename TEXT NOT NULL, file_path TEXT NOT NULL,
                result_json TEXT, error TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL)''')
            connection.execute('CREATE INDEX IF NOT EXISTS task_status ON detection_tasks(status,created_at)')
            columns = {row['name'] for row in connection.execute('PRAGMA table_info(detection_tasks)')}
            for name in ('client_seen_at', 'client_left_at', 'progress_json'):
                if name not in columns:
                    connection.execute(f'ALTER TABLE detection_tasks ADD COLUMN {name} TEXT')
            if 'request_source' not in columns:
                connection.execute("ALTER TABLE detection_tasks ADD COLUMN request_source TEXT NOT NULL DEFAULT 'web'")
            for name, definition in [('sha256', 'TEXT'), ('file_size', 'INTEGER NOT NULL DEFAULT 0'),
                                     ('error_code', 'TEXT'), ('retryable', 'INTEGER')]:
                if name not in columns:
                    connection.execute(f'ALTER TABLE detection_tasks ADD COLUMN {name} {definition}')
            connection.execute('''CREATE TABLE IF NOT EXISTS model_memory_failures (
                sha256 TEXT NOT NULL, revision TEXT NOT NULL, task_id TEXT NOT NULL,
                reason TEXT NOT NULL, created_at TEXT NOT NULL,
                PRIMARY KEY(sha256, revision))''')
            connection.execute('''CREATE TABLE IF NOT EXISTS model_node_cooldowns (
                endpoint TEXT PRIMARY KEY, generation_json TEXT NOT NULL, until_epoch REAL NOT NULL)''')
            connection.execute("UPDATE detection_tasks SET client_seen_at=created_at WHERE client_seen_at IS NULL")
            detection_metrics.initialize(connection)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def recover(self):
        # Call only after acquiring the process lease, never during import.
        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT task_id FROM detection_tasks WHERE status='running'").fetchall()
            for row in rows:
                connection.execute("UPDATE detection_tasks SET status='failed',error=?,error_code='MODEL_STATUS_UNKNOWN',retryable=0,updated_at=? WHERE task_id=?",
                                   ('Web 服务曾中断，无法确认模型是否完成；未自动重放样本。', datetime.now().isoformat(), row['task_id']))
                detection_metrics.finish(connection, row['task_id'], status='failed')
            return len(rows)

    def set_metadata(self, task_id, sha256, file_size):
        with self._lock, self._connect() as connection:
            connection.execute('UPDATE detection_tasks SET sha256=?,file_size=? WHERE task_id=?',
                               (sha256, file_size, task_id))

    def record_rejection(self, task_id, info, source, reason, code):
        now = datetime.now().isoformat()
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            changed = connection.execute('''INSERT OR IGNORE INTO detection_tasks
                (task_id,status,filename,file_path,created_at,updated_at,request_source,sha256,file_size,error,error_code,retryable)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                (task_id,'failed',info['filename'],'',now,now,source,info['sha256'],info['file_size'],reason,code,0))
            if changed.rowcount:
                detection_metrics.begin(connection, task_id, info['sha256'])
                detection_metrics.finish(connection, task_id, status='failed')
        return self.get(task_id)

    def create(self, task_id, filename, file_path, capacity, sha256=None, request_source='web', file_size=0):
        if request_source not in ('web', 'api'):
            raise ValueError('Invalid request source')
        now = datetime.now().isoformat(timespec='microseconds')
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            existing = connection.execute('SELECT * FROM detection_tasks WHERE task_id=?', (task_id,)).fetchone()
            if existing:
                return dict(existing)
            if request_source == 'api' and connection.execute('SELECT 1 FROM detection_metrics WHERE task_id=?', (task_id,)).fetchone():
                raise ExpiredRequest()
            count = connection.execute("SELECT COUNT(*) FROM detection_tasks WHERE status IN ('queued','running')").fetchone()[0]
            if count >= capacity:
                raise QueueFull()
            connection.execute('INSERT INTO detection_tasks(task_id,status,filename,file_path,created_at,updated_at,request_source) VALUES(?,?,?,?,?,?,?)',
                               (task_id, 'queued', filename, str(file_path), now, now, request_source))
            connection.execute('UPDATE detection_tasks SET client_seen_at=? WHERE task_id=?', (now, task_id))
            connection.execute('UPDATE detection_tasks SET sha256=?,file_size=? WHERE task_id=?',
                               (sha256, max(0, int(file_size)), task_id))
            detection_metrics.begin(connection, task_id, sha256)
            return dict(connection.execute('SELECT * FROM detection_tasks WHERE task_id=?', (task_id,)).fetchone())

    def get(self, task_id):
        with self._lock, self._connect() as connection:
            row = connection.execute('SELECT * FROM detection_tasks WHERE task_id=?', (task_id,)).fetchone()
            ahead = 0
            if row and row['status'] == 'queued':
                ahead = connection.execute(
                    "SELECT COUNT(*) FROM detection_tasks WHERE status='running' OR (status='queued' AND rowid < (SELECT rowid FROM detection_tasks WHERE task_id=?))",
                    (task_id,),
                ).fetchone()[0]
        if not row:
            return None
        result = dict(row)
        if result['status'] == 'queued':
            result['tasks_ahead'] = ahead
            result['queue_position'] = ahead + 1
        if result['status'] in {'completed', 'failed', 'cancelled'}:
            if (datetime.now() - datetime.fromisoformat(result['updated_at'])).total_seconds() > self.ttl_seconds:
                return None
        return result

    def heartbeat(self, task_id):
        with self._lock, self._connect() as connection:
            connection.execute("UPDATE detection_tasks SET client_seen_at=?,client_left_at=NULL WHERE task_id=?",
                               (datetime.now().isoformat(), task_id))

    def leave(self, task_id):
        with self._lock, self._connect() as connection:
            connection.execute("UPDATE detection_tasks SET client_left_at=? WHERE task_id=? AND request_source='web' AND status IN ('queued','running')",
                               (datetime.now().isoformat(), task_id))

    def cancel_abandoned(self, heartbeat_seconds=120, leave_seconds=30):
        now = datetime.now()
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            rows = connection.execute("""SELECT task_id,file_path FROM detection_tasks WHERE status='queued' AND request_source='web' AND
                ((client_left_at IS NOT NULL AND client_left_at<?) OR
                 (client_left_at IS NULL AND client_seen_at<?))""",
                ((now-timedelta(seconds=leave_seconds)).isoformat(),
                 (now-timedelta(seconds=heartbeat_seconds)).isoformat())).fetchall()
            for row in rows:
                connection.execute("UPDATE detection_tasks SET status='cancelled',error=?,updated_at=? WHERE task_id=? AND status='queued'",
                                   ('页面已离开，排队任务已取消', now.isoformat(), row['task_id']))
                detection_metrics.finish(connection, row['task_id'], status='cancelled')
            return [row['file_path'] for row in rows]

    def update_progress(self, task_id, progress):
        with self._lock, self._connect() as connection:
            connection.execute("UPDATE detection_tasks SET progress_json=? WHERE task_id=? AND status='running'",
                               (json.dumps(progress, ensure_ascii=False), task_id))

    def claim_next(self, max_concurrent=2, large_threshold=100 * 1024 * 1024):
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            running = connection.execute("SELECT file_size,sha256 FROM detection_tasks WHERE status='running'").fetchall()
            if len(running) >= max_concurrent or any(r['file_size'] >= large_threshold for r in running):
                return None
            row = connection.execute("SELECT * FROM detection_tasks WHERE status='queued' AND (request_source='api' OR (client_left_at IS NULL AND client_seen_at>=?)) ORDER BY rowid LIMIT 1",
                                     ((datetime.now()-timedelta(seconds=120)).isoformat(),)).fetchone()
            if not row:
                return None
            # FIFO head blocks new small jobs, so a large sample cannot starve.
            if running and (row['file_size'] >= large_threshold or
                            (row['sha256'] and any(r['sha256'] == row['sha256'] for r in running))):
                return None
            connection.execute("UPDATE detection_tasks SET status='running',updated_at=? WHERE task_id=?",
                               (datetime.now().isoformat(), row['task_id']))
            return dict(row)

    def set_status(self, task_id, status, error=None, error_code=None, retryable=None):
        with self._lock, self._connect() as connection:
            changed = connection.execute('UPDATE detection_tasks SET status=?,error=?,updated_at=? WHERE task_id=?',
                                         (status, error, datetime.now().isoformat(), task_id))
            if changed.rowcount and status in ('failed', 'cancelled'):
                connection.execute('UPDATE detection_tasks SET error_code=?,retryable=? WHERE task_id=?',
                                   (error_code, None if retryable is None else int(retryable), task_id))
                detection_metrics.finish(connection, task_id, status=status)

    def remember_memory_failure(self, task_id, revision, reason):
        with self._lock, self._connect() as connection:
            row = connection.execute('SELECT sha256 FROM detection_tasks WHERE task_id=?', (task_id,)).fetchone()
            if row and row['sha256']:
                connection.execute('''INSERT OR REPLACE INTO model_memory_failures
                    (sha256,revision,task_id,reason,created_at) VALUES(?,?,?,?,?)''',
                    (row['sha256'], revision, task_id, reason, datetime.now().isoformat()))

    def memory_failure(self, sha256, revision):
        if not sha256:
            return None
        with self._lock, self._connect() as connection:
            row = connection.execute('SELECT * FROM model_memory_failures WHERE sha256=? AND revision=?',
                                     (sha256, revision)).fetchone()
            return dict(row) if row else None

    def forget_memory_failure(self, sha256, revision):
        with self._lock, self._connect() as connection:
            return connection.execute('DELETE FROM model_memory_failures WHERE sha256=? AND revision=?',
                                      (sha256, revision)).rowcount

    def save_cooldown(self, endpoint, generation, until_epoch):
        with self._lock, self._connect() as connection:
            connection.execute('INSERT OR REPLACE INTO model_node_cooldowns VALUES(?,?,?)',
                               (endpoint, json.dumps(generation), until_epoch))

    def load_cooldowns(self):
        with self._lock, self._connect() as connection:
            return [dict(row) for row in connection.execute('SELECT * FROM model_node_cooldowns')]

    def clear_cooldown(self, endpoint):
        with self._lock, self._connect() as connection:
            connection.execute('DELETE FROM model_node_cooldowns WHERE endpoint=?', (endpoint,))

    def scheduling_status(self, large_threshold):
        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT file_size FROM detection_tasks WHERE status='running'").fetchall()
        return {'active_tasks': len(rows), 'large_sample_running': any(r['file_size'] >= large_threshold for r in rows),
                'large_sample_bytes': large_threshold}

    def expire_waiting(self, seconds):
        cutoff = (datetime.now() - timedelta(seconds=seconds)).isoformat()
        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT task_id,file_path FROM detection_tasks WHERE status='queued' AND created_at<?",
                                      (cutoff,)).fetchall()
            for row in rows:
                connection.execute("UPDATE detection_tasks SET status='failed',error=?,error_code='QUEUE_TIMEOUT',retryable=1,updated_at=? WHERE task_id=?",
                                   ('等待模型服务超过时限，本次任务未完成。', datetime.now().isoformat(), row['task_id']))
                detection_metrics.finish(connection, row['task_id'], status='failed')
            return [r['file_path'] for r in rows]

    def complete(self, task_id, result):
        with self._lock, self._connect() as connection:
            changed = connection.execute("UPDATE detection_tasks SET status='completed',result_json=?,error=NULL,updated_at=? WHERE task_id=?",
                                         (json.dumps(result, ensure_ascii=False, default=str), datetime.now().isoformat(), task_id))
            if changed.rowcount:
                detection_metrics.finish(connection, task_id, result)

    def record_direct_result(self, task_id, result):
        with self._lock, self._connect() as connection:
            detection_metrics.finish(connection, task_id, result)

    def detection_summary(self):
        with self._lock, self._connect() as connection:
            return detection_metrics.summary(connection)

    def begin_hash_query(self, hash_type, value):
        with self._lock, self._connect() as connection:
            return detection_metrics.begin_hash_query(connection, hash_type, value)

    def finish_hash_query(self, query_id, outcome, sample_sha256=None):
        with self._lock, self._connect() as connection:
            detection_metrics.finish_hash_query(connection, query_id, outcome, sample_sha256)

    def record_hash_query(self, outcome, hash_type=None, value=None, sample_sha256=None):
        with self._lock, self._connect() as connection:
            query_id = detection_metrics.begin_hash_query(connection, hash_type, value)
            detection_metrics.finish_hash_query(connection, query_id, outcome, sample_sha256)

    def cleanup(self):
        cutoff = (datetime.now() - timedelta(seconds=self.ttl_seconds)).isoformat()
        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT file_path FROM detection_tasks WHERE status IN ('completed','failed','cancelled') AND updated_at<?", (cutoff,)).fetchall()
            connection.execute("DELETE FROM detection_tasks WHERE status IN ('completed','failed','cancelled') AND updated_at<?", (cutoff,))
        return [row['file_path'] for row in rows if row['file_path']]

    def orphan_paths(self, upload_dir, cutoff_timestamp):
        # Only UUID-owned uploads; never delete active tasks or user files.
        with self._lock, self._connect() as connection:
            active = {str(Path(row['file_path']).resolve()) for row in connection.execute(
                "SELECT file_path FROM detection_tasks WHERE status IN ('queued','running')")}
            paths = []
            for path in Path(upload_dir).iterdir():
                if not re.fullmatch(r'(?:[0-9a-f]{64}-[0-9a-f]{32}|\.upload-[0-9]+-[0-9a-f]{32})', path.name):
                    continue
                if path.is_symlink() or str(path.resolve()) in active:
                    continue
                try:
                    if path.is_file() and path.stat().st_mtime < cutoff_timestamp:
                        paths.append(path)
                except FileNotFoundError:
                    pass
            return paths

    @staticmethod
    def public_status(row):
        response = {key: row[key] for key in ('task_id','status','filename','created_at','updated_at')}
        if row['status'] == 'queued':
            response.update({key: row[key] for key in ('tasks_ahead', 'queue_position') if key in row})
        if row['status'] == 'completed' and row.get('result_json'):
            response['result'] = json.loads(row['result_json'])
        if row['status'] == 'failed':
            response['error'] = row.get('error') or '检测任务失败'
            if row.get('error_code'):
                response['error_code'] = row['error_code']
            if row.get('retryable') is not None:
                response['retryable'] = bool(row['retryable'])
        response['file_size'] = row.get('file_size', 0)
        if row['status'] == 'cancelled':
            response['error'] = row.get('error') or '排队任务已取消'
        if row.get('progress_json') and row['status'] in ('running', 'failed'):
            response['progress'] = json.loads(row['progress_json'])
        return response


class ProcessLease:
    """Prevent duplicate uvicorn processes from recovering each other's jobs."""
    def __init__(self, path):
        self.path, self.handle = Path(path), None

    def acquire(self):
        self.handle = self.path.open('a+b')
        self.handle.seek(0)
        self.handle.write(b'0')
        self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            self.handle = None
            raise RuntimeError('同一任务目录只能运行一个 Web 后端进程；不要使用 --workers 或 --reload')

    def release(self):
        if self.handle:
            if os.name == 'nt':
                import msvcrt
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None
