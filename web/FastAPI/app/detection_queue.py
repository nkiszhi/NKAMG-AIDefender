"""Bounded SQLite jobs; one Web process owns each task directory."""
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timedelta
from contextlib import contextmanager
from pathlib import Path


class QueueFull(Exception):
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
            connection.execute("UPDATE detection_tasks SET client_seen_at=created_at WHERE client_seen_at IS NULL")

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
            connection.execute("UPDATE detection_tasks SET status='queued',progress_json=NULL WHERE status='running'")

    def create(self, task_id, filename, file_path, capacity):
        now = datetime.now().isoformat(timespec='microseconds')
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            existing = connection.execute('SELECT * FROM detection_tasks WHERE task_id=?', (task_id,)).fetchone()
            if existing:
                return dict(existing)
            count = connection.execute("SELECT COUNT(*) FROM detection_tasks WHERE status IN ('queued','running')").fetchone()[0]
            if count >= capacity:
                raise QueueFull()
            connection.execute('INSERT INTO detection_tasks(task_id,status,filename,file_path,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                               (task_id, 'queued', filename, str(file_path), now, now))
            connection.execute('UPDATE detection_tasks SET client_seen_at=? WHERE task_id=?', (now, task_id))
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
            connection.execute("UPDATE detection_tasks SET client_left_at=? WHERE task_id=? AND status IN ('queued','running')",
                               (datetime.now().isoformat(), task_id))

    def cancel_abandoned(self, heartbeat_seconds=120, leave_seconds=30):
        now = datetime.now()
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            rows = connection.execute("""SELECT task_id,file_path FROM detection_tasks WHERE status='queued' AND
                ((client_left_at IS NOT NULL AND client_left_at<?) OR
                 (client_left_at IS NULL AND client_seen_at<?))""",
                ((now-timedelta(seconds=leave_seconds)).isoformat(),
                 (now-timedelta(seconds=heartbeat_seconds)).isoformat())).fetchall()
            for row in rows:
                connection.execute("UPDATE detection_tasks SET status='cancelled',error=?,updated_at=? WHERE task_id=? AND status='queued'",
                                   ('页面已离开，排队任务已取消', now.isoformat(), row['task_id']))
            return [row['file_path'] for row in rows]

    def update_progress(self, task_id, progress):
        with self._lock, self._connect() as connection:
            connection.execute("UPDATE detection_tasks SET progress_json=? WHERE task_id=? AND status='running'",
                               (json.dumps(progress, ensure_ascii=False), task_id))

    def claim_next(self):
        with self._lock, self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            row = connection.execute("SELECT * FROM detection_tasks WHERE status='queued' AND client_left_at IS NULL AND client_seen_at>=? ORDER BY rowid LIMIT 1",
                                     ((datetime.now()-timedelta(seconds=120)).isoformat(),)).fetchone()
            if not row:
                return None
            connection.execute("UPDATE detection_tasks SET status='running',updated_at=? WHERE task_id=?",
                               (datetime.now().isoformat(), row['task_id']))
            return dict(row)

    def set_status(self, task_id, status, error=None):
        with self._lock, self._connect() as connection:
            connection.execute('UPDATE detection_tasks SET status=?,error=?,updated_at=? WHERE task_id=?',
                               (status, error, datetime.now().isoformat(), task_id))

    def complete(self, task_id, result):
        with self._lock, self._connect() as connection:
            connection.execute("UPDATE detection_tasks SET status='completed',result_json=?,error=NULL,updated_at=? WHERE task_id=?",
                               (json.dumps(result, ensure_ascii=False, default=str), datetime.now().isoformat(), task_id))

    def cleanup(self):
        cutoff = (datetime.now() - timedelta(seconds=self.ttl_seconds)).isoformat()
        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT file_path FROM detection_tasks WHERE status IN ('completed','failed','cancelled') AND updated_at<?", (cutoff,)).fetchall()
            connection.execute("DELETE FROM detection_tasks WHERE status IN ('completed','failed','cancelled') AND updated_at<?", (cutoff,))
        return [row['file_path'] for row in rows]

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
