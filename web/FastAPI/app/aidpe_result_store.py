"""Durable result outbox and guarded writes to the 27 AIDefender_PE primary."""
import json
import hashlib
import logging
import re
import sqlite3
import time
import os
import shutil
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .codefender_client import DEFAULT_MODEL_NAMES

logger = logging.getLogger("aidefender.aidpe_result_store")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TABLE_RE = re.compile(r"^sample_[0-9a-f]{2}$")


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str) if value is not None else None


def _models_payload(result):
    models = result.get("exe_result") or result.get("results") or {}
    if not isinstance(models, dict):
        return {}
    return {name: models[name] for name in DEFAULT_MODEL_NAMES if name in models}


def _ensemble_payload(result):
    models = result.get("exe_result") or result.get("results") or {}
    ensemble = models.get("集成结果") if isinstance(models, dict) else None
    return ensemble if isinstance(ensemble, dict) else None


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sample_category(result):
    category = (result or {}).get("sample_category")
    if category in ("模型判断恶意", "模型判断非恶意", "检查失败"):
        return category
    ensemble = _ensemble_payload(result or {})
    label = (ensemble or {}).get("display_result") or (ensemble or {}).get("result")
    if label == "Benign":
        return "模型判断非恶意"
    if label == "Malicious" or (isinstance(label, str) and label.startswith("Generic.ML.")):
        return "模型判断恶意"
    return "检查失败"


def archive_detected_sample(file_path, sample_root, sha256, result=None):
    """Move an uploaded entity to its outcome directory after verifying its SHA256."""
    source = Path(file_path)
    if not source.is_file() or not SHA256_RE.fullmatch((sha256 or "").lower()):
        raise ValueError("Uploaded sample or SHA256 is invalid")
    if sha256_file(source) != sha256.lower():
        raise ValueError("Uploaded sample SHA256 mismatch")
    root = Path(sample_root).resolve()
    folder = _sample_category(result)
    destination_dir = root / folder
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / f"{sha256.lower()}.sample"
    if destination.exists():
        existing = sha256_file(destination)
        if existing != sha256.lower():
            raise FileExistsError("Archive destination already contains different content")
        source.unlink(missing_ok=True)
        return destination
    temp = destination.with_name(destination.name + f".part-{os.getpid()}")
    try:
        os.replace(source, temp)
    except OSError:
        with source.open("rb") as incoming, temp.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
    os.replace(temp, destination)
    source.unlink(missing_ok=True)
    return destination


class ResultOutbox:
    """SQLite is the durable source until the primary write is read back from TXY."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("""CREATE TABLE IF NOT EXISTS aidpe_result_outbox (
                sha256 TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL DEFAULT 0,
                lease_at REAL,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""")
            connection.execute("CREATE INDEX IF NOT EXISTS aidpe_outbox_due ON aidpe_result_outbox(state,next_attempt)")
            connection.execute("""CREATE TABLE IF NOT EXISTS aidpe_sample_archive_queue (
                sha256 TEXT PRIMARY KEY,
                source_path TEXT NOT NULL,
                category TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL DEFAULT 0,
                last_error TEXT,
                updated_at TEXT NOT NULL
            )""")
            connection.execute("CREATE INDEX IF NOT EXISTS aidpe_archive_due ON aidpe_sample_archive_queue(next_attempt)")
            connection.commit()

    def enqueue_sample_archive(self, source_path, sha256, result):
        sha256 = str(sha256 or "").lower()
        if not SHA256_RE.fullmatch(sha256):
            return False
        source = Path(source_path).resolve()
        category = _sample_category(result)
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.execute("""INSERT INTO aidpe_sample_archive_queue
                (sha256,source_path,category,attempts,next_attempt,last_error,updated_at)
                VALUES(?,?,?,0,0,NULL,?) ON CONFLICT(sha256) DO UPDATE SET
                source_path=excluded.source_path,category=excluded.category,next_attempt=0,
                last_error=NULL,updated_at=excluded.updated_at""",
                (sha256, str(source), category, datetime.now(timezone.utc).isoformat()))
            connection.commit()
        return True

    def claim_sample_archives(self, limit=16):
        now = time.time()
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute("SELECT * FROM aidpe_sample_archive_queue WHERE next_attempt<=? "
                                      "ORDER BY next_attempt LIMIT ?", (now, limit)).fetchall()
            connection.execute("UPDATE aidpe_sample_archive_queue SET next_attempt=? WHERE sha256 IN "
                               "(SELECT sha256 FROM aidpe_sample_archive_queue WHERE next_attempt<=? "
                               "ORDER BY next_attempt LIMIT ?)", (now + 30, now, limit))
            connection.commit()
            return [dict(row) for row in rows]

    def complete_sample_archive(self, sha256):
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.execute("DELETE FROM aidpe_sample_archive_queue WHERE sha256=?", (sha256,))
            connection.commit()

    def retry_sample_archive(self, sha256, error):
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            row = connection.execute("SELECT attempts FROM aidpe_sample_archive_queue WHERE sha256=?", (sha256,)).fetchone()
            if row:
                delay = min(300, 30 * (2 ** min(row[0], 4)))
                connection.execute("UPDATE aidpe_sample_archive_queue SET attempts=attempts+1,next_attempt=? "
                                   " ,last_error=?,updated_at=? WHERE sha256=?",
                                   (time.time() + delay, error[:240], datetime.now(timezone.utc).isoformat(), sha256))
            connection.commit()

    def pending_sample_archive_paths(self):
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            rows = connection.execute("SELECT source_path FROM aidpe_sample_archive_queue").fetchall()
        return {str(Path(row[0]).resolve()) for row in rows}

    def enqueue(self, result, model_version):
        sha256 = str(result.get("sha256") or "").lower()
        if not SHA256_RE.fullmatch(sha256) or not result.get("is_pe"):
            return False
        status = result.get("detection_status") or "completed"
        uploaded_at = result.get("uploaded_at")
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            existing = connection.execute("SELECT payload_json FROM aidpe_result_outbox WHERE sha256=?", (sha256,)).fetchone()
        if existing:
            try:
                uploaded_at = uploaded_at or json.loads(existing[0]).get("uploaded_at")
            except (TypeError, ValueError):
                pass
        payload = {
            "sha256": sha256,
            "source": "web_upload",
            "model_version": model_version,
            "uploaded_at": uploaded_at or datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds"),
            "detection_status": status,
            "models": _models_payload(result),
            "codefender_result": _ensemble_payload(result),
        }
        now = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.execute("""INSERT INTO aidpe_result_outbox
                (sha256,payload_json,state,attempts,next_attempt,lease_at,last_error,created_at,updated_at)
                VALUES(?,?,'pending',0,0,NULL,NULL,?,?)
                ON CONFLICT(sha256) DO UPDATE SET payload_json=excluded.payload_json,
                    state='pending',next_attempt=0,lease_at=NULL,last_error=NULL,updated_at=excluded.updated_at""",
                (sha256, _json(payload), now, now))
            connection.commit()
        return True

    def claim_due(self):
        now = time.time()
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("""SELECT * FROM aidpe_result_outbox
                WHERE (state='pending' AND next_attempt<=?) OR (state='writing' AND lease_at<?)
                ORDER BY created_at LIMIT 1""", (now, now - 300)).fetchone()
            if not row:
                connection.commit()
                return None
            connection.execute("UPDATE aidpe_result_outbox SET state='writing',lease_at=?,updated_at=? WHERE sha256=?",
                               (now, datetime.now(timezone.utc).isoformat(), row['sha256']))
            connection.commit()
            return {"sha256": row["sha256"], "payload": json.loads(row["payload_json"]), "attempts": row["attempts"]}

    def mark_replicated(self, sha256):
        self._update(sha256, "replicated", None, None)

    def mark_retry(self, sha256, attempts, error):
        delay = min(300, 5 * (2 ** min(max(attempts, 0), 6)))
        self._update(sha256, "pending", time.time() + delay, error[:240])

    def _update(self, sha256, state, next_attempt, error):
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.execute("""UPDATE aidpe_result_outbox SET state=?,attempts=attempts+1,
                next_attempt=COALESCE(?,next_attempt),lease_at=NULL,last_error=?,updated_at=? WHERE sha256=?""",
                (state, next_attempt, error, datetime.now(timezone.utc).isoformat(), sha256))
            connection.commit()

    def due_count(self):
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            return connection.execute("SELECT COUNT(*) FROM aidpe_result_outbox WHERE state!='replicated'").fetchone()[0]


class PrimaryResultWriter:
    def __init__(self, settings):
        self.settings = settings

    @property
    def configured(self):
        return bool(self.settings.aidpe_primary_host and self.settings.aidpe_primary_user
                    and self.settings.aidpe_primary_passwd)

    def write(self, payload):
        sha256 = payload.get("sha256", "").lower()
        table = f"sample_{sha256[:2]}"
        if not SHA256_RE.fullmatch(sha256) or not TABLE_RE.fullmatch(table):
            raise ValueError("Invalid AIDefender_PE key")
        if not self.configured:
            raise RuntimeError("AIDefender_PE primary writer is not configured")

        import pymysql
        names = ["sha256", *DEFAULT_MODEL_NAMES, "codefender_result", "detection_status", "source", "model_version", "uploaded_at"]
        values = [sha256]
        values.extend(_json(payload.get("models", {}).get(name)) for name in DEFAULT_MODEL_NAMES)
        values.extend([
            _json(payload.get("codefender_result")),
            payload.get("detection_status") or "completed",
            "web_upload",
            payload.get("model_version") or "deployment-v1",
            payload.get("uploaded_at"),
        ])
        columns = ",".join(f"`{name}`" for name in names)
        placeholders = ",".join(["%s"] * len(names))
        updates = []
        for name in DEFAULT_MODEL_NAMES + ["codefender_result"]:
            updates.append(
                f"`{name}`=IF(VALUES(`detection_status`)='completed' AND "
                f"NOT (`model_version` <=> VALUES(`model_version`)),VALUES(`{name}`),"
                f"COALESCE(VALUES(`{name}`),`{name}`))"
            )
        updates.extend([
            "`source`=IF(`source`='malicious_pe','malicious_pe',VALUES(`source`))",
            "`model_version`=IF(VALUES(`detection_status`)='completed' OR (`detection_status`='pending' AND VALUES(`detection_status`)='failed'),VALUES(`model_version`),`model_version`)",
            "`uploaded_at`=COALESCE(`uploaded_at`,VALUES(`uploaded_at`))",
            "`detection_status`=IF(VALUES(`detection_status`)='completed' OR (`detection_status`='pending' AND VALUES(`detection_status`)='failed'),VALUES(`detection_status`),`detection_status`)",
        ])
        sql = (f"INSERT INTO `{self.settings.aidpe_db}`.`{table}` ({columns}) VALUES ({placeholders}) "
               f"ON DUPLICATE KEY UPDATE {','.join(updates)}")
        connection = pymysql.connect(
            host=self.settings.aidpe_primary_host,
            port=self.settings.aidpe_primary_port,
            user=self.settings.aidpe_primary_user,
            password=self.settings.aidpe_primary_passwd,
            database=self.settings.aidpe_db,
            charset="utf8mb4",
            connect_timeout=5,
            read_timeout=10,
            write_timeout=10,
            autocommit=True,
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(sql, values)
        finally:
            connection.close()

