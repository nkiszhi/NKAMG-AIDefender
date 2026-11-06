"""Durable upload counters, independent of expiring task reports."""
from datetime import datetime, timedelta, timezone


def now_iso():
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds')


def initialize(connection):
    connection.execute('''CREATE TABLE IF NOT EXISTS detection_metrics (
        task_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, finished_at TEXT,
        status TEXT NOT NULL, sha256 TEXT, mode TEXT, verdict TEXT,
        partial_models INTEGER NOT NULL DEFAULT 0)''')
    connection.execute('CREATE INDEX IF NOT EXISTS metrics_finished ON detection_metrics(status,finished_at)')
    connection.execute('CREATE TABLE IF NOT EXISTS metrics_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    connection.execute("INSERT OR IGNORE INTO metrics_metadata VALUES ('started_at', ?)", (now_iso(),))
    connection.execute('''CREATE TABLE IF NOT EXISTS hash_query_metrics (
        id INTEGER PRIMARY KEY, queried_at TEXT NOT NULL, outcome TEXT NOT NULL)''')


def begin(connection, task_id, sha256=None):
    connection.execute('''INSERT OR IGNORE INTO detection_metrics
        (task_id,created_at,status,sha256) VALUES (?,?,'pending',?)''',
        (task_id, now_iso(), sha256))


def finish(connection, task_id, result=None, status='completed'):
    result = result or {}
    begin(connection, task_id, result.get('sha256'))
    mode = result.get('detection_mode')
    verdict = None
    partial = 0
    if status == 'completed':
        if mode == 'rejected':
            status = 'unsupported'
        elif mode == 'sample_database' and result.get('database_hit') is True:
            verdict = 'malicious'
        else:
            models = result.get('exe_result') or result.get('results') or {}
            label = (models.get('集成结果') or {}).get('result')
            verdict = {'Malicious': 'malicious', '恶意': 'malicious',
                       'Benign': 'benign', '安全': 'benign'}.get(label, 'inconclusive')
            partial = int(any(
                isinstance(value, dict) and value.get('result') not in ('Malicious', 'Benign', '恶意', '安全')
                for key, value in models.items() if key not in ('集成结果', '签名库预检')
            ))
    # One terminal outcome per request ID, even after report expiry or retries.
    connection.execute('''UPDATE detection_metrics SET finished_at=?,status=?,
        sha256=COALESCE(sha256,?),mode=?,verdict=?,partial_models=?
        WHERE task_id=? AND status='pending' ''',
        (now_iso(), status, result.get('sha256'), mode, verdict, partial, task_id))


def summary(connection):
    connection.execute('BEGIN')
    started_at = connection.execute("SELECT value FROM metrics_metadata WHERE key='started_at'").fetchone()[0]
    counts = {row['status']: row['n'] for row in connection.execute(
        'SELECT status,COUNT(*) AS n FROM detection_metrics GROUP BY status')}
    verdicts = {row['verdict']: row['n'] for row in connection.execute(
        "SELECT verdict,COUNT(*) AS n FROM detection_metrics WHERE status='completed' GROUP BY verdict")}
    modes = {row['mode']: row['n'] for row in connection.execute(
        "SELECT mode,COUNT(*) AS n FROM detection_metrics WHERE status='completed' GROUP BY mode")}
    unique = connection.execute("""SELECT COUNT(DISTINCT sha256) FROM detection_metrics
        WHERE status='completed' AND sha256 IS NOT NULL AND sha256<>'' """).fetchone()[0]
    partial = connection.execute("SELECT COUNT(*) FROM detection_metrics WHERE status='completed' AND partial_models=1").fetchone()[0]
    monthly = [dict(row) for row in connection.execute("""SELECT substr(finished_at,1,7) AS name,COUNT(*) AS count
        FROM detection_metrics WHERE status='completed' GROUP BY name ORDER BY name DESC LIMIT 6""")][::-1]
    queries = {row['outcome']: row['n'] for row in connection.execute(
        'SELECT outcome,COUNT(*) AS n FROM hash_query_metrics GROUP BY outcome')}
    return {
        'available': True, 'started_at': started_at, 'updated_at': now_iso(),
        'received_total': sum(counts.values()), 'completed_total': counts.get('completed', 0),
        'malicious_total': verdicts.get('malicious', 0), 'benign_total': verdicts.get('benign', 0),
        'inconclusive_total': verdicts.get('inconclusive', 0),
        'database_total': modes.get('sample_database', 0), 'model_total': modes.get('models', 0),
        'failed_total': counts.get('failed', 0), 'cancelled_total': counts.get('cancelled', 0),
        'unsupported_total': counts.get('unsupported', 0), 'pending_total': counts.get('pending', 0),
        'unique_completed_samples': unique, 'partial_model_total': partial, 'monthly': monthly,
        'query_total': sum(queries.values()), 'query_hit_total': queries.get('hit', 0),
        'query_miss_total': queries.get('miss', 0), 'query_failed_total': queries.get('failed', 0),
    }
