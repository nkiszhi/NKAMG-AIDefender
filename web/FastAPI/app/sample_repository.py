import logging
import json
import re
from typing import Any, Dict, Optional

from .codefender_client import DEFAULT_MODEL_NAMES

logger = logging.getLogger("aidefender.sample_repository")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
TLSH_RE = re.compile(r"^(?:T1)?[0-9a-f]{70}$", re.IGNORECASE)
SSDEEP_RE = re.compile(r"^([0-9]{1,10}):([A-Za-z0-9/+]{0,64}):([A-Za-z0-9/+]{0,64})$")
TABLE_RE = re.compile(r"^sample_[0-9a-f]{2}$")
DB_RE = re.compile(r"^[A-Za-z0-9_]+$")


def identify_hash(value: str) -> str:
    if SHA256_RE.fullmatch(value):
        return 'sha256'
    if TLSH_RE.fullmatch(value):
        return 'tlsh'
    match = SSDEEP_RE.fullmatch(value)
    if match and (match[2] or match[3]):
        block = int(match[1])
        factor = block // 3
        if block % 3 == 0 and factor > 0 and factor & (factor - 1) == 0:
            return 'ssdeep'
    raise ValueError('请输入有效的 SHA256、TLSH 或 SSDeep 指纹')


class SampleRepository:
    def __init__(self, settings) -> None:
        self.settings = settings

    @property
    def query_databases(self):
        database = getattr(self.settings, 'aidpe_db', 'AIDefender_PE')
        return [database] if database == 'AIDefender_PE' else []

    @property
    def sha256_only(self):
        return True

    @property
    def configured(self) -> bool:
        return bool(getattr(self.settings, "mysql_host", "")
                    and getattr(self.settings, "mysql_user", "")
                    and self.query_databases)

    @staticmethod
    def table_name(sha256: str) -> str:
        table = f"sample_{sha256[:2].lower()}"
        if not TABLE_RE.match(table):
            raise ValueError("无效的SHA256分表名")
        return table

    def find_malicious(self, sha256: str) -> Optional[Dict[str, Any]]:
        if not sha256 or not SHA256_RE.match(sha256):
            return None
        if not self.configured:
            logger.info("MySQL未配置，跳过样本库查询")
            return None
        database = self.query_databases[0]
        table = self.table_name(sha256)
        try:
            record = self._query(database, table, sha256.lower())
        except Exception as error:
            logger.warning("AIDefender_PE查询失败 %s.%s: %s", database, table, error)
            raise RuntimeError("样本结果暂不可用") from error
        if record:
            record = dict(record)
            record["_source_db"] = database
            record["_source_table"] = table
            return record
        return None

    def _query(self, database: str, table: str, sha256: str) -> Optional[Dict[str, Any]]:
        import pymysql
        connection = pymysql.connect(
            host=self.settings.mysql_host,
            port=self.settings.mysql_port,
            user=self.settings.mysql_user,
            password=self.settings.mysql_passwd,
            database=database,
            charset="utf8mb4",
            connect_timeout=5,
            read_timeout=10,
            cursorclass=pymysql.cursors.DictCursor,
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT * FROM `{table}` WHERE sha256 = %s LIMIT 1", (sha256,))
                return cursor.fetchone()
        finally:
            connection.close()

    def find_by_hash(self, value: str) -> Optional[Dict[str, Any]]:
        kind = identify_hash(value)
        if kind == 'sha256':
            return self.find_malicious(value)
        # The AIDefender_PE schema intentionally stores only SHA256 and model results.
        raise ValueError('当前样本库仅支持SHA256精确查询')

    def _query_fingerprint(self, database: str, kind: str, value: str) -> Optional[Dict[str, Any]]:
        # Shards are named by SHA256, so a fuzzy-hash lookup must inspect every shard.
        # Identifiers come only from validated metadata; fingerprint values stay bound.
        if kind not in ('tlsh', 'ssdeep') or not DB_RE.fullmatch(database):
            raise ValueError('无效的指纹查询')
        import pymysql
        connection = pymysql.connect(
            host=self.settings.mysql_host, port=self.settings.mysql_port,
            user=self.settings.mysql_user, password=self.settings.mysql_passwd,
            database=database, charset='utf8mb4', connect_timeout=5,
            read_timeout=45, cursorclass=pymysql.cursors.DictCursor,
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT TABLE_NAME AS table_name FROM information_schema.COLUMNS '
                               'WHERE TABLE_SCHEMA=%s AND COLUMN_NAME=%s ORDER BY TABLE_NAME', (database, kind))
                tables = [row['table_name'] for row in cursor.fetchall() if TABLE_RE.fullmatch(row['table_name'])]
                for table in tables:
                    # SSDeep is case sensitive even when MySQL uses a case-insensitive collation.
                    predicate = f'BINARY `{kind}` = BINARY %s' if kind == 'ssdeep' else f'`{kind}` = %s'
                    cursor.execute(f'SELECT * FROM `{table}` WHERE {predicate} LIMIT 1', (value,))
                    record = cursor.fetchone()
                    if record:
                        return {**record, '_source_db': database, '_source_table': table}
        finally:
            connection.close()
        return None

    @staticmethod
    def public_fields(record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not record:
            return {}
        identity = {"name": "文件名", "length": "文件大小", "sha256": "SHA256", "md5": "MD5"}
        hashes = {"ssdeep": "SSDeep", "tlsh": "TLSH", "authentihash": "Authentihash", "imphash": "Imphash", "vhash": "Vhash", "rich_header_hash": "Rich Header Hash"}
        labels = {"category": "类别", "platform": "平台", "family": "家族", "filetype": "文件类型", "packer": "Packer"}

        def value(key: str) -> Any:
            item = record.get(key)
            return None if item is None or item == "" else item

        model_results = {}
        for key in DEFAULT_MODEL_NAMES:
            item = record.get(key)
            if item is None or item == '':
                continue
            model_results[key] = item

        def json_value(key):
            item = record.get(key)
            if isinstance(item, str):
                try:
                    return json.loads(item)
                except (TypeError, ValueError):
                    return item
            return item

        return {
            "identity": {output: value(key) for key, output in identity.items() if value(key) is not None},
            "hashes": {output: value(key) for key, output in hashes.items() if value(key) is not None},
            "labels": {output: value(key) for key, output in labels.items() if value(key) is not None},
            "model_results": {name: json_value(name) for name in model_results},
            "codefender_result": json_value('codefender_result'),
            "detection_status": value('detection_status'),
            "source": value('source'),
            "model_version": value('model_version'),
            "uploaded_at": value('uploaded_at'),
            "source_db": record.get("_source_db"),
            "source_table": record.get("_source_table"),
        }
