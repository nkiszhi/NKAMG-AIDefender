import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger("aidefender.sample_repository")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
TABLE_RE = re.compile(r"^sample_[0-9a-f]{2}$")
DB_RE = re.compile(r"^[A-Za-z0-9_]+$")


class SampleRepository:
    def __init__(self, settings) -> None:
        self.settings = settings

    @property
    def configured(self) -> bool:
        return bool(getattr(self.settings, "mysql_host", "")
                    and getattr(self.settings, "mysql_user", "")
                    and getattr(self.settings, "malicious_dbs", []))

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
        table = self.table_name(sha256)
        for database in self.settings.malicious_dbs:
            if not DB_RE.match(database):
                continue
            try:
                record = self._query(database, table, sha256.lower())
            except Exception as error:
                logger.warning("样本库查询失败 %s.%s: %s", database, table, error)
                raise RuntimeError(f"样本库暂不可用: {error}") from error
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
                cursor.execute(f"SELECT * FROM {table} WHERE TRIM(sha256) = %s LIMIT 1", (sha256,))
                return cursor.fetchone()
        finally:
            connection.close()

    @staticmethod
    def public_fields(record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not record:
            return {}
        identity = ("name", "length", "sha256", "md5")
        hashes = ("ssdeep", "tlsh", "authentihash", "imphash", "vhash", "rich_header_hash")
        labels = {"category": "Category", "platform": "Platform", "family": "Family", "filetype": "FileType", "packer": "Packer"}

        def value(key: str) -> Any:
            item = record.get(key)
            return None if item is None or item == "" else item

        return {
            "identity": {key: value(key) for key in identity},
            "hashes": {key: value(key) for key in hashes},
            "labels": {output: value(key) for key, output in labels.items()},
            "source_db": record.get("_source_db"),
            "source_table": record.get("_source_table"),
        }
