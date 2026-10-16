import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger("aidefender.stats")


class StatsRepository:
    def __init__(self, settings) -> None:
        self.settings = settings

    def _connect(self, database: str):
        import pymysql
        return pymysql.connect(
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

    @staticmethod
    def _top(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
        result = []
        seen = set()
        for row in rows:
            raw_name = row.get(key)
            name = " ".join(str(raw_name or "").strip().split())
            name = name.replace('"', '').replace("'", '').strip()
            if not name or name.upper() in {"UNKNOWN", "UN知", "N/A", "NA", "NULL", "NONE", "-"} or name in seen:
                continue
            seen.add(name)
            result.append({"name": name, "count": int(row.get("count") or 0)})
        return result

    def refresh(self) -> dict[str, Any]:
        if not (self.settings.mysql_host and self.settings.mysql_user and self.settings.mysql_passwd):
            return {"available": False, "reason": "MySQL未配置", "updated_at": None}
        result = {"available": True, "updated_at": datetime.now().isoformat(timespec="seconds"), "samples": {}, "domains": {}}
        try:
            with self._connect(self.settings.mysql_stats_db) as conn:
                with conn.cursor() as cur:
                    result["samples"] = self._sample_stats(cur)
            with self._connect(self.settings.mysql_domain_db) as conn:
                with conn.cursor() as cur:
                    result["domains"] = self._domain_stats(cur)
        except Exception as error:
            logger.warning("读取MySQL统计失败: %s", error)
            return {"available": False, "reason": f"MySQL统计读取失败: {error}", "updated_at": None}
        return result

    def _sample_stats(self, cur) -> dict[str, Any]:
        data = {"malicious_total": 0, "benign_total": 0, "monthly": [], "category": [], "platform": [], "family": [], "filetype": []}
        totals = {
            "malicious_total": "SELECT COALESCE(SUM(total_samples),0) AS value FROM sample_total_stats WHERE sample_class='malicious'",
            "benign_total": "SELECT COALESCE(SUM(total_samples),0) AS value FROM sample_total_stats WHERE sample_class='benign'",
        }
        for key, sql in totals.items():
            try:
                cur.execute(sql)
                data[key] = int((cur.fetchone() or {}).get("value") or 0)
            except Exception:
                logger.debug("样本总量统计不可用: %s", key, exc_info=True)
        for field in ("category", "platform", "family", "filetype"):
            try:
                sql = f"SELECT `{field}`, SUM(total_samples) AS count FROM `sample_{field}_stats` WHERE sample_class='malicious' GROUP BY `{field}` ORDER BY count DESC LIMIT 10"
                cur.execute(sql)
                data[field] = self._top(cur.fetchall(), field)
            except Exception:
                logger.debug("样本分类统计不可用: %s", field, exc_info=True)
        try:
            cur.execute("SELECT CONCAT(year, '-', LPAD(month, 2, '0')) AS name, SUM(total_samples) AS count FROM sample_monthly_stats WHERE sample_class='malicious' GROUP BY year, month ORDER BY year DESC, month DESC LIMIT 12")
            data["monthly"] = self._top(cur.fetchall(), "name")[::-1]
        except Exception:
            logger.debug("样本月度统计不可用", exc_info=True)
        return data

    def _domain_stats(self, cur) -> dict[str, Any]:
        data = {"total": 0, "monthly": [], "source": [], "category": []}
        try:
            cur.execute("SELECT COALESCE(SUM(record_count),0) AS value FROM domain_stats")
            data["total"] = int((cur.fetchone() or {}).get("value") or 0)
        except Exception:
            logger.debug("域名总数不可用", exc_info=True)
        for table, field in (("source_stats", "source"), ("category_stats", "category")):
            try:
                cur.execute(f"SELECT `{field}`, count FROM `{table}` ORDER BY count DESC LIMIT 10")
                data[field] = self._top(cur.fetchall(), field)
            except Exception:
                logger.debug("域名统计不可用: %s", table, exc_info=True)
        try:
            cur.execute("SELECT DATE_FORMAT(stat_date, '%Y-%m') AS name, SUM(record_count) AS count FROM domain_stats GROUP BY name ORDER BY name DESC LIMIT 12")
            data["monthly"] = self._top(cur.fetchall(), "name")[::-1]
        except Exception:
            logger.debug("域名月度统计不可用", exc_info=True)
        return data
