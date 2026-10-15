import configparser
import os
from pathlib import Path
from typing import List


WEB_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = WEB_ROOT / "config.ini"


def _load_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH, encoding="utf-8")
    return config


def _as_path(value: str, default: str) -> Path:
    raw = (value or default).strip()
    path = Path(raw)
    if not path.is_absolute():
        path = WEB_ROOT / path
    return path.resolve()


class Settings:
    def __init__(self) -> None:
        self._config = _load_config()

        self.host = self._get("server", "host", "127.0.0.1")
        self.port = self._getint("server", "port", 5006)
        self.cors_origins = self._get_list("server", "cors_origins", ["*"])
        self.max_upload_size = self._getint("server", "max_upload_size", 100 * 1024 * 1024)
        self.max_concurrent_scans = max(1, min(2, self._getint("server", "max_concurrent_scans", 1)))
        self.max_queued_scans = max(1, min(100, self._getint("server", "max_queued_scans", 8)))
        self.task_ttl_seconds = self._getint("server", "task_ttl_seconds", 3600)

        self.upload_dir = _as_path(self._get("paths", "upload_dir", "FastAPI/uploads"), "FastAPI/uploads")

        self.codefender_api_base = self._get("codefender", "api_base", "http://127.0.0.1:8001").rstrip("/")
        self.codefender_scan_endpoint = self._get("codefender", "scan_endpoint", "")
        self.codefender_predict_endpoint = self._get("codefender", "predict_endpoint", "/predict-single")
        self.codefender_include_de = self._get("codefender", "include_de", "true").strip().lower() in ("true", "1", "yes", "on")
        self.codefender_timeout = self._getint("codefender", "timeout", 300)
        self.threshold = self._getfloat("codefender", "threshold", 0.5)
        self.host_path_prefix = self._get("codefender", "host_path_prefix", "").strip()
        self.container_path_prefix = self._get("codefender", "container_path_prefix", "").strip()
        self.docker_container_name = self._get("docker", "container_name", "").strip()
        self.docker_container_upload_dir = self._get("docker", "container_upload_dir", "/codefender_uploads").strip()

        self.mysql_host = self._get("mysql", "host", "").strip()
        self.mysql_port = self._getint("mysql", "port", 3306)
        self.mysql_user = self._get("mysql", "user", "").strip()
        self.mysql_passwd = self._get("mysql", "passwd", "")
        self.malicious_dbs = self._get_list(
            "mysql", "malicious_dbs", ["malicious_elf", "malicious_pe", "malicious_others"]
        )
        self.benign_dbs = self._get_list("mysql", "benign_dbs", ["benign_elf", "benign_pe", "benign_others"])
        self.mysql_stats_db = self._get("mysql", "db_stats", "sample_stats").strip()
        self.mysql_domain_db = self._get("mysql", "db_domain", "domain").strip()

    def _get(self, section: str, option: str, default: str) -> str:
        env_name = f"CODEFENDER_{section}_{option}".upper()
        return os.getenv(env_name, self._config.get(section, option, fallback=default))

    def _getint(self, section: str, option: str, default: int) -> int:
        value = self._get(section, option, str(default))
        try:
            return int(value)
        except ValueError:
            return default

    def _getfloat(self, section: str, option: str, default: float) -> float:
        value = self._get(section, option, str(default))
        try:
            return float(value)
        except ValueError:
            return default

    def _get_list(self, section: str, option: str, default: List[str]) -> List[str]:
        value = self._get(section, option, ",".join(default))
        items = [item.strip() for item in value.split(",") if item.strip()]
        return items or default


settings = Settings()
