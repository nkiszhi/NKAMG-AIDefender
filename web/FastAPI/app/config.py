import configparser
import os
from pathlib import Path
from typing import List


WEB_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = WEB_ROOT / "config.ini"
EXAMPLE_CONFIG_PATH = WEB_ROOT / "config.example.ini"


def _load_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read([str(EXAMPLE_CONFIG_PATH), str(CONFIG_PATH)], encoding="utf-8")
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
        self.max_upload_size = max(1, min(
            self._getint("server", "max_upload_size", 1024 * 1024 * 1024),
            self._getint("uploads", "max_file_size", 1024 * 1024 * 1024),
            1024 * 1024 * 1024,
        ))
        self.min_free_disk_bytes = max(0, self._getint("uploads", "min_free_disk_bytes", 512 * 1024 * 1024))
        self.orphan_ttl_seconds = max(600, self._getint("uploads", "orphan_ttl_seconds", 3600))
        self.max_concurrent_scans = max(1, min(2, self._getint("server", "max_concurrent_scans", 1)))
        self.max_queued_scans = max(1, min(100, self._getint("server", "max_queued_scans", 8)))
        self.task_ttl_seconds = self._getint("server", "task_ttl_seconds", 3600)
        self.large_sample_bytes = max(1, self._getint('server', 'large_sample_bytes', 100 * 1024 * 1024))
        self.max_queue_wait_seconds = max(60, self._getint('server', 'max_queue_wait_seconds', 1800))
        monitor = self._get('codefender', 'resource_monitor_path', '').strip()
        self.model_monitor_path = _as_path(monitor, monitor) if monitor else None
        self.model_monitor_stale_seconds = max(5, self._getint('codefender', 'resource_monitor_stale_seconds', 15))
        self.model_min_available_bytes = max(0, self._getint('codefender', 'min_available_memory_bytes', 4 * 1024**3))
        self.model_revision = self._get('codefender', 'model_revision', 'deployment-v1').strip() or 'deployment-v1'
        self.model_recovery_seconds = max(30, self._getint('codefender', 'recovery_timeout_seconds', 1200))
        self.api_upload_timeout_seconds = max(10, self._getint('uploads', 'api_upload_timeout_seconds', 600))
        self.api_upload_idle_timeout_seconds = max(5, self._getint('uploads', 'api_upload_idle_timeout_seconds', 60))

        self.upload_dir = _as_path(self._get("paths", "upload_dir", "FastAPI/uploads"), "FastAPI/uploads")

        self.codefender_api_base = self._get("codefender", "api_base", "http://127.0.0.1:8001").rstrip("/")
        self.codefender_api_bases = list(dict.fromkeys(
            url.strip().rstrip('/') for url in self._get('codefender', 'api_bases', '').split(',') if url.strip()
        )) or [self.codefender_api_base]
        self.codefender_api_base = self.codefender_api_bases[0]
        self.codefender_scan_endpoint = self._get("codefender", "scan_endpoint", "")
        self.codefender_predict_endpoint = self._get("codefender", "predict_endpoint", "/predict-single")
        self.codefender_response_contract = self._get("codefender", "response_contract", "web").strip().lower()
        if self.codefender_response_contract not in ("web", "development"):
            raise ValueError('codefender.response_contract 必须为 web 或 development')
        self.codefender_include_de = self._get("codefender", "include_de", "true").strip().lower() in ("true", "1", "yes", "on")
        self.codefender_timeout = self._getint("codefender", "timeout", 300)
        self.threshold = self._getfloat("codefender", "threshold", 0.5)
        self.host_path_prefix = self._get("codefender", "host_path_prefix", "").strip()
        self.container_path_prefix = self._get("codefender", "container_path_prefix", "").strip()
        if self.codefender_response_contract == 'development' and self.codefender_scan_endpoint:
            raise ValueError('开发诊断接口仅支持上传，请将 codefender.scan_endpoint 留空')
        self.docker_container_name = self._get("docker", "container_name", "").strip()
        self.docker_container_upload_dir = self._get("docker", "container_upload_dir", "/codefender_uploads").strip()
        if self.max_concurrent_scans > len(self.codefender_api_bases):
            raise ValueError('并行检测需要独立模型服务地址：请为每个运行槽配置一个 codefender.api_bases 地址')
        if len(self.codefender_api_bases) > 1 and self.codefender_scan_endpoint:
            raise ValueError('多模型容器仅支持上传接口，请将 codefender.scan_endpoint 留空')

        self.mysql_host = self._get("mysql", "host", "").strip()
        self.mysql_port = self._getint("mysql", "port", 3306)
        self.mysql_user = self._get("mysql", "user", "").strip()
        self.mysql_passwd = self._get("mysql", "passwd", "")
        # Switch explicitly only after source membership and replication acceptance.
        self.pe_lookup_db = self._get('mysql', 'pe_lookup_db', 'malicious_pe').strip()
        if self.pe_lookup_db not in ('malicious_pe', 'AIDefender_PE'):
            raise ValueError('mysql.pe_lookup_db 必须为 malicious_pe 或 AIDefender_PE')
        self.malicious_dbs = self._get_list(
            "mysql", "malicious_dbs", ["malicious_elf", "malicious_pe", "malicious_others"]
        )
        self.benign_dbs = self._get_list("mysql", "benign_dbs", ["benign_elf", "benign_pe", "benign_others"])
        self.mysql_stats_db = self._get("mysql", "db_stats", "sample_stats").strip()
        self.mysql_domain_db = self._get("mysql", "db_domain", "domain").strip()
        self.domain_stats_mode = self._get('mysql', 'domain_stats_mode', 'legacy').strip()
        if self.domain_stats_mode not in ('legacy', 'snapshot'):
            raise ValueError('mysql.domain_stats_mode 必须为 legacy 或 snapshot')
        self.aidpe_db = self._get("mysql", "aidpe_db", "AIDefender_PE").strip()
        if self.aidpe_db != "AIDefender_PE":
            raise ValueError("mysql.aidpe_db 必须为 AIDefender_PE")
        self.aidpe_primary_host = self._get("mysql", "aidpe_primary_host", "").strip()
        self.aidpe_primary_port = self._getint("mysql", "aidpe_primary_port", 13306)
        self.aidpe_primary_user = self._get("mysql", "aidpe_primary_user", "").strip()
        self.aidpe_primary_passwd = self._get("mysql", "aidpe_primary_passwd", "")
        self.aidpe_outbox_path = _as_path(
            self._get("paths", "aidpe_outbox_path", "FastAPI/data/aidpe_result_outbox.sqlite3"),
            "FastAPI/data/aidpe_result_outbox.sqlite3",
        )
        self.aidpe_sample_root = _as_path(
            self._get("paths", "aidpe_sample_root", "FastAPI/web_upload_samples"),
            "FastAPI/web_upload_samples",
        )

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
