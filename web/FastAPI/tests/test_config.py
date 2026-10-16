import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.config import _load_config


class ConfigLoadingTests(unittest.TestCase):
    def test_example_config_is_loaded_without_local_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_config = Path(temp_dir) / "config.ini"
            with patch("app.config.CONFIG_PATH", local_config):
                config = _load_config()

        self.assertEqual(config.getint("server", "port"), 5006)
        self.assertEqual(config.get("codefender", "api_base"), "http://127.0.0.1:8001")

    def test_local_config_overrides_example_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local_config = Path(temp_dir) / "config.ini"
            local_config.write_text("[server]\nport = 6123\n", encoding="utf-8")
            with patch("app.config.CONFIG_PATH", local_config):
                config = _load_config()

        self.assertEqual(config.getint("server", "port"), 6123)
        self.assertEqual(config.get("codefender", "api_base"), "http://127.0.0.1:8001")


if __name__ == "__main__":
    unittest.main()
