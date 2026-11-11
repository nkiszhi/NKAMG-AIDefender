import tempfile
import configparser
import unittest
from pathlib import Path
from unittest.mock import patch

from app.config import _load_config, Settings


class ConfigLoadingTests(unittest.TestCase):
    def test_development_response_contract_is_explicit_and_upload_only(self):
        config = configparser.ConfigParser()
        with patch('app.config._load_config', return_value=config):
            self.assertEqual(Settings().codefender_response_contract, 'web')
        config.read_dict({'codefender': {'response_contract': 'development', 'api_base': 'http://127.0.0.1:18002'}})
        with patch('app.config._load_config', return_value=config):
            self.assertEqual(Settings().codefender_response_contract, 'development')
        config.read_dict({'codefender': {'scan_endpoint': '/scan'}})
        with patch('app.config._load_config', return_value=config), self.assertRaises(ValueError):
            Settings()
        config.read_dict({'codefender': {'scan_endpoint': '', 'response_contract': 'production'}})
        with patch('app.config._load_config', return_value=config), self.assertRaises(ValueError):
            Settings()

    def test_parallel_workers_require_isolated_addresses(self):
        config = configparser.ConfigParser()
        config.read_dict({'server': {'max_concurrent_scans': '2'}})
        with patch('app.config._load_config', return_value=config):
            with self.assertRaises(ValueError):
                Settings()
        config.read_dict({'codefender': {'api_bases': 'http://127.0.0.1:8001,http://127.0.0.1:8002'}})
        with patch('app.config._load_config', return_value=config):
            self.assertEqual(len(Settings().codefender_api_bases), 2)
        config.read_dict({'codefender': {'scan_endpoint': '/scan'}})
        with patch('app.config._load_config', return_value=config):
            with self.assertRaises(ValueError):
                Settings()

    def test_upload_limit_defaults_to_one_gib_and_respects_lower_policy(self):
        config = configparser.ConfigParser()
        with patch('app.config._load_config', return_value=config):
            self.assertEqual(Settings().max_upload_size, 1024 ** 3)
        config.read_dict({'server': {'max_upload_size': '104857600'}})
        with patch('app.config._load_config', return_value=config):
            self.assertEqual(Settings().max_upload_size, 100 * 1024 * 1024)
        config.read_dict({'uploads': {'max_file_size': '10485760'}})
        with patch('app.config._load_config', return_value=config):
            self.assertEqual(Settings().max_upload_size, 10 * 1024 * 1024)
        config.read_dict({'server': {'max_upload_size': str(2 * 1024 ** 3)},
                          'uploads': {'max_file_size': str(2 * 1024 ** 3)}})
        with patch('app.config._load_config', return_value=config):
            self.assertEqual(Settings().max_upload_size, 1024 ** 3)

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
