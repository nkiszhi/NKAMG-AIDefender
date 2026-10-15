import asyncio
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import UploadFile
from app.file_info import save_upload
from app.config import settings


class PEUploadTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Uses the local Windows Python PE executable")
    def test_identical_pe_bytes_accept_all_filename_extensions(self):
        content = Path(sys.executable).read_bytes()
        self.assertEqual(content[:2], b"MZ")
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(settings, "upload_dir", Path(folder)):
                for name in ("sample.exe", "sample.bin", "sample.vir", "sample", "hash.zip"):
                    with self.subTest(name=name):
                        upload = UploadFile(filename=name, file=io.BytesIO(content))
                        path, info = asyncio.run(save_upload(upload))
                        self.assertTrue(info["is_pe"])
                        self.assertEqual(info["filename"], name)

    def test_exe_extension_does_not_make_text_a_pe(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(settings, "upload_dir", Path(folder)):
                upload = UploadFile(filename="sample.exe", file=io.BytesIO(b"not a PE"))
                path, info = asyncio.run(save_upload(upload))
                self.assertFalse(info["is_pe"])
                self.assertIn("6E 6F 74", info["pe_info"]["reason"])
