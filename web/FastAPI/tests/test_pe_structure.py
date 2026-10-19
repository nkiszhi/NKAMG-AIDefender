import struct
import tempfile
import unittest
from pathlib import Path

from app.file_info import analyze_pe, build_file_info


def make_pe(bits=32, dll=False):
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional_size = 240 if bits == 64 else 224
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664 if bits == 64 else 0x14c,
                     1, 0, 0, 0, optional_size, 0x2002 if dll else 0x2)
    struct.pack_into('<H', data, 0x98, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<I', data, 0x98 + (108 if bits == 64 else 92), 16)
    section = 0x98 + optional_size
    data[section:section + 5] = b'.text'
    struct.pack_into('<IIII', data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    return data


class PEStructureTests(unittest.TestCase):
    def inspect(self, data, filename='sample.bin'):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / filename
            path.write_bytes(data)
            return build_file_info(path)

    def test_four_pe_types_ignore_filename_and_match_structure(self):
        for bits in (32, 64):
            for dll in (False, True):
                with self.subTest(bits=bits, dll=dll):
                    info = self.inspect(make_pe(bits, dll), 'hash.vir')
                    kind = ('dll' if dll else 'exe') + str(bits)
                    self.assertTrue(info['is_pe'])
                    self.assertEqual(info['pe_info']['pe_type'], kind)
                    self.assertEqual(info['pe_info']['is_dll'], dll)
                    self.assertEqual(info['pe_info']['bits'], bits)
                    self.assertTrue(info['file_type'].startswith(kind))

    def test_rejects_truncated_and_inconsistent_headers(self):
        cases = []
        data = make_pe(); struct.pack_into('<I', data, 0x3c, 0x20)
        cases.append((data, '偏移'))
        data = make_pe(); struct.pack_into('<H', data, 0x94, 1)
        cases.append((data, '可选头'))
        data = make_pe(); struct.pack_into('<H', data, 0x94, 70)
        cases.append((data, '长度不足'))
        data = make_pe(); struct.pack_into('<I', data, 0x98 + 92, 17)
        cases.append((data, '数据目录'))
        cases.append((make_pe()[:0x98 + 224 + 39], '节表'))
        cases.append((make_pe()[:-1], '原始数据'))
        cases.append((b'MZ', 'DOS文件头'))
        for data, reason in cases:
            with self.subTest(reason=reason):
                info = self.inspect(data, 'pretend.exe')
                self.assertFalse(info['is_pe'])
                self.assertIn(reason, info['pe_info']['reason'])
                self.assertIn('未通过', info['file_type'])

    def test_accepts_bss_and_overlay_without_overstrict_loader_checks(self):
        data = make_pe()
        struct.pack_into('<II', data, 0x98 + 224 + 16, 0, 0)
        self.assertTrue(self.inspect(data[:512])['is_pe'])
        self.assertTrue(self.inspect(make_pe() + b'overlay') ['is_pe'])

    def test_arm64_is_not_mislabeled_as_x64(self):
        data = make_pe(64, True)
        struct.pack_into('<H', data, 0x84, 0xaa64)
        info = self.inspect(data)
        self.assertTrue(info['is_pe'])
        self.assertEqual(info['pe_info']['pe_type'], 'dll64')
        self.assertIn('ARM64', info['file_type'])

    def test_magic_only_does_not_claim_valid_pe(self):
        info = self.inspect(b'MZ' + bytes(1022))
        self.assertFalse(info['is_pe'])
        self.assertIn('未通过', info['file_type'])
