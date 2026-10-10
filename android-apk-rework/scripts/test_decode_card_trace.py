"""Synthetic metadata only: run with python -m unittest discover -s scripts."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from decode_card_trace import HEADER, MAX_INPUT_BYTES, decode_records


def record(level, name, cid=7):
    data = name.encode('latin1' if cid == 7 else 'utf-16le')
    return HEADER.pack(level, cid, len(data)) + data


class MetadataTests(unittest.TestCase):
    def test_signed_levels_encodings_and_deduplication(self):
        data = record(-1, 'Basic') + record(2, '目标卡', 8) + record(-1, 'Basic')
        self.assertEqual(decode_records(data, 7, 8), [
            {'vipLevel': -1, 'productName': 'Basic'},
            {'vipLevel': 2, 'productName': '目标卡'},
        ])

    def test_shared_tier_does_not_collapse_distinct_cards(self):
        self.assertEqual(len(decode_records(record(2, 'A') + record(2, 'B'), 7, 8)), 2)

    def test_same_name_with_different_levels_is_preserved(self):
        rows = decode_records(record(1, 'A') + record(2, 'A'), 7, 8)
        self.assertEqual([x['vipLevel'] for x in rows], [1, 2])

    def test_int64_boundaries(self):
        for level in [-(2**63), 2**63 - 1]:
            with self.subTest(level=level):
                self.assertEqual(decode_records(record(level, 'A'), 7, 8)[0]['vipLevel'], level)

    def test_empty_stream(self):
        self.assertEqual(decode_records(b'', 7, 8), [])

    def test_invalid_records_are_rejected(self):
        cases = [b'x', HEADER.pack(1, 9, 0), HEADER.pack(1, 7, 2) + b'a',
                 HEADER.pack(1, 8, 1) + b'a', HEADER.pack(1, 7, 257) + b'a' * 257,
                 HEADER.pack(1, 8, 2) + b'\x00\xd8', b'x' * (MAX_INPUT_BYTES + 1)]
        for data in cases:
            with self.subTest(size=len(data)):
                with self.assertRaises(ValueError):
                    decode_records(data, 7, 8)

    def test_invalid_cids_are_rejected(self):
        for one, two in [(7, 7), (0, 8), (-1, 8), (7, 2**32)]:
            with self.subTest(cids=(one, two)):
                with self.assertRaises(ValueError):
                    decode_records(b'', one, two)

    def test_encoding_error_does_not_dump_name_bytes(self):
        with self.assertRaisesRegex(ValueError, '^Invalid name encoding at byte 16$'):
            decode_records(HEADER.pack(1, 8, 2) + b'\x00\xd8', 7, 8)

    def test_cli_evidence_and_output_preservation(self):
        script = Path(__file__).with_name('decode_card_trace.py')
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'metadata.bin'
            out = Path(folder) / 'metadata.json'
            data = record(2, 'A') + record(2, 'B')
            source.write_bytes(data)
            args = [sys.executable, str(script), '--input', str(source), '--out', str(out),
                    '--one-byte-cid', '7', '--two-byte-cid', '8', '--highest-name', 'Missing']
            p = subprocess.run(args, capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            result = json.loads(out.read_text(encoding='utf-8'))
            self.assertFalse(result['requested_card_observed'])
            self.assertFalse(result['entitlement_verified'])
            self.assertFalse(result['full_playback_verified'])
            original_output = out.read_bytes()
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertEqual(out.read_bytes(), original_output)
            args[args.index('--out') + 1] = str(source)
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertEqual(source.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
