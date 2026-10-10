#!/usr/bin/env python3
"""Decode bounded, names/levels-only <qII> metadata records; no APK mutation."""
import argparse
import json
import struct
from pathlib import Path

HEADER = struct.Struct('<qII')
MAX_INPUT_BYTES = 1024 * 1024
MAX_NAME_BYTES = 256


def decode_records(data, one_byte_cid, two_byte_cid):
    """Level is already decoded signed int64; this function does not untag Smi."""
    if not (0 < one_byte_cid <= 0xffffffff and
            0 < two_byte_cid <= 0xffffffff and one_byte_cid != two_byte_cid):
        raise ValueError('String CIDs must be distinct positive uint32 values')
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError('Metadata exceeds the 1 MiB limit')
    offset = 0
    records = []
    seen = set()
    while offset < len(data):
        if len(data) - offset < HEADER.size:
            raise ValueError(f'Truncated metadata header at byte {offset}')
        level, cid, size = HEADER.unpack_from(data, offset)
        offset += HEADER.size
        if cid not in (one_byte_cid, two_byte_cid):
            raise ValueError(f'Unexpected String CID at byte {offset - HEADER.size}')
        if size > MAX_NAME_BYTES or size > len(data) - offset:
            raise ValueError(f'Invalid or truncated name length at byte {offset}')
        if cid == two_byte_cid and size % 2:
            raise ValueError(f'Odd UTF-16 byte length at byte {offset}')
        try:
            name = data[offset:offset + size].decode(
                'latin1' if cid == one_byte_cid else 'utf-16le', errors='strict')
        except UnicodeError:
            raise ValueError(f'Invalid name encoding at byte {offset}') from None
        offset += size
        key = (level, name)
        if key not in seen:
            records.append({'vipLevel': level, 'productName': name})
            seen.add(key)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--one-byte-cid', required=True, type=lambda x: int(x, 0))
    parser.add_argument('--two-byte-cid', required=True, type=lambda x: int(x, 0))
    parser.add_argument('--highest-name', help='Exact requested name; no tier guessing')
    args = parser.parse_args()
    try:
        if args.input.resolve() == args.out.resolve():
            raise ValueError('Input and output must differ')
        with args.input.open('rb') as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        records = decode_records(data, args.one_byte_cid, args.two_byte_cid)
        matches = [x for x in records if x['productName'] == args.highest_name]
        result = {
            'format': '<qII> signed decoded level, String CID, byte length, name bytes',
            'records': records,
            'requested_highest_name': args.highest_name,
            'requested_card_matches': matches,
            'requested_card_observed': bool(matches),
            'entitlement_verified': False,
            'full_playback_verified': False,
        }
        # Refuse existing output, including the input itself; no raw-data error dumps.
        with args.out.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f'Decoded {len(records)} distinct card records; '
          f'requested name observed: {bool(matches)}. Entitlements remain unverified.')


if __name__ == '__main__':
    main()
