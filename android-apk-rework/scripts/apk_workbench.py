#!/usr/bin/env python3
"""Inventory APKs, apply guarded native patches, compare final payloads.

Standard library only. Does not discover patch targets, sign or run applications.
"""
import argparse
import copy
import hashlib
import json
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path

SIG = re.compile(r'^META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|MANIFEST\.MF|SIG-[^/]+)$', re.I)
DEX = re.compile(r'^classes(?:\d+)?\.dex$')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda: f.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def number(value):
    require(isinstance(value, (int, str)) and not isinstance(value, bool), 'Offset must be an integer or integer string')
    return int(value, 0) if isinstance(value, str) else int(value)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')


def elf_info(data):
    require(data[:4] == b'\x7fELF' and len(data) >= 52, 'Not an ELF file')
    cls, encoding = data[4:6]
    require(cls in (1, 2) and encoding in (1, 2), 'Unsupported ELF format')
    endian = '<' if encoding == 1 else '>'
    machine = struct.unpack_from(endian + 'H', data, 18)[0]
    return {'bits': 32 if cls == 1 else 64, 'endian': endian,
            'machine': machine, 'architecture': {3: 'x86', 40: 'arm', 62: 'x86_64', 183: 'aarch64'}.get(machine, str(machine))}


def va_to_offset(data, va, size):
    info = elf_info(data)
    e = info['endian']
    if info['bits'] == 64:
        require(len(data) >= 64, 'Truncated ELF64 header')
        phoff = struct.unpack_from(e + 'Q', data, 32)[0]
        stride, count = struct.unpack_from(e + 'HH', data, 54)
        fmt, minimum = 'IIQQQQQQ', 56
    else:
        phoff = struct.unpack_from(e + 'I', data, 28)[0]
        stride, count = struct.unpack_from(e + 'HH', data, 42)
        fmt, minimum = 'IIIIIIII', 32
    require(count != 0xffff, 'Extended program-header numbering needs an ELF parser')
    require(stride >= minimum and phoff + stride * count <= len(data), 'Invalid program headers')
    matches = []
    for i in range(count):
        p = struct.unpack_from(e + fmt, data, phoff + i * stride)
        kind, offset, start, length = (p[0], p[2], p[3], p[5]) if info['bits'] == 64 else (p[0], p[1], p[2], p[4])
        if kind == 1 and start <= va and va + size <= start + length:
            target = offset + va - start
            require(target + size <= len(data), 'Segment exceeds ELF file')
            matches.append(target)
    require(len(matches) == 1, 'VA range must map to exactly one file-backed PT_LOAD')
    return matches[0]


def unique_zip(z):
    names = z.namelist()
    require(len(names) == len(set(names)), 'Duplicate ZIP member names require explicit handling')
    require(z.testzip() is None, 'ZIP CRC failure')
    return set(names)


def check_dex_header(data):
    require(data[:4] == b'dex\n' and len(data) >= 112, 'Replacement is not standard DEX')
    require(struct.unpack_from('<I', data, 32)[0] == len(data), 'DEX file_size mismatch')
    require(data[12:32] == hashlib.sha1(data[32:]).digest(), 'DEX SHA1 mismatch')
    require(struct.unpack_from('<I', data, 8)[0] == zlib.adler32(data[12:]) & 0xffffffff, 'DEX Adler32 mismatch')


def inventory(args):
    location = Path(args.input).resolve()
    files = [location] if location.is_file() else sorted(location.glob('*.apk'))
    require(files, 'No APK files found')
    results = []
    for path in files:
        with zipfile.ZipFile(path) as z:
            names = unique_zip(z)
            libraries = []
            for name in sorted(n for n in names if n.startswith('lib/') and n.endswith('.so')):
                data = z.read(name)
                info = elf_info(data)
                libraries.append({'entry': name, 'size': len(data), 'sha256': digest(data), **info})
            engines = []
            if any(n.endswith('/libflutter.so') for n in names):
                engines.append('flutter')
            if any(n.endswith('/libil2cpp.so') for n in names):
                engines.append('unity-il2cpp')
            if 'assets/index.android.bundle' in names:
                engines.append('react-native')
            versions = []
            for name in sorted(n for n in names if n.endswith('/libflutter.so')):
                pattern = rb'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)? \((?:stable|beta|dev|main)\)[^\x00\r\n]{0,140}'
                versions.extend(x.decode('ascii', 'replace') for x in re.findall(pattern, z.read(name)))
            results.append({'path': str(path), 'size': path.stat().st_size, 'sha256': file_digest(path),
                            'zip_crc': 'passed', 'engines': engines or ['unknown-or-dex'],
                            'abis': sorted({n.split('/')[1] for n in names if n.startswith('lib/') and len(n.split('/')) >= 3}),
                            'dex': sorted(n for n in names if DEX.fullmatch(n)),
                            'libraries': libraries, 'dart_version_candidates': sorted(set(versions)),
                            'jar_signature_members': sorted(n for n in names if SIG.fullmatch(n))})
    write_json(args.out, results)
    print(f'Inventoried {len(results)} APK(s) -> {Path(args.out).resolve()}')


def build(args):
    source, spec_path, output, manifest_path = map(lambda x: Path(x).resolve(), (args.source, args.spec, args.out, args.manifest))
    require(len({source, spec_path, output, manifest_path}) == 4, 'Input/output paths must be distinct')
    require(not output.exists() and not manifest_path.exists(), 'Output exists; choose a new revision path')
    spec = json.loads(spec_path.read_text(encoding='utf-8-sig'))
    sha = file_digest(source)
    require(sha == spec.get('source_sha256', '').lower(), 'Source APK SHA256 does not match specification')
    changes, replacements, buffers, ranges = [], [], {}, {}
    with zipfile.ZipFile(source) as src:
        names = unique_zip(src)
        for patch in spec.get('patches', []):
            name = patch['entry']
            require(name in names and name.endswith('.so'), 'Byte patches are restricted to existing ELF SO members; reassemble DEX')
            require(bool(patch.get('purpose', '').strip()), 'Patch purpose required')
            require(('va' in patch) != ('offset' in patch), 'Specify exactly one of va or offset')
            before, after = bytes.fromhex(patch['before_hex']), bytes.fromhex(patch['after_hex'])
            require(before and len(before) == len(after) and before != after, 'Native patch must change equal, nonzero byte lengths')
            original = src.read(name)
            elf_info(original)
            offset = va_to_offset(original, number(patch['va']), len(before)) if 'va' in patch else number(patch['offset'])
            require(offset >= 0 and offset + len(before) <= len(original), 'Patch out of bounds')
            require(original[offset:offset + len(before)] == before, f'Original bytes mismatch: {name}@{offset:#x}')
            touched = set(range(offset, offset + len(before)))
            require(not touched.intersection(ranges.get(name, set())), 'Overlapping patches')
            ranges.setdefault(name, set()).update(touched)
            buffers.setdefault(name, bytearray(original))[offset:offset + len(after)] = after
            changes.append({**patch, 'offset': hex(offset)})
        for item in spec.get('replacements', []):
            name = item['entry']
            require(name in names and not SIG.fullmatch(name) and not src.getinfo(name).is_dir(), 'Replacement must target a non-signature file')
            require(name not in buffers and bool(item.get('purpose', '').strip()), 'Conflicting replacement or missing purpose')
            original = src.read(name)
            require(digest(original) == item['expected_sha256'].lower(), 'Replacement source hash mismatch')
            path = Path(item['file'])
            if not path.is_absolute():
                path = spec_path.parent / path
            data = path.read_bytes()
            require(data != original, 'Replacement does not change contents')
            if DEX.fullmatch(name):
                check_dex_header(data)
            buffers[name] = data
            replacements.append({'entry': name, 'file': str(path.resolve()), 'purpose': item['purpose']})
        require(buffers, 'No changes specified')
        members = [{'entry': name, 'before_sha256': digest(src.read(name)), 'after_sha256': digest(data), 'size': len(data)} for name, data in sorted(buffers.items())]
        output.parent.mkdir(parents=True, exist_ok=True)
        output_created = False
        try:
            with output.open('xb') as f:
                output_created = True
                with zipfile.ZipFile(f, 'w') as dst:
                    dst.comment = src.comment
                    for info in src.infolist():
                        if not SIG.fullmatch(info.filename):
                            dst.writestr(copy.copy(info), buffers[info.filename] if info.filename in buffers else src.read(info.filename))
            with zipfile.ZipFile(output) as dst:
                require(unique_zip(dst) == {n for n in names if not SIG.fullmatch(n)}, 'Unexpected unsigned member set')
                for name in dst.namelist():
                    require(dst.read(name) == (bytes(buffers[name]) if name in buffers else src.read(name)), f'Payload mismatch: {name}')
            record = {'source': str(source), 'source_sha256': sha, 'unsigned_sha256': file_digest(output),
                      'patches': changes, 'replacements': replacements, 'modified_members': members,
                      'scope': 'Guarded payload changes only; unsigned, alignment and runtime not verified'}
            write_json(manifest_path, record)
        except Exception:
            if output_created and output.exists():
                output.unlink()
            raise
    print(f'Built {output}; {len(members)} modified member(s); unsigned')


def compare(args):
    source, target = Path(args.source).resolve(), Path(args.target).resolve()
    record = json.loads(Path(args.manifest).read_text(encoding='utf-8-sig'))
    require(file_digest(source) == record['source_sha256'], 'Manifest is bound to another source APK')
    modified = {x['entry']: x for x in record['modified_members']}
    require(len(modified) == len(record['modified_members']), 'Duplicate modified members in manifest')
    with zipfile.ZipFile(source) as a, zipfile.ZipFile(target) as b:
        aa, bb = unique_zip(a), unique_zip(b)
        require({n for n in aa if not SIG.fullmatch(n)} == {n for n in bb if not SIG.fullmatch(n)}, 'Non-signature member sets differ')
        require(set(modified) <= aa.intersection(bb), 'Declared modified member is missing')
        for name in sorted(n for n in aa if not SIG.fullmatch(n)):
            original, final = a.read(name), b.read(name)
            if name in modified:
                item = modified[name]
                require(digest(original) == item['before_sha256'] and digest(final) == item['after_sha256'], f'Modified hash mismatch: {name}')
            else:
                require(original == final, f'Undeclared payload change: {name}')
    result = {'source_sha256': file_digest(source), 'target_sha256': file_digest(target), 'zip_crc': 'passed',
              'payload_comparison': 'passed', 'modified_members': sorted(modified),
              'scope': 'Does not verify APK signatures, alignment, ELF compatibility or runtime'}
    write_json(args.out, result)
    print(f'Payload comparison passed -> {Path(args.out).resolve()}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('inventory'); p.add_argument('--input', required=True); p.add_argument('--out', required=True); p.set_defaults(run=inventory)
    p = sub.add_parser('build')
    for field in ('source', 'spec', 'out', 'manifest'):
        p.add_argument('--' + field, required=True)
    p.set_defaults(run=build)
    p = sub.add_parser('compare')
    for field in ('source', 'target', 'manifest', 'out'):
        p.add_argument('--' + field, required=True)
    p.set_defaults(run=compare)
    args = parser.parse_args()
    try:
        args.run(args)
    except (ValueError, TypeError, KeyError, OSError, zipfile.BadZipFile, struct.error) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
