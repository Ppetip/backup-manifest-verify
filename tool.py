"""Verify a backup against trusted SHA-256 entries without restoring files, rejecting traversal and symlink paths."""
import hashlib
import re
from pathlib import Path, PurePosixPath

def verify(root, entries, max_bytes=100_000_000):
    root = Path(root).resolve(strict=True)
    result = []
    total = 0
    for name,expected in sorted(entries.items()):
        relative = PurePosixPath(name)
        if not name or '\\' in name or ':' in name or relative.is_absolute() or '..' in relative.parts or '.'==name:
            raise ValueError('unsafe manifest path')
        if not re.fullmatch('[a-fA-F0-9]{64}',expected):
            raise ValueError('invalid SHA-256 digest')
        target = root.joinpath(*relative.parts)
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('symlink in backup')
        if not target.resolve().is_relative_to(root):
            raise ValueError('path escaped backup')
        if not target.is_file():
            result.append(dict(kind='missing',path=name)); continue
        digest = hashlib.sha256()
        with target.open('rb') as stream:
            for block in iter(lambda:stream.read(65536),b''):
                total += len(block)
                if total > max_bytes:
                    raise ValueError('verification byte budget exceeded')
                digest.update(block)
        result.append(dict(kind='verified' if digest.hexdigest()==expected.lower() else 'corrupt',path=name))
    return result

def analyze(data):
    return verify(data['root'],data['entries'],data.get('max_bytes',100_000_000))


def main():
    import argparse, json, sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='path to JSON input, or - for stdin')
    args = parser.parse_args()
    try:
        if args.input == '-':
            data = json.load(sys.stdin)
        else:
            with open(args.input, encoding='utf-8') as stream:
                data = json.load(stream)
        result = analyze(data)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as error:
        print('Invalid input: '+str(error), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
