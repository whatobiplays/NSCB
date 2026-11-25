#!/usr/bin/env python3
"""Create a deterministic source file larger than the production Split boundary."""

import argparse
import hashlib
import json
import os
from pathlib import Path


SEGMENT_LIMIT = 0xFFFF0000
DEFAULT_SIZE = 0x1_0000_0000
CHUNK_SIZE = 1 << 20


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--size", type=lambda value: int(value, 0), default=DEFAULT_SIZE)
    args = parser.parse_args()
    if args.size <= SEGMENT_LIMIT:
        parser.error("size must exceed the production Split segment limit")

    pattern = bytes((index * 131 + 17) & 0xFF for index in range(4096))
    block = pattern * (CHUNK_SIZE // len(pattern))
    remaining = args.size
    digest = hashlib.sha256()
    with args.output.open("xb") as source:
        while remaining:
            chunk = block[: min(remaining, len(block))]
            source.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        source.flush()
        os.fsync(source.fileno())

    print(
        json.dumps(
            {
                "source_path": str(args.output.resolve()),
                "size_bytes": args.size,
                "sha256": digest.hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
