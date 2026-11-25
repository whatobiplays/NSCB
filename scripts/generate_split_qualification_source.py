#!/usr/bin/env python3
"""Create an offset-dependent source file larger than the production Split boundary."""

import argparse
import hashlib
import json
import os
from pathlib import Path


SEGMENT_LIMIT = 0xFFFF0000
DEFAULT_SIZE = 0x1_0000_0000
CONTENT_BLOCK_SIZE = 1 << 16
WRITE_CHUNK_SIZE = 1 << 20
CONTENT_DOMAIN = b"NSCB Split qualification source v2\0"


def content_block(offset: int, size: int = CONTENT_BLOCK_SIZE) -> bytes:
    """Return deterministic bytes for one aligned range in the logical source."""
    if offset < 0 or offset % CONTENT_BLOCK_SIZE != 0:
        raise ValueError("offset must be a nonnegative content-block boundary")
    if size < 0 or size > CONTENT_BLOCK_SIZE:
        raise ValueError("size must fit within one content block")

    seed = CONTENT_DOMAIN + offset.to_bytes(8, "little")
    return hashlib.shake_256(seed).digest(size)


def content_chunk(offset: int, size: int) -> bytes:
    """Return a range assembled from blocks whose seeds include their offsets."""
    if offset < 0 or offset % CONTENT_BLOCK_SIZE != 0:
        raise ValueError("offset must be a nonnegative content-block boundary")
    if size < 0:
        raise ValueError("size must be nonnegative")

    chunk = bytearray()
    while len(chunk) < size:
        block_size = min(CONTENT_BLOCK_SIZE, size - len(chunk))
        block_offset = offset + len(chunk)
        chunk.extend(content_block(block_offset, block_size))
    return bytes(chunk)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--size", type=lambda value: int(value, 0), default=DEFAULT_SIZE)
    args = parser.parse_args()
    if args.size <= SEGMENT_LIMIT:
        parser.error("size must exceed the production Split segment limit")

    digest = hashlib.sha256()
    with args.output.open("xb") as source:
        offset = 0
        while offset < args.size:
            chunk = content_chunk(offset, min(WRITE_CHUNK_SIZE, args.size - offset))
            source.write(chunk)
            digest.update(chunk)
            offset += len(chunk)
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
