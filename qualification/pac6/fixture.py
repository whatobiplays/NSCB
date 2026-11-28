"""Create deterministic, key-free byte streams for the PAC-6 consumer matrix."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

SEGMENT_SIZE = 0xFFFF0000
BLOCK_SIZE = 1024 * 1024
RESERVE_BYTES = 1024 * 1024 * 1024
SEED_PREFIX = b"NSCB-Issue-14-PAC-6-fixture-v1\0"

CASE_LENGTHS: dict[str, tuple[int, ...]] = {
    "single": (9499,),
    "small-multipart": (1731, 4096, 3672),
    "ten-members": tuple(1021 + index * 37 for index in range(10)),
    "production-boundary": (SEGMENT_SIZE, 1),
}


def required_free_bytes(input_bytes: int, output_bytes: int | None = None) -> int:
    """Return the fixture, output, and reserve space needed before generation."""
    output_bytes = input_bytes if output_bytes is None else output_bytes
    return input_bytes + output_bytes + RESERVE_BYTES


def _expected_chunks(case_name: str, total_length: int):
    seed = SEED_PREFIX + case_name.encode("ascii") + b"\0"
    block_number = 0
    produced = 0
    while produced < total_length:
        block = hashlib.shake_256(seed + block_number.to_bytes(8, "little")).digest(BLOCK_SIZE)
        count = min(BLOCK_SIZE, total_length - produced)
        yield block[:count]
        produced += count
        block_number += 1


def generate_fixture(
    directory: Path,
    case_name: str,
    extension: str,
    *,
    available_free_bytes: int | None = None,
) -> dict[str, Any]:
    """Write ordered members while hashing the exact joined input stream."""
    if case_name not in CASE_LENGTHS:
        raise ValueError(f"unknown PAC-6 case: {case_name}")
    if extension not in {"xc", "ns"}:
        raise ValueError("extension must be 'xc' or 'ns'")

    lengths = CASE_LENGTHS[case_name]
    total_length = sum(lengths)
    disk = shutil.disk_usage(directory.parent if directory.parent.exists() else Path.cwd())
    free_bytes = disk.free if available_free_bytes is None else available_free_bytes
    needs_space_check = case_name == "production-boundary"
    required = required_free_bytes(total_length) if needs_space_check else 0
    if needs_space_check and free_bytes < required:
        raise OSError(
            f"insufficient free space before fixture generation: {free_bytes} < {required}"
        )

    directory.mkdir(parents=True, exist_ok=False)
    input_hash = hashlib.sha256()
    members: list[dict[str, Any]] = []
    stream = iter(_expected_chunks(case_name, total_length))
    current = memoryview(b"")
    stream_offset = 0

    for index, member_length in enumerate(lengths):
        name = f"pac6-{case_name}.{extension}{index}"
        path = directory / name
        member_hash = hashlib.sha256()
        remaining = member_length
        with path.open("xb") as output:
            while remaining:
                if not current:
                    current = memoryview(next(stream))
                    stream_offset = 0
                count = min(remaining, len(current) - stream_offset)
                chunk = current[stream_offset : stream_offset + count]
                output.write(chunk)
                member_hash.update(chunk)
                input_hash.update(chunk)
                remaining -= count
                stream_offset += count
                if stream_offset == len(current):
                    current = memoryview(b"")
                    stream_offset = 0
        if path.stat().st_size != member_length:
            raise OSError(f"fixture member length mismatch: {name}")
        members.append(
            {
                "name": name,
                "length": member_length,
                "sha256": member_hash.hexdigest(),
            }
        )

    return {
        "case": case_name,
        "extension": extension,
        "input_length": total_length,
        "input_sha256": input_hash.hexdigest(),
        "ordered_members": members,
        "storage_preflight": {
            "free_bytes": free_bytes,
            "required_bytes": required,
            "passed": free_bytes >= required if needs_space_check else True,
            "reserve_bytes": RESERVE_BYTES if needs_space_check else 0,
        },
    }


def rename_layout(directory: Path, from_extension: str, to_extension: str) -> None:
    """Rename the same fixture bytes for the other legacy member suffix."""
    source_paths = sorted(directory.glob(f"*.{from_extension}[0-9]*"))
    if not source_paths:
        raise FileNotFoundError(f"no .{from_extension}N fixture members in {directory}")
    for source in source_paths:
        stem, numbered_extension = source.name.rsplit(".", 1)
        if not numbered_extension.startswith(from_extension) or not numbered_extension[len(from_extension) :].isdigit():
            raise ValueError(f"unexpected legacy member name: {source.name}")
        target = source.with_name(
            f"{stem}.{to_extension}{numbered_extension[len(from_extension):]}"
        )
        source.rename(target)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
