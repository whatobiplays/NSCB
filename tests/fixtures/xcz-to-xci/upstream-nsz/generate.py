#!/usr/bin/env python3
"""Rebuild the upstream-compressed part of the synthetic XCZ fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zlib


NSZ_COMMIT = "148218ff89bb4b607d07730a8cf87d5e1f249ebc"
APPLICATION_KAEK = bytes.fromhex("9266aa6cfaef6a6231902a8778e6f6e6")
KEY_NAMES = (
    "aes_kek_generation_source",
    "aes_key_generation_source",
    "titlekek_source",
    "key_area_key_application_source",
    "key_area_key_ocean_source",
    "key_area_key_system_source",
    "master_key_00",
)


def synthetic_crc_key(name: str, checksum: int) -> bytes:
    prefix = hashlib.sha256(("NSCB synthetic key " + name).encode()).digest()[:12]
    baseline = zlib.crc32(prefix + bytes(4)) & 0xFFFFFFFF
    columns = []
    for bit in range(32):
        suffix = (1 << bit).to_bytes(4, "little")
        columns.append((zlib.crc32(prefix + suffix) & 0xFFFFFFFF) ^ baseline)

    rows = []
    delta = checksum ^ baseline
    for output_bit in range(32):
        coefficients = sum(
            ((columns[variable] >> output_bit) & 1) << variable
            for variable in range(32)
        )
        rows.append(coefficients | (((delta >> output_bit) & 1) << 32))

    pivots = []
    pivot_row = 0
    for variable in range(32):
        selected = next(
            row for row in range(pivot_row, 32) if (rows[row] >> variable) & 1
        )
        rows[pivot_row], rows[selected] = rows[selected], rows[pivot_row]
        for row in range(32):
            if row != pivot_row and ((rows[row] >> variable) & 1):
                rows[row] ^= rows[pivot_row]
        pivots.append(variable)
        pivot_row += 1

    solution = 0
    for row, variable in enumerate(pivots):
        solution |= ((rows[row] >> 32) & 1) << variable
    value = prefix + solution.to_bytes(4, "little")
    if zlib.crc32(value) & 0xFFFFFFFF != checksum:
        raise ValueError(f"could not construct synthetic CRC value for {name}")
    return value


def hfs_members(image: bytes, start: int) -> list[tuple[str, bytes]]:
    if image[start : start + 4] != b"HFS0":
        raise ValueError("HFS0 signature is missing")
    count = int.from_bytes(image[start + 4 : start + 8], "little")
    strings_size = int.from_bytes(image[start + 8 : start + 12], "little")
    strings_start = start + 0x10 + count * 0x40
    data_start = strings_start + strings_size
    if data_start > len(image):
        raise ValueError("HFS0 table extends beyond its container")

    members = []
    for index in range(count):
        entry = start + 0x10 + index * 0x40
        offset = int.from_bytes(image[entry : entry + 8], "little")
        length = int.from_bytes(image[entry + 8 : entry + 16], "little")
        name_offset = int.from_bytes(image[entry + 16 : entry + 20], "little")
        name_start = strings_start + name_offset
        try:
            name_end = image.index(b"\0", name_start, data_start)
        except ValueError as error:
            raise ValueError("HFS0 name is not terminated") from error
        name = image[name_start:name_end].decode("utf-8")
        member_start = data_start + offset
        member_end = member_start + length
        if member_end > len(image):
            raise ValueError(f"HFS0 member {name} exceeds its container")
        members.append((name, image[member_start:member_end]))
    return members


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_clean_upstream_checkout(upstream_root: Path) -> None:
    status = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=upstream_root,
        text=True,
    )
    if status:
        raise SystemExit("pinned NSZ checkout must be clean")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-root", type=Path, required=True)
    parser.add_argument(
        "--fixture-dir", type=Path, default=Path(__file__).resolve().parent
    )
    args = parser.parse_args()
    upstream_root = args.upstream_root.expanduser().resolve()
    fixture_dir = args.fixture_dir.expanduser().resolve()

    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=upstream_root, text=True
    ).strip()
    if commit != NSZ_COMMIT:
        raise SystemExit(f"expected NSZ {NSZ_COMMIT}, found {commit}")
    require_clean_upstream_checkout(upstream_root)

    sys.dont_write_bytecode = True
    sys.path.insert(0, str(upstream_root))
    from nsz.nut import Keys

    source_path = fixture_dir / "source.xci"
    meta_path = fixture_dir / "meta.nca"
    program_path = fixture_dir / "program.nca"
    source = source_path.read_bytes()
    source_root = int.from_bytes(source[0x130:0x138], "little")
    source_members = hfs_members(source, source_root)
    secure = next(data for name, data in source_members if name == "secure")
    source_secure_members = dict(hfs_members(secure, 0))
    if source_secure_members.get("meta.nca") != meta_path.read_bytes():
        raise SystemExit("source XCI Meta member differs from retained evidence")
    if source_secure_members.get("program.nca") != program_path.read_bytes():
        raise SystemExit("source XCI Program member differs from retained evidence")

    with tempfile.TemporaryDirectory(prefix=".upstream-nsz-", dir=fixture_dir) as temporary:
        temporary_dir = Path(temporary)
        keys_path = temporary_dir / "synthetic.keys"
        generated_keys = {
            name: synthetic_crc_key(name, Keys.crc32_checksum[name])
            for name in KEY_NAMES
        }
        generated_keys["header_key"] = bytes([0x42]) * 32
        keys_path.write_text(
            "".join(
                f"{name} = {value.hex().upper()}\n"
                for name, value in generated_keys.items()
            ),
            encoding="ascii",
        )
        if not Keys.load(str(keys_path)):
            raise SystemExit("pinned NSZ did not load the synthetic key file")
        derived = Keys.keyAreaKey(0, 0)
        if isinstance(derived, str):
            derived = bytes.fromhex(derived)
        if bytes(derived) != APPLICATION_KAEK:
            raise SystemExit("synthetic key derivation differs from the NCA evidence")

        output_dir = temporary_dir / "output"
        output_dir.mkdir()
        environment = os.environ.copy()
        existing_python_path = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            str(upstream_root)
            if not existing_python_path
            else str(upstream_root) + os.pathsep + existing_python_path
        )
        command = [
            sys.executable,
            str(upstream_root / "nsz.py"),
            "--keys",
            str(keys_path),
            "-C",
            "--solid",
            "--level",
            "1",
            "--threads",
            "1",
            "--multi",
            "1",
            "--output",
            str(output_dir),
            str(source_path),
        ]
        subprocess.run(command, cwd=upstream_root, env=environment, check=True)
        raw_output = (output_dir / "source.xcz").read_bytes()

        root_offset = int.from_bytes(raw_output[0x130:0x138], "little")
        root_count = int.from_bytes(raw_output[root_offset + 4 : root_offset + 8], "little")
        root_strings = int.from_bytes(raw_output[root_offset + 8 : root_offset + 12], "little")
        root_data = root_offset + 0x10 + root_count * 0x40 + root_strings
        declared_end = max(
            root_data
            + int.from_bytes(
                raw_output[root_offset + 0x10 + index * 0x40 : root_offset + 0x18 + index * 0x40],
                "little",
            )
            + int.from_bytes(
                raw_output[root_offset + 0x18 + index * 0x40 : root_offset + 0x20 + index * 0x40],
                "little",
            )
            for index in range(root_count)
        )
        padding_size = declared_end - len(raw_output)
        if padding_size != 410:
            raise SystemExit(f"expected 410 declared tail-padding bytes, found {padding_size}")

        raw_path = fixture_dir / "upstream-raw.xcz"
        adapted_path = fixture_dir / "upstream.xcz"
        raw_path.write_bytes(raw_output)
        adapted = raw_output + bytes(padding_size)
        adapted_path.write_bytes(adapted)

        adapted_root = int.from_bytes(adapted[0x130:0x138], "little")
        adapted_members = hfs_members(adapted, adapted_root)
        adapted_secure = next(data for name, data in adapted_members if name == "secure")
        ncz_members = [
            data for name, data in hfs_members(adapted_secure, 0) if name.endswith(".ncz")
        ]
        if len(ncz_members) != 1:
            raise SystemExit(f"expected one Program NCZ member, found {len(ncz_members)}")
        program_ncz = ncz_members[0]
        (fixture_dir / "program.ncz").write_bytes(program_ncz)

        manifest = {
            "upstream_commit": NSZ_COMMIT,
            "entry_point": "nsz.py -> nsz.main -> compress -> solidCompressXci -> processContainer",
            "settings": {
                "container": "XCI",
                "solid": True,
                "block_compression": False,
                "level": 1,
                "threads": 1,
                "multi": 1,
                "rights_free": True,
            },
            "synthetic_key_file_sha256": sha256(keys_path.read_bytes()),
            "alignment_padding_appended": padding_size,
            "artifacts": {
                name: sha256((fixture_dir / name).read_bytes())
                for name in (
                    "source.xci",
                    "meta.nca",
                    "program.nca",
                    "program.ncz",
                    "upstream-raw.xcz",
                    "upstream.xcz",
                )
            },
        }
        print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
