# Canonical FAT32 Split qualification

**Status:** Host evidence and physical FAT32/Horizon evidence are recorded separately. Owner authorization is in place, but physical work remains `NOT RUN` until the exact FAT32 medium, Windows host, and Switch are identified and recorded.

The procedure records four distinct claims:

1. **Manifest consistency:** the transferred members match the supplied manifest.
2. **Source-backed completeness:** evidence from the original source establishes its byte length and SHA-256.
3. **Archive finalization:** the selected inner directory's archive bit was set and read back, or an external finalization step remains.
4. **Consumer interoperability:** Horizon opened the directory as one logical file and read the expected byte stream.

The finalizer establishes manifest consistency and reports archive-attribute state. It does not issue a trust receipt or establish source-backed completeness or Horizon compatibility. A missing archive bit does not invalidate a separately proven byte stream. A matching byte stream does not establish that Horizon accepts the directory as a logical file.

The evidence boundary remains the accidental-loss and corruption model in [ADR 0028](../adr/0028-evidence-backed-split-set-qualification.md). The adjacent manifest is a portable consistency declaration, and the host-retained receipt remains the local trust anchor for source evidence. Neither is presented as cryptographic origin authentication or as protection against intentional changes to host-controlled state. Finalization does not issue, replace, or export a receipt.

## PAC and TAC mapping

| PAC | Requirement | TACs | Acceptance evidence |
| --- | --- | --- | --- |
| PAC-1 | Produce a complete, deterministic, FAT32-compatible canonical Split set. | TAC-2, TAC-4 | Production-profile regressions and recorded source, segment, and reconstructed-stream measurements. |
| PAC-2 | Qualify transfer of the Split set to FAT32 storage. | TAC-1, TAC-4, TAC-7 | Ordinary file-copy procedure, exact destination inventory, matching hashes, and an interrupted-copy failure check. |
| PAC-3 | Finalize the archive bit with a native facility where supported, or a documented external step. | TAC-3, TAC-12, TAC-13 | Targeted mutation or Goldleaf action, followed by independent readback. |
| PAC-4 | Verify canonical consumer interoperability independently. | TAC-5 | Horizon reports the expected logical-file length and SHA-256. |
| PAC-5 | Preserve publication safety and trust guarantees. | TAC-6, TAC-8, TAC-9, TAC-12 | APFS and receipt regressions, identity checks, preserved unrelated entries, and no receipt issuance during finalization. |
| PAC-6 | State which platform paths are supported, externally finalized, or unqualified. | TAC-10, TAC-11 | This support matrix and a revision-bound record of compile, host, and physical evidence. |

| TAC | Qualification requirement |
| --- | --- |
| TAC-1 | Transfer through ordinary filesystem APIs. Do not write raw volume data, unmount or remount storage automatically, or run the producer against FAT32. |
| TAC-2 | Use production segments of at most `0xFFFF0000` bytes. Every nonfinal segment has that size, the final segment is nonempty and no larger, names are contiguous `00`–`99`, and the set has at most 100 members. |
| TAC-3 | Read the selected directory's attributes, add only the archive bit, preserve other bits, and read the result back. Attribute errors retain a verified manifest-consistency result; source-backed completeness and consumer interoperability remain unestablished. |
| TAC-4 | Complete a FAT32 round trip using a source larger than one production segment. Record source and reconstructed lengths and SHA-256, plus each segment's order, length, and SHA-256. |
| TAC-5 | Open the selected directory through Horizon as one logical file and match the source length and SHA-256. |
| TAC-6 | Preserve the current APFS publication behavior and truthful terminal states. Do not rewrite the Windows or Linux publication backend for attribute finalization. |
| TAC-7 | An incomplete transfer or failed consumer read never earns a success claim. Keep failed output for inspection and report transfer, finalization, and consumer results separately. |
| TAC-8 | Preserve unrelated files and attributes. Finalization is limited to the selected inner directory. Do not recurse into other directories or remove unexpected entries. |
| TAC-9 | Keep local trust-receipt requirements unchanged. The finalization command neither creates nor replaces a receipt. |
| TAC-10 | Identify platform capabilities accurately. Mark unavailable toolchains, compile-only results, host results, and physical results separately. |
| TAC-11 | Qualify canonical numbered directories only. Legacy `.xcN` and `.nsN` layouts remain reserved for Slice C. |
| TAC-12 | Bind the explicitly selected directory to an opened identity before manifest verification. Reject a selected symlink or reparse-point alias, retain the handle through finalization, and check both the selected path and verified path for observed displacement. |
| TAC-13 | After Goldleaf finalization, inspect the archive bit through a separate read-only host API call. Record the selected directory and unrelated sentinel masks before and after the action. |

## Current PAC and TAC disposition

| ID | Disposition on 2026-11-25 | Evidence and remaining work |
| --- | --- | --- |
| PAC-1 | PASS for APFS set structure | The deterministic 4 GiB source, canonical members, manifest, and reconstructed stream match recorded measurements. FAT32 transfer is tracked separately under PAC-2. |
| PAC-2 | NOT QUALIFIED | The ordinary-filesystem transfer recipe and APFS copy simulation are recorded. No FAT32 transfer has run. |
| PAC-3 | PARTIAL | The Windows harness calls the actual NSCB CLI and checks both results, independent readback, sentinels, and receipt state. PowerShell, Windows native finalization, Goldleaf, and post-Goldleaf readback have not run. |
| PAC-4 | NOT QUALIFIED | The primary and corruption-control NROs embed the expected source digest. Horizon has not consumed either file. |
| PAC-5 | PARTIAL | Repository-native validation passes and receipt requirements remain intact. Physical preservation checks have not run. |
| PAC-6 | PASS for documented boundaries | macOS external finalization, the Windows native candidate, unqualified Linux support, and separate direct-publication qualification are identified. |
| TAC-1 | NOT QUALIFIED | The ordinary-filesystem recipe is ready; transfer to FAT32 has not run. |
| TAC-2 | PASS | The canonical fixture has contiguous `00` and `01` members within the production size limit; its source, segment, manifest, and reconstructed hashes were reverified. |
| TAC-3 | PARTIAL | CLI and harness checks cover targeted setting and readback. Windows execution, Goldleaf, and independent post-Goldleaf inspection remain pending. |
| TAC-4 | NOT QUALIFIED | APFS measurements pass. The required FAT32 round trip has not run. |
| TAC-5 | NOT RUN | The NRO is built; no Switch runtime readback has occurred. |
| TAC-6 | PASS for host behavior | The full repository validation passes. APFS publication behavior remains in the regression suite, and no Windows or Linux publication backend rewrite was added. |
| TAC-7 | PARTIAL | A control-specific NRO and deterministic corrupted-stream digest are recorded. Physical incomplete-transfer and corrupted-segment runs remain pending. |
| TAC-8 | PARTIAL | The Windows harness checks unrelated sentinel attributes and contents. Its Windows run and the physical preservation checks have not occurred. |
| TAC-9 | PASS for host behavior | Finalization keeps source-backed completeness and consumer interoperability unestablished and does not issue a trust receipt. The producer's local receipt remains in the APFS fixture. |
| TAC-10 | PASS | The platform matrix distinguishes built, externally finalized, and unqualified paths. Container package versions and the NRO hash are recorded above. |
| TAC-11 | PASS | This slice covers canonical numbered directories. Legacy `.xcN` and `.nsN` layouts remain reserved for Slice C. |
| TAC-12 | PASS for host behavior | Selected-directory identity and observed-displacement regressions pass in repository validation. |
| TAC-13 | NOT RUN | Goldleaf finalization and the separate read-only Windows attribute inspection remain pending. |

## Platform support

| Platform | Finalization path | Evidence boundary |
| --- | --- | --- |
| macOS | Keep production on APFS, copy the completed bundle to FAT32, then use Goldleaf on the selected inner directory. The host command reports `external_finalization_required`. | The workflow is documented. The Goldleaf action, FAT32 result, and Horizon readback remain unqualified until the physical procedure passes. |
| Windows | The native candidate identifies the mounted filesystem as FAT32, adds the archive bit with `SetFileAttributesW`, and verifies it with `GetFileAttributesW`. Other filesystems return `unsupported_filesystem`. | The pinned Rust 1.98.1 Windows GNU check passes when Cargo is given that toolchain's `rustc` explicitly through `RUSTC`. Invoking the Cargo shim without that override reported a missing `core` crate even though the target component is installed. The MSVC check is blocked because the available Xcode compiler lacks the target `stdlib.h`/MSVC runtime headers. The separate native-finalization procedure is prepared but has not run. Windows behavior remains unqualified pending the physical test. |
| Linux | The mounted-filesystem `FAT_IOCTL_GET_ATTRIBUTES` and `FAT_IOCTL_SET_ATTRIBUTES` API is the candidate for a future qualified path. | The x86_64 GNU target check passes. The AArch64 check is blocked because `aarch64-linux-gnu-gcc` is unavailable for the `ring` build. No Linux attribute backend is claimed; filesystem identification and API behavior remain unqualified, and this slice does not rewrite the Linux publication backend. |
| Other hosts | No native finalizer is claimed. | Unqualified. |
| Direct FAT32 publication | Outside the transfer workflow. | Separate qualification obligation. |

Goldleaf's current Explorer exposes a directory operation for setting or clearing the archive bit. Its selected-item handler passes the selected path to `SetArchiveBit`, which calls libnx's `fsdevSetConcatenationFileAttribute` for that path. The procedure below uses the set action on the canonical inner directory only. Goldleaf does not provide the independent readback required for acceptance, so the procedure checks the bit separately on Windows after Goldleaf exits.

## Host qualification status

- Repository-native `make all` is the final host regression gate. The latest result, coverage report, and CI run are recorded on PR #92; earlier failed or cancelled runs remain historical evidence.
- Coverage.py 7.17.5 ran the three offset-dependent generator tests and seven Windows-harness source checks: 10 tests passed. Branch coverage was 51% for the generator, 96% for the harness test module, and 92% for the generator test module. This report covers Python code; PowerShell execution remains untested on this Mac.
- Windows GNU and Linux x86_64 cross-target checks are compile evidence only. Windows MSVC and Linux AArch64 limitations remain as listed in the platform matrix.
- The finalizer checks the manifest, exact inner-directory inventory, segment hashes, and production segment profile. It does not consult or create a source receipt.
- The Split finalization CLI rejects unknown dash-prefixed arguments as usage errors. Its subprocess regression checks exit code 2 and the usage response.
- The Horizon checker uses the pinned libnx signed-size and Npad APIs with a fixed 64 KiB static read buffer. Its Makefile follows the official application template for source discovery, dependency files, NRO and NACP outputs, and library search paths. It links `-lmbedcrypto -lnx`. Changes to the generated path, length, or digest header rebuild the checker object, ELF, and NRO.
- The offset-dependent production-boundary fixture was rehashed on 2026-11-25. The source and reconstructed stream are 4,294,967,296 bytes with SHA-256 `49d348020480cca3fd51331db42ac1ef3b0377ccdea296f54c629346be78fe94`. Segment `00` is 4,294,901,760 bytes with SHA-256 `7aceda50e41813a6f1ee4e29b214f4f362ee424e88e284fe27fbaeb4b757b33d`; segment `01` is 65,536 bytes with SHA-256 `eb132cd4f23c648973f9e383c4aff2b1344ad681cd1576076ca7353259fe52ed`. The 526-byte manifest hashes to `17436697a5ecc0c35961bccef815f41bdd7f06a55e8a0b30f39d989bf6f263e3`. The verification record is `target/issue-14-slice-b-qualification-offset-v2/validation/final-qualification-fixture-20261125.json`.
- The primary checker NRO was built on 2026-11-25 in the disposable Linux arm64 image `devkitpro/devkita64:20260219`, resolved to digest `sha256:1fc388c3a0d34bd2045a6dadcb1020e069d5f876a187fd705de14b4440c00282`. It is 212,992 bytes with SHA-256 `6e3f8eaa3e39ad307fb24faee8390706007c58410d54d7298ffca3c315c75776` and embeds `/nscb-qualification/qualification-source.nsp` plus the expected 4 GiB source digest.
- The corruption-control NRO uses a separate build directory and embeds `/nscb-qualification-negative-corrupt/qualification-source.nsp` while retaining the original expected length and digest. It is 212,992 bytes with SHA-256 `c764083d84a06a948cee9e7c47246ebd6defe5eccdff320b23426d2d140aedcf`. Both NRO builds used devkitA64 `r29.2-1`, libnx `4.12.0-1`, switch-mbedtls `2.28.10-1`, switch-zlib `1.3.1-1`, devkita64-gcc `15.2.0-7`, devkita64-binutils `2.45.1-2`, and devkita64-rules `1.1.1-1`. The package command confirmed switch-mbedtls and switch-zlib were already current. Only the dedicated `container-build-final` and `container-build-negative-corrupt` directories were mounted writable; the repository root was not mounted. The native macOS devkitPro installation was not changed.
- The NRO is 212,992 bytes with SHA-256 `6e3f8eaa3e39ad307fb24faee8390706007c58410d54d7298ffca3c315c75776`. The build verified that the binary contains the expected offset-dependent fixture digest. The build record, package log, source copies, and NRO are under `target/issue-14-slice-b-qualification-offset-v2/container-build-final`. The build establishes the NRO artifact; Horizon execution remains pending.
- The Windows harness invokes the candidate `nscb.exe` twice and checks the `set` and `already_set` results, independent attribute readback, sentinel preservation, and absence of a trust store under an isolated `NSCB_STATE_DIR`. It records the executable's SHA-256 and requires source-backed completeness and consumer interoperability to remain unestablished. Seven focused Python checks pass. PowerShell is unavailable on this Mac, so the Windows harness has not run on Windows.
- Physical FAT32 transfer, Goldleaf finalization, post-Goldleaf attribute readback, Windows native finalization, Horizon consumption, and physical negative controls remain `NOT RUN`. Exact target identities are pending. No physical medium or Switch has been accessed.

The earlier repeating-pattern fixture remains historical evidence at `target/issue-14-slice-b-qualification/fixture-measurements.json`; that file was not overwritten. Its 4,294,967,296-byte source and reconstructed stream hash to `1bdb600eb7d29d0a1013ea5de3707f3416664ca922313166529aec32faccc72b`. Its `00` segment is 4,294,901,760 bytes with SHA-256 `af6eadf3a6fb419bab3be5398ed6acd2e4d880dedac720f05eb67701cc6e3a8a`; `01` is 65,536 bytes with SHA-256 `d8f32a3b4c195f65444e342b0c61bdaf114802e84ab7821a1f88e3f66ea15100`. Its 526-byte manifest hashes to `b36dce16871bcd8fb9416e01e5ed0a8b58a1ddd16ebdd60959b7a4a8253c05a1`. The APFS copy simulation matched the inventory and hashes. Its macOS finalizer result was exit 8 with verified manifest consistency and external finalization required. Those measurements predate the offset-dependent generator and do not qualify FAT32.

The fresh offset-dependent fixture is recorded in `target/issue-14-slice-b-qualification-offset-v2/transfer-measurements.json`. Its source and reconstructed stream are 4,294,967,296 bytes with SHA-256 `49d348020480cca3fd51331db42ac1ef3b0377ccdea296f54c629346be78fe94`. Segment `00` is 4,294,901,760 bytes with SHA-256 `7aceda50e41813a6f1ee4e29b214f4f362ee424e88e284fe27fbaeb4b757b33d`; `01` is 65,536 bytes with SHA-256 `eb132cd4f23c648973f9e383c4aff2b1344ad681cd1576076ca7353259fe52ed`. The 526-byte manifest hashes to `17436697a5ecc0c35961bccef815f41bdd7f06a55a8e0b30f39d989bf6f263e3`, and the isolated local receipt is issued for it. The host finalizer exited 8 with manifest consistency verified, archive readback unavailable, external finalization required, and source-backed completeness and consumer interoperability not established. An ordinary `shutil.copyfile` APFS simulation reproduced the exact inventory and hashes. It does not establish FAT32 transfer or Horizon compatibility.

## Reproducible APFS fixture

The generator creates deterministic 64 KiB blocks from a domain tag and each block's absolute byte offset. Equal offsets repeat; different offsets produce different block digests, including offsets aligned to the block size. The 4 GiB source is `0x100000000` bytes, just over one production segment. NSCB should produce two physical parts: `00` at `0xFFFF0000` bytes and `01` at `0x10000` bytes.

Use a new ignored worktree path under `target/`; do not reuse or remove an existing fixture. Keep the source, bundle, isolated application data, and recorded measurements on APFS. The offset-dependent run in this worktree uses `target/issue-14-slice-b-qualification-offset-v2/` and leaves the earlier fixture directory untouched.

```sh
mkdir target/issue-14-slice-b-qualification-offset-v2
mkdir target/issue-14-slice-b-qualification-offset-v2/home
python3 -B scripts/generate_split_qualification_source.py \
  target/issue-14-slice-b-qualification-offset-v2/qualification-source.nsp \
  > target/issue-14-slice-b-qualification-offset-v2/source-generator.json
```

Run the ordinary producer against the APFS bundle path. Keep the application data and source receipt inside the disposable fixture root:

```sh
rustup run 1.98.1 cargo build --locked --release \
  --features standalone-job-history --bin nscb

HOME="$PWD/target/issue-14-slice-b-qualification-offset-v2/home" \
USERPROFILE="$PWD/target/issue-14-slice-b-qualification-offset-v2/home" \
XDG_CONFIG_HOME="$PWD/target/issue-14-slice-b-qualification-offset-v2/home/.config" \
  target/release/nscb split \
  "$PWD/target/issue-14-slice-b-qualification-offset-v2/qualification-source.nsp" \
  "$PWD/target/issue-14-slice-b-qualification-offset-v2/qualification-source.bundle" \
  --json
```

The bundle contains `qualification-source.nsp/00`, `qualification-source.nsp/01`, and the sibling manifest `qualification-source.nsp.nscb-split.json`. Record the generator's source length and SHA-256, the manifest hash, and the receipt state. The producer must use the normal source-backed path and write its local receipt; do not substitute a hand-built manifest or bypass the receipt contract.

## Ordinary-filesystem FAT32 transfer

The copy recipe below transfers only the manifest and the two named segment files. It creates the canonical directory with no Finder metadata, AppleDouble files, or other unexpected members. It refuses an unexpected source entry and refuses to overwrite an existing destination.

Set `APFS_BUNDLE` and `FAT32_ROOT` to the verified mounted paths. Use an empty destination directory on the mounted FAT32 volume.

```sh
APFS_BUNDLE="/Volumes/NSCB_APFS/NSCB-qualification/qualification-source.bundle" \
FAT32_ROOT="/Volumes/NSCB_FAT32/nscb-qualification" \
python3 - <<'PY'
from pathlib import Path
import os
import shutil

bundle = Path(os.environ["APFS_BUNDLE"])
destination = Path(os.environ["FAT32_ROOT"])
name = "qualification-source.nsp"
members = ("00", "01")
source_inner = bundle / name
manifest = bundle / f"{name}.nscb-split.json"

entries = list(source_inner.iterdir())
if {entry.name for entry in entries} != set(members):
    raise SystemExit("source canonical directory has unexpected members")
if any(entry.is_symlink() or not entry.is_file() for entry in entries):
    raise SystemExit("source canonical directory contains a non-regular member")
if manifest.is_symlink() or not manifest.is_file():
    raise SystemExit("source manifest is missing or not a regular file")

destination.mkdir(parents=True, exist_ok=False)
target_inner = destination / name
target_inner.mkdir()
shutil.copyfile(manifest, destination / manifest.name)
for member in members:
    shutil.copyfile(source_inner / member, target_inner / member)

print(f"manifest={destination / manifest.name}")
print(f"inner_directory={target_inner}")
print(f"members={','.join(members)}")
PY
```

`shutil.copyfile` copies file contents through ordinary filesystem calls without copying extended attributes or directory metadata. Do not use Finder to copy into the canonical directory. Keep unrelated sentinel files outside it.

Run the following measurement on the APFS source and the FAT32 destination before finalization. It checks exact member names, segment sizes and order, each segment hash, and the reconstructed destination stream against the original source.

```sh
SOURCE="/Volumes/NSCB_APFS/NSCB-qualification/qualification-source.nsp" \
FAT32_INNER="/Volumes/NSCB_FAT32/nscb-qualification/qualification-source.nsp" \
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

source = Path(os.environ["SOURCE"])
inner = Path(os.environ["FAT32_INNER"])
expected = ("00", "01")
limit = 0xFFFF0000
entries = list(inner.iterdir())
if {entry.name for entry in entries} != set(expected):
    raise SystemExit("destination canonical directory has unexpected members")
if any(entry.is_symlink() or not entry.is_file() for entry in entries):
    raise SystemExit("destination canonical directory contains a non-regular member")

def measure(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()

source_size, source_hash = measure(source)
logical_hash = hashlib.sha256()
segments = []
logical_size = 0
for index, name in enumerate(expected):
    path = inner / name
    size, digest = measure(path)
    if index == 0 and size != limit:
        raise SystemExit("first segment does not match the production boundary")
    if index == 1 and size != 0x10000:
        raise SystemExit("final segment does not match the fixture length")
    segments.append({"name": name, "bytes": size, "sha256": digest})
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            logical_size += len(chunk)
            logical_hash.update(chunk)

result = {
    "source": {"bytes": source_size, "sha256": source_hash},
    "segments": segments,
    "reconstructed": {
        "bytes": logical_size,
        "sha256": logical_hash.hexdigest(),
    },
}
if source_size != logical_size or source_hash != logical_hash.hexdigest():
    raise SystemExit("reconstructed destination stream differs from source")
print(json.dumps(result, sort_keys=True, indent=2))
PY
```

Keep the full JSON output for the APFS source bundle and FAT32 destination. The source and reconstructed lengths must be `4294967296`; their SHA-256 values must match. Record the two segment hashes in numeric order.

Run `nscb finalize-split-set <FAT32_INNER> --json` from the host. On macOS, expect `manifest_consistency=verified`, `archive_attribute=external_finalization_required`, and `consumer_interoperability=not_established`; exit status 8 reports that external finalization remains. The command validates the destination inventory and manifest. It does not set the archive bit on macOS. A missing archive bit does not undo the byte-stream measurements.

## Physical FAT32 and Horizon procedure

Before any physical step, ask the owner to identify the disposable FAT32 medium (model, capacity, volume label, and volume serial), Windows host (computer name, edition, version, and build), and Switch (model and firmware), and provide the Goldleaf release or commit. Record the selected drive or mount path with those identities. Stop if a connected device does not match. Do not format media, write raw sectors, automatically unmount or remount storage, modify unrelated data, or publish directly to FAT32.

The PowerShell examples use drive `E:`. Replace it with the identified volume's drive letter.
The Windows host must provide PowerShell and Python 3 available as `python3` for the control-copy measurements.

Use the offset-dependent fixture described above. Keep its source, bundle, manifest, segments, local receipt, and measurements on APFS. The exact source and reconstructed stream are 4,294,967,296 bytes with SHA-256 `49d348020480cca3fd51331db42ac1ef3b0377ccdea296f54c629346be78fe94`. Segment `00` is 4,294,901,760 bytes with SHA-256 `7aceda50e41813a6f1ee4e29b214f4f362ee424e88e284fe27fbaeb4b757b33d`; segment `01` is 65,536 bytes with SHA-256 `eb132cd4f23c648973f9e383c4aff2b1344ad681cd1576076ca7353259fe52ed`. The manifest is 526 bytes with SHA-256 `17436697a5ecc0c35961bccef815f41bdd7f06a55e8a0b30f39d989bf6f263e3`.

1. Confirm the recorded target identities and at least 17 GiB of free FAT32 space. Do not format or erase the medium. Leave existing entries untouched and create the four qualification directories `nscb-qualification`, `nscb-qualification-windows-native`, `nscb-qualification-negative-incomplete`, and `nscb-qualification-negative-corrupt`.
2. Use the ordinary-filesystem recipe above to transfer the manifest and both segments to the Goldleaf, Windows-native, and corruption-control directories. Their inner paths are `/nscb-qualification/qualification-source.nsp`, `/nscb-qualification-windows-native/qualification-source.nsp`, and `/nscb-qualification-negative-corrupt/qualification-source.nsp`. Each complete set contains only `00` and `01`; its outer directory contains `qualification-source.nsp.nscb-split.json`. Run the source and destination measurement on the Goldleaf and Windows-native copies before finalization.

   Create the incomplete control with the original manifest and segment `00`, leaving `01` absent. Use the source bundle and ordinary file operations:

   ```sh
   APFS_BUNDLE="/Volumes/NSCB_APFS/NSCB-qualification/qualification-source.bundle" \
   FAT32_ROOT="/Volumes/NSCB_FAT32/nscb-qualification-negative-incomplete" \
   python3 - <<'PY'
   from pathlib import Path
   import os
   import shutil

   bundle = Path(os.environ["APFS_BUNDLE"])
   destination = Path(os.environ["FAT32_ROOT"])
   name = "qualification-source.nsp"
   source_inner = bundle / name
   target_inner = destination / name
   destination.mkdir(parents=True, exist_ok=False)
   target_inner.mkdir()
   shutil.copyfile(source_inner / "00", target_inner / "00")
   shutil.copyfile(bundle / f"{name}.nscb-split.json", destination / f"{name}.nscb-split.json")
   PY
   ```

   The expected incomplete paths are `/nscb-qualification-negative-incomplete/qualification-source.nsp/00` and `/nscb-qualification-negative-incomplete/qualification-source.nsp.nscb-split.json`; segment `01` must be absent. Start the corruption control as a byte-identical complete copy. Change one byte at offset 4096 of its `00` segment with ordinary file I/O:

   ```powershell
   $segment = 'E:\nscb-qualification-negative-corrupt\qualification-source.nsp\00'
   $stream = [IO.File]::Open($segment, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
   try {
       $stream.Position = 4096
       $originalByte = $stream.ReadByte()
       if ($originalByte -lt 0) { throw 'Segment 00 is shorter than the corruption offset.' }
       $stream.Position = 4096
       $stream.WriteByte([byte]($originalByte -bxor 1))
       $stream.Flush($true)
   }
   finally {
       $stream.Dispose()
   }
   Get-Item -LiteralPath $segment | Select-Object FullName, Length
   Get-FileHash -LiteralPath $segment -Algorithm SHA256
   ```

   Segment `00` must remain 4,294,901,760 bytes and hash to `2cdae65b6d7638492f258471e73f8a588ea98b71d75e25c56a540baa17daacbe`. Keep segment `01` and the manifest unchanged. The corrupted logical stream is 4,294,967,296 bytes with SHA-256 `ee5de9ad6adec54be7a780a60005f9c956b7f6676e83be438f489c42152b9510`. The expected values and their derivation are recorded in `target/issue-14-slice-b-qualification-offset-v2/validation/corruption-control-measurement-20261125.json`.

   Measure the corruption copy through ordinary file reads and save the JSON result. This confirms the physical copy has the recorded sizes and altered logical hash before Horizon reads it.

   ```powershell
   $env:CONTROL_INNER = 'E:\nscb-qualification-negative-corrupt\qualification-source.nsp'
   $python = @'
   import hashlib
   import json
   import os
   from pathlib import Path

   inner = Path(os.environ['CONTROL_INNER'])
   names = ('00', '01')
   if {entry.name for entry in inner.iterdir()} != set(names):
       raise SystemExit('corruption control has an unexpected directory inventory')

   logical = hashlib.sha256()
   total = 0
   segments = []
   for name in names:
       path = inner / name
       digest = hashlib.sha256()
       size = 0
       with path.open('rb') as stream:
           while chunk := stream.read(1024 * 1024):
               size += len(chunk)
               digest.update(chunk)
               logical.update(chunk)
       segments.append({'name': name, 'bytes': size, 'sha256': digest.hexdigest()})
       total += size

   result = {'segments': segments, 'logical_bytes': total, 'logical_sha256': logical.hexdigest()}
   print(json.dumps(result, sort_keys=True, indent=2))
   if total != 4294967296 or logical.hexdigest() != 'ee5de9ad6adec54be7a780a60005f9c956b7f6676e83be438f489c42152b9510':
       raise SystemExit('corruption control differs from the prepared one-byte mutation')
   '@
   $python | python3 -
   ```
3. Build and identify the checker before copying it to the medium. The verified build used a single writable mount for the dedicated qualification build directory and did not mount the repository:

   ```sh
   BUILD_DIR="$PWD/target/issue-14-slice-b-qualification-offset-v2/container-build-final"
   mkdir -p "$BUILD_DIR/source"
   cp tests/horizon/split_readback/Makefile "$BUILD_DIR/Makefile"
   cp tests/horizon/split_readback/source/main.c "$BUILD_DIR/source/main.c"
   docker run --rm --platform linux/arm64 \
     --mount "type=bind,source=$BUILD_DIR,target=/work" \
     --workdir /work devkitpro/devkita64@sha256:1fc388c3a0d34bd2045a6dadcb1020e069d5f876a187fd705de14b4440c00282 \
     /bin/sh -c '
       set -eu
       export DEVKITPRO=/opt/devkitpro
       dkp-pacman -Sy --needed --noconfirm switch-mbedtls switch-zlib
       dkp-pacman -Q devkitA64 libnx switch-mbedtls switch-zlib devkita64-gcc devkita64-binutils devkita64-rules
       make all SPLIT_PATH=/nscb-qualification/qualification-source.nsp EXPECTED_SIZE=4294967296 EXPECTED_SHA256=49d348020480cca3fd51331db42ac1ef3b0377ccdea296f54c629346be78fe94
       grep -aF /nscb-qualification/qualification-source.nsp nscb_split_readback.nro >/dev/null
       grep -aF 49d348020480cca3fd51331db42ac1ef3b0377ccdea296f54c629346be78fe94 nscb_split_readback.nro >/dev/null
       sha256sum nscb_split_readback.nro
     '
   ```

   Record the image digest, package output, build log, NRO size, and NRO hash. For the qualified build in this worktree, the image digest was `sha256:1fc388c3a0d34bd2045a6dadcb1020e069d5f876a187fd705de14b4440c00282`; the NRO hash was `6e3f8eaa3e39ad307fb24faee8390706007c58410d54d7298ffca3c315c75776`. Copy the NRO to `/switch/nscb_split_readback.nro` on the FAT32 volume and verify the copied file hash before continuing.
   Build a second NRO for the corruption control. Use a different writable build directory, keep the expected source length and digest, and set the embedded path to the corrupted copy:

   ```sh
   CONTROL_BUILD_DIR="$PWD/target/issue-14-slice-b-qualification-offset-v2/container-build-negative-corrupt"
   mkdir -p "$CONTROL_BUILD_DIR/source"
   cp tests/horizon/split_readback/Makefile "$CONTROL_BUILD_DIR/Makefile"
   cp tests/horizon/split_readback/source/main.c "$CONTROL_BUILD_DIR/source/main.c"
   docker run --rm --platform linux/arm64 \
     --mount "type=bind,source=$CONTROL_BUILD_DIR,target=/work" \
     --workdir /work devkitpro/devkita64@sha256:1fc388c3a0d34bd2045a6dadcb1020e069d5f876a187fd705de14b4440c00282 \
     /bin/sh -c '
       set -eu
       export DEVKITPRO=/opt/devkitpro
       dkp-pacman -Sy --needed --noconfirm switch-mbedtls switch-zlib
       dkp-pacman -Q devkitA64 libnx switch-mbedtls switch-zlib devkita64-gcc devkita64-binutils devkita64-rules
       make BUILD=build-negative-corrupt all SPLIT_PATH=/nscb-qualification-negative-corrupt/qualification-source.nsp EXPECTED_SIZE=4294967296 EXPECTED_SHA256=49d348020480cca3fd51331db42ac1ef3b0377ccdea296f54c629346be78fe94
       grep -aF /nscb-qualification-negative-corrupt/qualification-source.nsp nscb_split_readback.nro >/dev/null
       grep -aF 49d348020480cca3fd51331db42ac1ef3b0377ccdea296f54c629346be78fe94 nscb_split_readback.nro >/dev/null
       cp nscb_split_readback.nro nscb_split_readback_negative_corrupt.nro
       sha256sum nscb_split_readback_negative_corrupt.nro
     '
   ```

   The control NRO built to 212,992 bytes with SHA-256 `c764083d84a06a948cee9e7c47246ebd6defe5eccdff320b23426d2d140aedcf`. Copy it to `/switch/nscb_split_readback_negative_corrupt.nro` and verify the copied hash. The primary NRO and control NRO must each embed their own logical path and the original source digest.
4. On Windows, create `unrelated` and `unrelated\sentinel.bin` beside the canonical directory in both Goldleaf roots. Record each sentinel's attributes, file length, and SHA-256. In the Windows-native root, create `preservation-sentinel.bin` and an empty `preservation-sentinel-directory` for the harness. Set Archive clear on the Goldleaf and corruption-control inner directories. Run the read-only attribute inspection below and save the baseline. Run the separate Windows native-finalization test on `nscb-qualification-windows-native` as described below; it prepares Archive clear and Hidden set on that target. Safely eject the volume before inserting it into the Switch.

   ```powershell
   $goldleafRoots = @(
       'E:\nscb-qualification',
       'E:\nscb-qualification-negative-corrupt'
   )
   foreach ($root in $goldleafRoots) {
       $unrelated = Join-Path $root 'unrelated'
       New-Item -ItemType Directory -Path $unrelated | Out-Null
       [IO.File]::WriteAllBytes(
           (Join-Path $unrelated 'sentinel.bin'),
           [Text.Encoding]::UTF8.GetBytes("NSCB Goldleaf sentinel`n")
       )
   }
   attrib -a 'E:\nscb-qualification\qualification-source.nsp'
   attrib -a 'E:\nscb-qualification-negative-corrupt\qualification-source.nsp'
   ```
5. In Goldleaf Explorer, set Archive on `/nscb-qualification/qualification-source.nsp` and `/nscb-qualification-negative-corrupt/qualification-source.nsp`. Confirm each selected path. Do not select either outer directory or use a recursive action.
6. Shut down the Switch and return the medium to the identified Windows host. Run the read-only attribute inspection before Horizon testing. Both Goldleaf-selected directories must show Archive set, and all their other bits must match the baseline. The Windows-native directory must retain its successful finalizer result. Sentinel masks, contents, and hashes must match their baselines. Safely eject the volume before returning it to the Switch.
7. Launch `/switch/nscb_split_readback.nro`. Expected output:

   ```text
   INTEROP_PASS bytes=4294967296 sha256=49d348020480cca3fd51331db42ac1ef3b0377ccdea296f54c629346be78fe94 path=/nscb-qualification/qualification-source.nsp
   HORIZON_READBACK=PASS
   ```

   Save the full screen output. Any open, size, read, or digest failure must end with `HORIZON_READBACK=FAIL`.
8. Launch `/switch/nscb_split_readback_negative_corrupt.nro`. It must read `/nscb-qualification-negative-corrupt/qualification-source.nsp` and report the precomputed corrupted-stream digest:

   ```text
   INTEROP_FAIL reason=sha256_mismatch expected=49d348020480cca3fd51331db42ac1ef3b0377ccdea296f54c629346be78fe94 actual=ee5de9ad6adec54be7a780a60005f9c956b7f6676e83be438f489c42152b9510
   HORIZON_READBACK=FAIL
   ```

   The output must not contain `INTEROP_PASS`. Keep the full screen output.
9. Shut down the Switch and return the medium to Windows. Run the read-only attribute inspection again. Confirm the selected directory and sentinel masks did not change during Horizon reads. Re-run source, destination, segment, and manifest measurements. The main copy must still match the APFS source; the corruption copy must match its recorded altered segment and logical-stream hashes. Confirm the APFS bundle and local receipt remain unchanged.
10. Run the host finalizer on the incomplete copy. It must exit nonzero with `split_finalization.error` and `invalid_split_set`; it must not claim source-backed completeness or consumer interoperability. Keep its output and the incomplete-copy inventory.

   ```powershell
   $nscb = 'C:\path\to\candidate\nscb.exe'
   $output = & $nscb finalize-split-set 'E:\nscb-qualification-negative-incomplete\qualification-source.nsp' --json
   $exitCode = $LASTEXITCODE
   $output
   "exit_code=$exitCode"
   if ($exitCode -eq 0) { throw 'Incomplete control unexpectedly passed finalization.' }
   ```
11. Record each PAC and TAC result separately. Missing target identities, an unavailable Windows run, a failed transfer, a failed attribute readback, or a failed Horizon readback leaves the corresponding qualification unestablished.

### Read-only archive-attribute inspection after Goldleaf

Run this in PowerShell on the identified Windows host. Save a baseline before any attribute changes, run it after Goldleaf and before Horizon testing, then run it again after Horizon reads. Replace the drive letter if needed. The script calls `GetFileAttributesW` and does not change attributes.

```powershell
if (-not ('Fat32AttributeReader' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

public static class Fat32AttributeReader
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFileAttributesW(string path);
}
'@
}

$paths = @(
    'E:\nscb-qualification\qualification-source.nsp',
    'E:\nscb-qualification-negative-corrupt\qualification-source.nsp',
    'E:\nscb-qualification-windows-native\qualification-source.nsp',
    'E:\nscb-qualification\unrelated',
    'E:\nscb-qualification\unrelated\sentinel.bin',
    'E:\nscb-qualification-negative-corrupt\unrelated',
    'E:\nscb-qualification-negative-corrupt\unrelated\sentinel.bin',
    'E:\nscb-qualification-windows-native\preservation-sentinel.bin',
    'E:\nscb-qualification-windows-native\preservation-sentinel-directory'
)

foreach ($path in $paths) {
    [uint32]$attributes = [Fat32AttributeReader]::GetFileAttributesW($path)
    if ($attributes -eq [uint32]::MaxValue) {
        throw "GetFileAttributesW failed for $path; Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    [pscustomobject]@{
        Path       = $path
        Mask       = ('0x{0:X8}' -f $attributes)
        ArchiveBit = (($attributes -band 0x20) -ne 0)
    }
}
```

Save all three outputs. After Goldleaf, the main and corruption-control inner directories must show `ArchiveBit = True`, with all other bits unchanged from baseline. The Windows-native directory must also show Archive set after its harness run. Each unrelated directory, sentinel file, and sentinel directory must retain its original mask. Sentinel contents, lengths, and SHA-256 values must match their baselines. This inspection establishes attribute state; the Horizon output establishes consumer interoperability.

## Separate Windows native-finalization test

Use a second disposable FAT32 copy. Keep it separate from the Goldleaf copy. Set `$root` to a new directory such as `E:\nscb-qualification-windows-native` and transfer the same manifest and segments with the ordinary-filesystem recipe. The canonical directory will be `$root\qualification-source.nsp`.

Create two sentinels beside the canonical directory and record their hashes and attribute masks:

```powershell
$root = 'E:\nscb-qualification-windows-native'
$target = Join-Path $root 'qualification-source.nsp'
$sentinelFile = Join-Path $root 'preservation-sentinel.bin'
$sentinelDirectory = Join-Path $root 'preservation-sentinel-directory'

[IO.File]::WriteAllBytes($sentinelFile, [Text.Encoding]::UTF8.GetBytes("NSCB attribute sentinel`n"))
New-Item -ItemType Directory -Path $sentinelDirectory
attrib +h +r $sentinelFile
attrib +h $sentinelDirectory
attrib -a +h $target
```

The `attrib` command prepares the selected directory with Archive clear and Hidden set. It does not perform the finalization under test. Use the `nscb.exe` built from the reviewed candidate, and record its SHA-256 from the JSON output:

```powershell
.\scripts\qualification\test_split_archive_finalization_windows.ps1 `
  -QualificationRoot $root `
  -NscbExecutable 'C:\path\to\candidate\nscb.exe'
```

The harness checks that the volume is FAT32, then invokes the actual NSCB command `finalize-split-set <canonical-dir> --json` twice. Both exit codes must be zero. The first result must report `archive_attribute=set`; the second must report `archive_attribute=already_set`. After each call, `GetFileAttributesW` independently reads the selected directory. Archive must be set, and every other attribute bit must match the original mask. The sentinel file's length, SHA-256, and attributes and the empty sentinel directory's attributes and contents must remain unchanged.

The harness gives the executable an isolated `NSCB_STATE_DIR` under the temporary directory. It fails if a `split-trust` store or a receipt field appears, and it requires `source_backed_completeness` and `consumer_interoperability` to remain `not_established`. It removes the empty temporary directory after the run. A passing JSON result includes both exit codes and statuses, the executable path and SHA-256, the independent attribute masks, sentinel measurements, and `trust_receipt_store_absent=true`. Save the complete JSON output and the pre-test measurements.

The result must report `first_exit_code=0`, `first_archive_attribute=set`, `second_exit_code=0`, `second_archive_attribute=already_set`, `archive_bit_set=true`, and `other_selected_attributes_preserved=true`. Sentinel file and directory preservation fields must also be `true`.

This test exercises Windows native finalization only. It does not run Goldleaf or Horizon. If the directory was visible before setup, clear the temporary Hidden attribute afterward with `attrib -h $target`; Archive should remain set. Do not run this script on the Goldleaf copy.

## Source references

- Microsoft documents [SetFileAttributesW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw), [GetFileAttributesW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesw), [GetVolumePathNameW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamew), and [GetVolumeInformationW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw).
- The pinned [libnx filesystem header](https://github.com/switchbrew/libnx/blob/20cbcfd90567f7bf84df7725f27e345e2164fa6b/nx/include/switch/services/fs.h) defines the concatenation-directory behavior and the signed file-size and read APIs used by the checker.
- The [official libnx application Makefile template](https://github.com/switchbrew/switch-examples/blob/master/templates/application/Makefile) defines the NRO build targets, source discovery, object dependencies, and `LIBDIRS` conventions adapted by the checker. The pinned [libnx switch rules](https://github.com/switchbrew/libnx/blob/20cbcfd90567f7bf84df7725f27e345e2164fa6b/nx/switch_rules) provide the NRO conversion target.
- devkitPro provides the [devkitPro pacman releases](https://github.com/devkitPro/pacman/releases) and the [official `devkitpro/devkita64` container](https://hub.docker.com/r/devkitpro/devkita64), including a Linux arm64 image.
- The official [libnx package definition](https://github.com/devkitPro/pacman-packages/blob/master/libnx/PKGBUILD) places libnx in the `switch-dev` group and depends on devkitA64. The official [switch-mbedtls package definition](https://github.com/devkitPro/pacman-packages/blob/master/switch/mbedtls/PKGBUILD) declares its `switch-zlib` dependency.
- The pinned [libnx HID header](https://github.com/switchbrew/libnx/blob/20cbcfd90567f7bf84df7725f27e345e2164fa6b/nx/include/switch/services/hid.h) defines the Npad styles, state getters, and button masks used to close the checker.
- Goldleaf's inspected [selected-directory action](https://github.com/XorTroll/Goldleaf/blob/1b94ca0a448abab03219f1cd887fdf481cc7227f/Goldleaf/source/ui/ui_BrowserLayout.cpp#L585-L592) passes one selected path to its [archive-bit setter](https://github.com/XorTroll/Goldleaf/blob/1b94ca0a448abab03219f1cd887fdf481cc7227f/Goldleaf/source/fs/fs_StdExplorer.cpp#L263-L267). This source inspection does not replace the physical test.
- Linux documents [FAT_IOCTL_GET_ATTRIBUTES and FAT_IOCTL_SET_ATTRIBUTES](https://man7.org/linux/man-pages/man2/ioctl_fat.2.html). API availability does not qualify filesystem identification or Horizon interoperability.
