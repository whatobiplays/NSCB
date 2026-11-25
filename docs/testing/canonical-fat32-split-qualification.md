# Canonical FAT32 Split qualification

**Status:** Host implementation evidence and physical FAT32/Horizon evidence are recorded separately. Physical qualification remains `NOT RUN` until the owner authorizes the target media and console and the procedure below passes.

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

## Platform support

| Platform | Finalization path | Evidence boundary |
| --- | --- | --- |
| macOS | Keep production on APFS, copy the completed bundle to FAT32, then use Goldleaf on the selected inner directory. The host command reports `external_finalization_required`. | The workflow is documented. The Goldleaf action, FAT32 result, and Horizon readback remain unqualified until the physical procedure passes. |
| Windows | Identify the mounted filesystem as FAT32, use `SetFileAttributesW` to add the archive bit, and verify with `GetFileAttributesW`. Other filesystems return `unsupported_filesystem`. | The Windows GNU target check passes with the job-history feature enabled. The MSVC check is blocked because the available Xcode compiler lacks the target `stdlib.h`/MSVC runtime headers. Native Windows execution and physical Horizon consumption remain unqualified. |
| Linux | The mounted-filesystem `FAT_IOCTL_GET_ATTRIBUTES` and `FAT_IOCTL_SET_ATTRIBUTES` API is the candidate for a future qualified path. | The x86_64 GNU target check passes. The AArch64 check is blocked because `aarch64-linux-gnu-gcc` is unavailable for the `ring` build. No Linux attribute backend is claimed; filesystem identification and API behavior remain unqualified, and this slice does not rewrite the Linux publication backend. |
| Other hosts | No native finalizer is claimed. | Unqualified. |
| Direct FAT32 publication | Outside the transfer workflow. | Separate qualification obligation. |

Goldleaf's current Explorer exposes a directory operation for setting or clearing the archive bit. Its selected-item handler passes the selected path to `SetArchiveBit`, which calls libnx's `fsdevSetConcatenationFileAttribute` for that path. The procedure below uses the set action on the canonical inner directory only. Goldleaf does not provide the independent readback required for acceptance, so the procedure checks the bit separately on Windows after Goldleaf exits.

## Host qualification status

- Repository-native `make all` passes on macOS with the pinned Rust toolchain. APFS publication behavior and the existing receipt contract remain in scope for repository regressions.
- Windows GNU and Linux x86_64 cross-target checks pass with `standalone-job-history`; they are compile evidence only. Windows MSVC and Linux AArch64 limitations are listed in the platform matrix.
- The finalizer verifies the manifest, exact inner-directory inventory, physical segment hashes, and production segment profile. It does not consult or create a source receipt.
- The corrected Horizon checker uses the pinned libnx signed-size and Npad APIs and a fixed 64 KiB static read buffer.
- The Horizon NRO has not been built in this environment. `DEVKITPRO=/opt/devkitpro` is set, but these prerequisites are absent: `/opt/devkitpro/devkitA64/base_rules`, `/opt/devkitpro/libnx/switch_rules`, the AArch64 devkitA64 compiler/binutils (including `aarch64-none-elf-gcc`), `elf2nro`, `/opt/devkitpro/portlibs/switch/include/mbedtls/sha256.h`, and `/opt/devkitpro/portlibs/switch/lib/libmbedcrypto.a`. The Makefile also requires `EXPECTED_SIZE` and `EXPECTED_SHA256`.
- Physical FAT32 transfer, Goldleaf finalization, independent archive-bit inspection, Horizon readback, and unrelated-attribute preservation are `NOT RUN`. No media or console was accessed.

The disposable APFS fixture has been generated and checked. Its 4,294,967,296-byte source and reconstructed stream both hash to `1bdb600eb7d29d0a1013ea5de3707f3416664ca922313166529aec32faccc72b`. The canonical set contains `00` (4,294,901,760 bytes; SHA-256 `af6eadf3a6fb419bab3be5398ed6acd2e4d880dedac720f05eb67701cc6e3a8a`) and `01` (65,536 bytes; SHA-256 `d8f32a3b4c195f65444e342b0c61bdaf114802e84ab7821a1f88e3f66ea15100`). The 526-byte manifest hashes to `b36dce16871bcd8fb9416e01e5ed0a8b58a1ddd16ebdd60959b7a4a8253c05a1`; the isolated local receipt is issued for that manifest. An ordinary `copyfile` transfer to a second APFS directory reproduced the exact two-member inventory and hashes. That simulation is not FAT32 qualification. On macOS, the host finalizer returned exit 8 with `manifest_consistency=verified`, `archive_attribute=external_finalization_required`, `source_backed_completeness=not_established`, and `consumer_interoperability=not_established`. Measurements are recorded in the ignored worktree artifact `target/issue-14-slice-b-qualification/fixture-measurements.json`.

## Reproducible APFS fixture

The generator creates a deterministic 4 GiB source. Its length is `0x100000000` bytes, just over one production segment. NSCB should produce two physical parts: `00` at `0xFFFF0000` bytes and `01` at `0x10000` bytes.

Use a new ignored worktree path under `target/`; do not reuse or remove an existing fixture. Keep the source, bundle, isolated application data, and recorded measurements on APFS.

```sh
mkdir target/issue-14-slice-b-qualification
mkdir target/issue-14-slice-b-qualification/home
python3 -B scripts/generate_split_qualification_source.py \
  target/issue-14-slice-b-qualification/qualification-source.nsp
```

Run the ordinary producer against the APFS bundle path. Keep the application data and source receipt inside the disposable fixture root:

```sh
rustup run 1.98.1 cargo build --locked --release \
  --features standalone-job-history --bin nscb

HOME="$PWD/target/issue-14-slice-b-qualification/home" \
USERPROFILE="$PWD/target/issue-14-slice-b-qualification/home" \
XDG_CONFIG_HOME="$PWD/target/issue-14-slice-b-qualification/home/.config" \
  target/release/nscb split \
  "$PWD/target/issue-14-slice-b-qualification/qualification-source.nsp" \
  "$PWD/target/issue-14-slice-b-qualification/qualification-source.bundle" \
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

Perform these steps only after separate owner authorization for the disposable FAT32 media and Switch. Use an existing FAT32 volume with more than 4 GiB free. Do not format it, access raw sectors, or let NSCB publish directly to it.

1. Record the media label and identifier, FAT32 filesystem report, free space, host OS, console firmware, and exact Goldleaf release or commit. Keep the source, bundle, manifest, segments, local receipt, and measurements on APFS.
2. Transfer the bundle with the ordinary-filesystem recipe above. The expected paths on the FAT32 volume are `/nscb-qualification/qualification-source.nsp/00`, `/nscb-qualification/qualification-source.nsp/01`, and `/nscb-qualification/qualification-source.nsp.nscb-split.json`. Compare the destination measurements with the APFS source record. Run the host finalizer and save its full JSON output.
3. On a host with the required devkitPro toolchain, build the checker with the measured source digest:

   ```sh
   make -C tests/horizon/split_readback \
     SPLIT_PATH=/nscb-qualification/qualification-source.nsp \
     EXPECTED_SIZE=4294967296 \
     EXPECTED_SHA256=1bdb600eb7d29d0a1013ea5de3707f3416664ca922313166529aec32faccc72b
   shasum -a 256 tests/horizon/split_readback/build/nscb_split_readback.nro
   ```

   Copy the NRO to `/switch/nscb_split_readback.nro` on the FAT32 volume. Record its SHA-256. If the required toolchain is unavailable or the NRO fails to build, stop physical qualification and record that prerequisite as `NOT RUN`.
4. Safely eject the media from the build host. On Windows, mount it and record the archive-attribute masks for the selected inner directory, an unrelated directory, and an unrelated sentinel file with the read-only procedure below. Record the sentinel's bytes and SHA-256. Safely eject the volume from Windows before inserting it into the console.
5. In Goldleaf Explorer, navigate to `/nscb-qualification`, select `qualification-source.nsp`, and choose the selected directory's set-archive-bit action. Confirm the selected path before applying the change. Do not select the outer qualification directory or a recursive operation.
6. Launch `/switch/nscb_split_readback.nro`. The checker opens `/nscb-qualification/qualification-source.nsp` through Horizon, reads it in bounded chunks, and compares the signed file size and SHA-256. Expected output:

   ```text
   INTEROP_PASS bytes=4294967296 sha256=1bdb600eb7d29d0a1013ea5de3707f3416664ca922313166529aec32faccc72b path=/nscb-qualification/qualification-source.nsp
   HORIZON_READBACK=PASS
   ```

   Record the complete screen output. Any open, size, read, or hash failure must end with `HORIZON_READBACK=FAIL`.
7. Exit the checker and Goldleaf, shut down the console, and remove the media only when safe. Mount it on Windows and repeat the read-only inspection. The selected inner directory must show archive bit `0x20`, and its other attribute bits must match the baseline. The unrelated directory and sentinel must retain their original masks, and the sentinel hash must match.
8. Re-run the source and destination measurements and compare the full inner-directory inventory. Confirm the APFS source, bundle, manifest, segments, and receipt remain unchanged. Save outputs with OS, tool, and revision details.
9. On separate disposable copies, stop a transfer before all members arrive and corrupt one segment after a complete transfer. The host finalizer must reject the incomplete set. Horizon must never report `HORIZON_READBACK=PASS` for the corrupted copy; record the failure output.
10. Mark unavailable Windows execution, an unavailable NRO build, and any missing physical observations as `NOT RUN` or `COMPILE ONLY`. Physical interoperability remains unqualified until every required step passes.

### Read-only archive-attribute inspection after Goldleaf

Run this in PowerShell on Windows after Goldleaf has exited and the media is mounted. Run it once before the Goldleaf action for the baseline, then again after the Horizon test. Replace the drive letter if needed. The script calls `GetFileAttributesW` and does not change attributes.

```powershell
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

public static class Fat32AttributeReader
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFileAttributesW(string path);
}
'@

$paths = @(
    'E:\nscb-qualification\qualification-source.nsp',
    'E:\nscb-qualification\unrelated',
    'E:\nscb-qualification\unrelated\sentinel.bin'
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

Save both outputs. The selected inner directory must show `ArchiveBit = True` after Goldleaf, with all other attribute bits unchanged from baseline. The unrelated directory and sentinel must retain their original masks. This inspection establishes attribute state; the Horizon output establishes consumer interoperability.

## Source references

- Microsoft documents [SetFileAttributesW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw), [GetFileAttributesW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesw), and [GetVolumeInformationW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw).
- The pinned [libnx filesystem header](https://github.com/switchbrew/libnx/blob/20cbcfd90567f7bf84df7725f27e345e2164fa6b/nx/include/switch/services/fs.h) defines the concatenation-directory behavior and the signed file-size and read APIs used by the checker.
- The pinned [libnx HID header](https://github.com/switchbrew/libnx/blob/20cbcfd90567f7bf84df7725f27e345e2164fa6b/nx/include/switch/services/hid.h) defines the Npad styles, state getters, and button masks used to close the checker.
- Goldleaf's inspected [selected-directory action](https://github.com/XorTroll/Goldleaf/blob/1b94ca0a448abab03219f1cd887fdf481cc7227f/Goldleaf/source/ui/ui_BrowserLayout.cpp#L585-L592) passes one selected path to its [archive-bit setter](https://github.com/XorTroll/Goldleaf/blob/1b94ca0a448abab03219f1cd887fdf481cc7227f/Goldleaf/source/fs/fs_StdExplorer.cpp#L263-L267). This source inspection does not replace the physical test.
- Linux documents [FAT_IOCTL_GET_ATTRIBUTES and FAT_IOCTL_SET_ATTRIBUTES](https://man7.org/linux/man-pages/man2/ioctl_fat.2.html). API availability does not qualify filesystem identification or Horizon interoperability.
