# Canonical FAT32 Split qualification

**Status:** Host implementation and regression evidence are recorded separately from physical FAT32 and Horizon results. Physical qualification remains `NOT RUN` until the owner authorizes the target media and console and the experiment passes.

This procedure keeps four evidence claims separate:

1. **Manifest consistency:** transferred members match the supplied manifest.
2. **Source-backed completeness:** independent source evidence establishes the original byte length and SHA-256.
3. **Archive finalization:** the selected inner directory's archive attribute was set and read back, or an external step is still required.
4. **Consumer interoperability:** Horizon opened the directory as one logical file and read the expected byte stream.

The finalizer establishes only the first claim and reports the third. It neither creates portable trust nor qualifies a Split set for NSCB transformations.

## PAC/TAC mapping

| PAC | Requirement | Technical acceptance criteria | Evidence required for acceptance |
| --- | --- | --- | --- |
| PAC-1 | Produce a complete, deterministic, FAT32-compatible canonical Split set. | TAC-2, TAC-4 | Production-profile test plus the physical source, segment, and reconstructed-stream measurements. |
| PAC-2 | Establish a qualified workflow for transferring the set to FAT32 storage. | TAC-1, TAC-4, TAC-7 | Exact inventory and content checks on the mounted destination; an interrupted copy must fail closed. |
| PAC-3 | Establish targeted archive-attribute finalization through native facilities where supported and documented external finalization otherwise. | TAC-3 | Native setter and readback on positively identified FAT32, or an external Goldleaf action followed by Horizon readback. |
| PAC-4 | Independently verify canonical consumer interoperability. | TAC-5 | The read-only Horizon checker opens the directory as a logical file and matches the original source length and SHA-256. |
| PAC-5 | Preserve publication safety and trust guarantees. | TAC-6, TAC-8, TAC-9 | Existing APFS and receipt regressions, original-bundle comparison, unrelated-entry preservation, and no receipt issuance during finalization. |
| PAC-6 | Distinguish supported, externally finalized, and unqualified platform capabilities. | TAC-1, TAC-10, TAC-11 | This support matrix and an exact-revision record that identifies unavailable, compile-only, and physical evidence. |

| TAC | Qualification requirement | Current boundary |
| --- | --- | --- |
| TAC-1 | Qualify the mounted FAT32 transfer workflow and identify the target filesystem positively before native mutation. | Transfer is ordinary filesystem copying. Direct FAT32 publication is outside this workflow. |
| TAC-2 | Enforce `0xFFFF0000` bytes for each nonfinal segment, a nonempty final segment no larger than that limit, contiguous `00`–`99` names, and at most 100 members. | Small segment seams remain test-only. |
| TAC-3 | Read the selected directory's attributes, add only the archive bit, preserve other bits, and independently read back the result. | Windows uses `SetFileAttributesW`; macOS requires an external or on-device action; Linux remains unqualified until FAT32 can be identified positively. |
| TAC-4 | Complete a physical FAT32 round trip with data larger than one production segment. | The procedure below uses a 4 GiB source: segment `00` is `0xFFFF0000` bytes and segment `01` is `0x10000` bytes. |
| TAC-5 | Test the logical file through an independent Horizon consumer. | The read-only libnx checker opens the path through Horizon's filesystem service and hashes the resulting stream. |
| TAC-6 | Preserve APFS publication and existing truthful terminal states. | No publication backend rewrite is part of this change. |
| TAC-7 | Show that an interrupted transfer or failed consumer read never earns a success claim. | Keep incomplete output for review; finalizer and consumer statuses remain separate. |
| TAC-8 | Preserve unrelated files and attributes. | Finalization is limited to the selected inner directory. Unexpected entries are rejected and never removed. |
| TAC-9 | Keep local trust receipts and resolver behavior unchanged. | A valid transferred set may be checked without the producer host's receipt; the normal resolver still requires its existing receipt. |
| TAC-10 | State platform boundaries and distinguish native execution from compile-only evidence. | See the support matrix below. |
| TAC-11 | Preserve historical records and keep legacy layouts separate. | This procedure covers canonical numbered directories only. Legacy `.xcN` and `.nsN` layouts are outside it. |

## Platform support matrix

| Platform | Finalization path | Evidence status |
| --- | --- | --- |
| macOS | Keep the producer on APFS, copy the completed bundle to FAT32, then use Goldleaf on the Switch to set the archive bit on the selected inner directory. The host command reports `external_finalization_required`. | The workflow is documented. Physical FAT32 and Horizon results remain pending. |
| Windows | Identify the mounted filesystem as `FAT32`, preserve the current attribute mask, add `FILE_ATTRIBUTE_ARCHIVE` with `SetFileAttributesW`, and verify through `GetFileAttributesW`. Other filesystems return `unsupported_filesystem`. | `COMPILE ONLY`: the pinned Windows target checks and production-library Clippy pass. Native Windows execution and physical Horizon consumption remain unqualified. |
| Linux | The mounted FAT attribute ioctl is available, but this implementation does not have a qualified positive FAT32 identification path. It reports `unqualified_platform` and does not mutate attributes. | Unqualified. |
| Other hosts | No native finalizer is claimed. | Unqualified. |
| Direct FAT32 publication | Not implemented by this workflow. | Separate qualification obligation. |

The Windows filesystem-name check uses `GetVolumePathNameW` and `GetVolumeInformationW`. The attribute operation uses the selected directory path only. It does not recurse, request elevation, or change mount state.

## Current qualification status

- macOS host tests verify the manifest, inventory, size-profile, and finalizer result paths without modifying FAT32 media.
- Linux runtime qualification has not been run. The current implementation returns `unqualified_platform` without changing attributes.
- The Horizon readback NRO is not built. This environment lacks the `devkitA64` compiler, libnx Switch build rules, and the Switch mbedTLS header.
- Physical FAT32 transfer, archive-bit inspection, Goldleaf finalization, Horizon readback, and unrelated-file attribute preservation are `NOT RUN`. Separate owner authorization is required before using the target media or console.

## Physical qualification procedure

Run this procedure only after separate owner authorization for a disposable FAT32 target and Switch/Horizon access. Use a target with more than 4 GiB of free space. Do not format, erase, or access raw volume sectors.

1. **Create the source on APFS.** Generate a deterministic 4 GiB file with the repository helper:

   ```sh
   python3 scripts/generate_split_qualification_source.py /path/on/apfs/qualification-source.nsp
   ```

   Record the emitted byte length and SHA-256. The default length is `0x100000000`, which exceeds the production segment limit. Do not place this source on FAT32.

2. **Produce the canonical bundle on APFS.** Use the existing source-backed Split producer with its default production segment size. Record the exact manifest digest, source receipt state, and each part's basename, length, and SHA-256. The expected physical parts are `00` at `0xFFFF0000` bytes and `01` at `0x10000` bytes.

3. **Snapshot the APFS output.** Record the source, manifest, inner directory, and member hashes, lengths, and identities. Keep this bundle unchanged through the remaining steps.

4. **Transfer the outer bundle using ordinary filesystem copy.** Copy it to the mounted FAT32 volume. Do not run the producer against the FAT32 path. Compare the target's exact inner-directory inventory, segment names, lengths, and hashes with the APFS bundle and manifest. Keep unrelated sentinel files outside the inner directory and record their content hashes and attribute masks.

5. **Run the host finalizer.** On Windows, require `set` or `already_set` with `archive_attribute_readback=verified`. On macOS, require `external_finalization_required`, then use Goldleaf's directory action to set the archive bit on the selected inner directory only. Linux must report `unqualified_platform` and must not set the bit. Record the destination attribute result. Do not treat a missing bit as evidence that verified bytes are incomplete.

6. **Build the independent Horizon reader.** After the source hash is known, build the read-only checker with the target path and source evidence:

   ```sh
   make -C tests/horizon/split_readback \
     SPLIT_PATH=/qualification/qualification-source.nsp \
     EXPECTED_SIZE=4294967296 \
     EXPECTED_SHA256=<source-sha256>
   ```

   Install the resulting NRO on the authorized test console. It checks that Horizon reports the path as a file, opens it with `fsFsOpenFile`, reads it in bounded chunks, and matches both length and SHA-256. The checker performs no writes. Record the NRO hash and full console output. `HORIZON_READBACK=PASS` is required for consumer interoperability.

7. **Check the failure boundaries.** On a separate disposable copy, interrupt transfer before all parts are present. The finalizer must fail, and the checker must not print a pass. On another separate copy, complete finalization successfully, alter one member, then run the checker against the original expected source hash. The checker must fail even though the archive bit was previously set.

8. **Verify preservation.** Recheck the APFS snapshot and the unrelated FAT32 sentinels. Their names, bytes, and attribute masks must match the initial record. The finalizer must not have removed entries or changed attributes outside the selected inner directory.

9. **Record every result.** Capture host and OS versions, filesystem identification, copy method, source and manifest digests, per-member measurements, before/after attribute state, NRO build identity, consumer output, unrelated-file snapshots, and any interruption or failure. Mark missing hardware, missing Windows execution, and compile-only checks `NOT RUN` or `COMPILE ONLY`; do not promote them to pass.

## Source references

- Microsoft documents `SetFileAttributesW` for setting file and directory attributes and `GetFileAttributesW` for reading them: [SetFileAttributesW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw), [GetFileAttributesW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesw), and [GetVolumeInformationW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw).
- The pinned [libnx filesystem header](https://github.com/switchbrew/libnx/blob/20cbcfd90567f7bf84df7725f27e345e2164fa6b/nx/include/switch/services/fs.h) defines a `ConcatenationFile` as a directory with the archive bit and provides the Horizon filesystem APIs used by the readback checker.
- [Goldleaf](https://github.com/XorTroll/Goldleaf) documents directory operations that can set or unset the archive bit. It is the candidate on-device finalizer for hosts without a qualified native path.
- The pinned [nxdumptool helper](https://github.com/DarkMatterCore/nxdumptool/blob/ade1a481121498ec649fbc832afe733050790acd/source/core/nxdt_utils.c) and [maintainer discussion](https://github.com/DarkMatterCore/nxdumptool/discussions/143) provide independent implementation context for numbered concatenation directories. They are design evidence; they do not replace the physical experiment.
- Linux documents `FAT_IOCTL_GET_ATTRIBUTES` and `FAT_IOCTL_SET_ATTRIBUTES` for FAT filesystems: [ioctl_fat(2)](https://man7.org/linux/man-pages/man2/ioctl_fat.2.html). This API availability alone does not qualify exact FAT32 identification or Horizon interoperability.
