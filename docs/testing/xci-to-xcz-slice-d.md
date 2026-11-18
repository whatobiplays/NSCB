# XCI to XCZ Slice D Qualification

## 1. Authorization and qualification boundary

The product owner approved standard interoperable XCZ output carrying the selected 16-byte Program section key and counter in plaintext NCZ metadata, limited to the rights-free base Application profile. The approval is recorded in [Issue #17](https://github.com/whatobiplays/NSCB/issues/17#issuecomment-6957933172); NSP/NSZ approval was not used to authorize this operation.

Anyone who obtains a published artifact can access that key material and may be able to decrypt the associated compressed section. The implementation retains key redaction, zeroization, private staging, and semantic validation. Qualification used wholly synthetic, rights-free content and does not establish Nintendo authenticity, signature validity, strict upstream verification, Full Verification, console installability, or byte-identical whole-XCI reconstruction.

The accepted input profile remains narrow: a rights-free base Application XCI with supported Meta and Program NCAs and canonical empty auxiliary partitions. Populated or otherwise nonempty auxiliary payload data is rejected; preserving populated auxiliary partitions is outside this qualification.

## 2. Exact qualified source and environment

- Repository: `whatobiplays/NSCB`
- Qualified source commit: `09303c4637e7563085001b1b2a319fa304f00a1b`
- Baseline: `2790b5bed2010211a75c9c8c8008f146b3557626`
- Branch: `codex/issue-17-xci-to-xcz-compression`
- Native host: macOS 27.0.1, build 26A434, Darwin arm64
- Rust and Cargo: repository-pinned 1.98.1; host `aarch64-apple-darwin`; LLVM 22.1.8
- Upstream decoder/encoder: unmodified NSZ 5.0.0 source at [`148218ff89bb4b607d07730a8cf87d5e1f249ebc`](https://github.com/nicoboss/nsz/commit/148218ff89bb4b607d07730a8cf87d5e1f249ebc), Python 3.12.16

The rights-free source XCI is 110,592 bytes with SHA-256 `32f9ceef52681b648bfc296e5603e8fb92a452ea23d9e1f529e9e7e059832573`.

The NSZ key file was generated solely for this synthetic fixture. It is 490 bytes, SHA-256 `56c8ea6f228e6acee7a886481eecf035d62277daca67a7aa94b5ae837bc9fa0a`, and contains synthetic values for `aes_kek_generation_source`, `aes_key_generation_source`, `titlekek_source`, `key_area_key_application_source`, `key_area_key_ocean_source`, `key_area_key_system_source`, `master_key_00`, and `header_key`. All seven fixed CRC32 inputs required by the pinned loader passed, and the loader-derived Application key matched the fixture. The separate NSCB key file is 141 bytes, SHA-256 `841fb05339501aa7d63d9ee339377520541fe3ee5bbc1811144e727171656c67`, with synthetic `header_key` and `key_area_key_application_00` entries. Neither file contains proprietary Nintendo keys or copied production key data.

The upstream process used the explicit synthetic key file, an isolated `HOME` and `XDG_CONFIG_HOME`, `PYTHONNOUSERSITE=1`, and `PYTHONDONTWRITEBYTECODE=1`. The source archive was checked out at the pinned commit; no user or host key-file fallback was available.

## 3. Acceptance results

| Group | Result | Evidence |
| --- | --- | --- |
| PAC-1: Format and interoperability | Pass on exact qualified source | Two Balanced XCI-to-XCZ runs produced byte-identical 148,992-byte artifacts, SHA-256 `50cc8ab489b89249aecaf9a1dadfe29cab183567dcf2683ea387f2dbaa40e897`. The unmodified pinned NSZ decoder successfully parsed and decoded the XCZ. A bounded streaming HFS0 reader independently verified the reconstructed NCA bytes against the expected hashes below. |
| PAC-2: Compression selection | Pass | Engine and CLI tests cover Balanced 9, Fast 3, Maximum 19, numeric levels 1–19, invalid levels, and frozen execution settings. |
| PAC-3: Logical round trip | Pass for the qualified profile | Native tests exercise XCI → XCZ → XCI. The upstream-decoded XCI contains exact logical Meta and Program NCA bytes. Whole-XCI byte equality is not required or claimed. Reverse upstream compression followed by NSCB decompression also reconstructed matching logical NCA bytes, subject to the fixture-specific tail padding described in Section 4. |
| PAC-4: Safe publication | Pass | Engine tests cover Fail, Skip, Replace, AlreadyUpToDate, cancellation, source/key mutation, destination races, staged-output validation, and preservation of competing destinations. |
| PAC-5: Adversarial and regression behavior | Pass on native tests; cross-platform runtime remains unqualified | Tests reject malformed HFS0/NCZ data, bad hashes and frames, invalid offsets, unsupported profiles, and populated or otherwise nonempty auxiliary payload regions. They verify missing application-key rejection before staging and report a Zstandard output-write failure. Existing NSP/NSZ, XCI → NSP, and XCZ → XCI focused regressions pass. Linux and Windows GNU targets compile, but their test binaries were not executed on this macOS host. |
| PAC-6: Qualification evidence | Pass for this profile, with limits recorded | Exact-source native qualification, deterministic replay, unmodified pinned upstream interoperability in both directions, local validation, two independent Cubic reviews, and CI #103 are recorded below. |

The independently checked reconstructed NCA SHA-256 values are:

- Meta NCA: `87bfa1629b651e3f49a9ba053fb3842c5c34e31c9303e6e1807703cd84e68e7f`
- Program NCA: `166f438248bd9fbad65125fb76af5e002812e7a104902a516d626f3a6850bd2c`

The upstream decoder emitted `[CORRUPTED] meta.nca`. In the pinned NSZ code, this label is produced because the Meta NCA hash is absent from the CNMT-derived `fileHashes` set; the ordinary check reports the mismatch, while strict verification is a separate mode. The independently streamed Meta bytes match the expected Meta NCA hash above. This result confirms the logical bytes for this synthetic fixture, but it does not establish that strict upstream verification passes or that the content is Nintendo-authentic.

The shared checked XCI layout calculation supplies placement, alignment, and output-length arithmetic to both measured geometry and preflight bounds. `RomSize` and `ValidDataEndAddress` checks remain in the checked geometry layer; card-header fields are not normalized. Five focused tests cover aligned and unaligned member sizes, `logo` presence and absence, bound/measurement consistency, maximum-size rejection, overflow, and card-header constraints.

## 4. Upstream commands and reverse qualification

The NSCB binary was built from the exact qualified source with:

```text
rustup run 1.98.1 cargo build --locked --features standalone-job-history --bin nscb
```

Balanced compression was run twice with the same tracked source and synthetic NSCB key file. Both commands exited 0 and reported `cleanup_incomplete`:

```text
target/debug/nscb xci-to-xcz --source tests/fixtures/xcz-to-xci/upstream-nsz/source.xci --output <run-output.xcz> --workspace <private-run-workspace> --keys target/issue17-p2-qualification/nscb-synthetic-keys.dat --preset balanced --json
```

The unmodified upstream decoder command exited 0 and reconstructed a 174,114-byte XCI with SHA-256 `aab64f07c9addbbe80369892b1317194957fb3e4502529cea731c75ce4b1e0a0`:

```text
python nsz.py --keys <isolated-synthetic-keys.dat> -D --output <decode-directory> <balanced-output.xcz>
```

The exact executable paths, isolated environment paths, per-run output locations, exit codes, and retained logs are recorded in the [PR qualification comment](https://github.com/whatobiplays/NSCB/pull/86#issuecomment-6973808333).

For reverse qualification, unmodified pinned NSZ compressed the rights-free source XCI with `-C --solid --level 1 --threads 1 --multi 1`, exiting 0. It emitted a 148,582-byte XCZ with SHA-256 `7cd4b1890666d573426b08d834da788b30cd630f7014acdbb14d4e2eed5434c3`; its declared terminal extent was 148,992 bytes. Exactly 410 zero bytes were appended to satisfy the tracked fixture's physical extent, producing the 148,992-byte input hash `55e2c70ccd5e0c3de60158104426147fb90a30614273c7a3dc400dd84ee70115`. NSCB decompressed it successfully; the reconstructed XCI SHA-256 is `866602c76441a8879088eda20ed4998ba8efca1e63bdfe3ac3d3cdaf74722557`, and its Meta and Program NCA hashes match those above.

The 410-byte padding is a fixture-specific requirement for this reverse interoperability case. It does not expand the supported profile or claim that arbitrary short or truncated XCZ inputs are accepted.

## 5. Local validation, CI, and independent review

All local Rust commands used the repository-pinned Rust 1.98.1 toolchain on native macOS arm64.

| Command or review | Result |
| --- | --- |
| `make all` | Exit 0: 1,885 passed, 8 ignored, 0 failed. |
| Focused conversion tests | Exit 0: 56 tests, 0 failures across `xci_to_xcz`, `xci_to_xcz_cli`, `nsp_nsz`, `xci_to_nsp`, `xci_to_nsp_cli`, and `xcz_to_xci_cli`. |
| Focused geometry tests | Exit 0: 5 tests. |
| `cargo fmt --all -- --check` | Pass. |
| Strict Clippy | Pass with warnings denied. |
| Linux and Windows GNU all-target checks | Pass; compile unsupported-capability paths only. Runtime tests were not run on those operating systems. |
| CI #103 | All 9 jobs passed, including macOS arm64 `make all`, Linux validation and semantic suites, Windows semantic tests, Windows Server 2025 MSVC library tests and strict Clippy, and content-policy checks. [Run #103](https://github.com/whatobiplays/NSCB/actions/runs/44268620556). |
| Cubic 1.14.2 | Two separate non-authoring reviews of the exact correction delta and cumulative candidate completed clean with zero findings. The cumulative review covered the full 17-file base-to-candidate diff, implementation paths, tests, geometry constraints, relevant names, strings, and paths. |

The earlier inability to cross-compile Windows MSVC on the local macOS host was a host toolchain/SDK limitation. CI #103 completed the Windows MSVC jobs successfully.

The two Cubic reviews retained prior dispositions: the zeroizing-buffer issue was corrected; the CLI `Debug` exposure concern is a false positive because the alleged exposure path is absent; the auxiliary-layout finding remains disputed and outside the approved canonical-empty profile; and the suggested lifecycle/module and generic auxiliary-validator expansions were declined because no concrete defect supported widening the architecture or accepted profile.

## 6. Historical evidence, coverage, and retained artifacts

The earlier success record reported the same XCZ and NCA hashes but did not retain run-specific source/key digests or isolated user-key paths. The exact-source replay above now reproduces those hashes using the validated synthetic key files and isolated upstream environment.

A separate historical upstream CLI diagnostic used source XCI SHA-256 `16bc81f21f8a7167a3289eb8ed15ec9f9dfd6fde4a67aab18cf43e9ca8699244`, XCZ SHA-256 `58192e70aeb1a5ba4d7797b43c543b61534526a6c7bd1bea05f202cf397e1d95`, and a 141-byte key file SHA-256 `8442aac25fc452b5febfccc79c717c38efc92a817ed9907d70c5c90d7f641572` containing only `header_key` and `key_area_key_application_00`. It exited 1 because `aes_kek_generation_source` was missing while decrypting the NCA header in `AllowedToWriteOutfile → ExtractTitleIDAndVersion`. That occurs before NSZ's XCZ/NCZ decompression path; the run produced no decoded XCI or NCA hashes and did not test NCZ parsing. It was an incomplete synthetic key fixture, not evidence of a product regression or a zeroization defect. The failed log is retained.

A separate 553-byte loader diagnostic file, SHA-256 `4c6ec516fca7353a34965660dac70bea72e87afb51b06804ded19d2a0eb275ef`, passed its synthetic CRC checks but derived an Application key that did not match that fixture and failed PFS0 parsing. It was not the key file used in the failed CLI run. An earlier preliminary NSCB command also exited 2 with `config_directory_unavailable` because relative `HOME` and `XDG_CONFIG_HOME` values were supplied; rerunning with absolute isolated paths succeeded.

Earlier full-suite runs encountered the timing-sensitive `tests/cli_subprocess.rs::copy_subprocess::blocked_reporting_after_cancellation_preserves_the_source_and_destination` failure (`filler process did not saturate the stdout pipe`). Its isolated rerun and the final `make all` passed. A baseline reproduction was not run.

Historical coverage was collected while `HEAD` was `2790b5bed2010211a75c9c8c8008f146b3557626` with uncommitted Slice D changes. The exact dirty-tree diff fingerprint was not retained, so the coverage snapshot cannot be assigned to a later committed SHA or independently reconstructed. The table was reported to predate the final zeroizing-buffer change; it is not coverage for qualified source commit `09303c4637e7563085001b1b2a319fa304f00a1b`.

| Source file | Executed / total lines | Line coverage |
| --- | ---: | ---: |
| `src/ncz.rs` | 439 / 486 | 90.33% |
| `src/nsp_nsz.rs` | 381 / 456 | 83.55% |
| `src/xci_format.rs` | 339 / 357 | 94.96% |
| `src/xci_to_xcz.rs` | 495 / 566 | 87.46% |
| `src/xcz_to_xci.rs` | 626 / 735 | 85.17% |
| `src/operation.rs` | 4,752 / 9,624 | 49.38% |
| `src/engine.rs` | 54 / 209 | 25.84% |

These are whole-file line metrics, not Slice D thresholds; the shared files contain unrelated behavior. The export had no separate `src/cli.rs` row, so no CLI line percentage is claimed. A broader profile merge was rejected because raw profiles from separate full-suite binaries used incompatible format versions; the focused profile set merged successfully.

Three successful NSCB operations in the final exact-source qualification (two XCI-to-XCZ compressions and one reverse NSCB decompression) reported `cleanup_incomplete` and retained their operation artifacts. The operation workspaces, qualification outputs, and prior failure logs remain retained. Automatic cleanup is not claimed. No release qualification is claimed.

The documentation-only follow-up leaves the executable and test trees identical to qualified source commit `09303c4637e7563085001b1b2a319fa304f00a1b`: `src` tree `794302cc37410bf0b139ef1dd55a3089fe0bc3a4` and `tests` tree `85e5fbdf66ac753344aa97e69e67630090f0ff03`. The PR evidence comment records the final documentation commit and its CI result.
