# Preliminary third-party dependency assessment (2026-10-10)

**Status:** researched shortlist, **not** an approved or release-qualified provider manifest.
**Authority:** [NSCB v1 spec issue #2](https://github.com/whatobiplays/NSCB/issues/2), [ADR 0002](https://github.com/whatobiplays/NSCB/blob/main/docs/adr/0002-managed-tool-providers.md), [ADR 0014](https://github.com/whatobiplays/NSCB/blob/main/docs/adr/0014-qualified-release-matrix.md), and [ADR 0016](https://github.com/whatobiplays/NSCB/blob/main/docs/adr/0016-repository-content-policy.md).
The candidate tool names are not authorization to substitute user-installed binaries into production. Select and qualify exact versions, SHA-256 digests, build reproducibility, redistribution terms, native platforms, and operation-specific postconditions before pinning a provider manifest.

## Candidate reusable Switch-content software

| Capability | Candidate | First-party evidence | License / decision status |
| --- | --- | --- | --- |
| NCA/NSP/XCI read/decrypt/extract | **hactool** | https://github.com/SciresM/hactool (README, LICENSE) | ISC. Strong candidate for a qualified read/extract executable. Required key path can be passed explicitly. Its documented functions do not establish our build/repack support. |
| NSP/XCI/NCA/PFS0/HFS0/CNMT/NACP inspect/extract | **NSTool** | https://github.com/jakcron/nstool (README, BUILDING, LICENSE, deps) | MIT. Strong candidate for a reader/extractor and independent cross-check oracle. Audit transitive dependency licensing and native build coverage. Do not require both hactool and NSTool unless they demonstrably cover different necessary operations. |
| NSZ/XCZ/NCZ format and compressor/decompressor | **NSZ** | https://github.com/nicoboss/nsz and https://github.com/nicoboss/nsz/blob/master/docs/formats.md | MIT, Python-based tool. Primary interoperability oracle and reference for NCZ framing; potentially qualified managed helper, but default Python-runtime packaging may conflict with self-contained release expectations. Investigate native Rust framing with a qualified Zstandard crate. |
| Zstandard codec | **zstd-rs** | https://github.com/gyscos/zstd-rs, https://docs.rs/crate/zstd/latest | BSD-3-Clause Rust bindings and compatible native zstd. Preferred mature codec over writing compression internals. Verify vendored C library's applicable BSD license and four-target builds. Evaluate pure-Rust alternatives on correctness/performance rather than assuming equivalence. |
| NSP/NCA writer/repacker | **hacPack** | https://github.com/DarkMatterCore/hacPack | GPL-2.0; technically relevant, **license/redistribution review mandatory** and cross-target build status unqualified. Prefer an isolated executable only if legally and operationally acceptable; otherwise investigate a narrowly scoped NSCB-owned container writer atop existing crypto/format libraries. |
| Modern extraction alternative | **hac2l** | https://github.com/Atmosphere-NX/hac2l | GPL-2.0 with project-specific alternative-license exceptions that do **not** automatically apply to NSCB. Not the default candidate over ISC/MIT readers. |

**Important gap:** No single source in this shortlist has yet been shown to cover the full package-building, split/merge, signed-metadata, compatibility-patch, and exact-restoration contract across all target platforms. Avoid claiming that all complex work is delegated. NSCB can own small canonical container writers, semantic validation, and orchestration while relying on mature parsing and cryptography libraries. In particular, independently test multi-content build→split against synthetic payloads and the scenario in [issue #1](https://github.com/whatobiplays/NSCB/issues/1).

## Device USB/MTP client options

| Host/path | Candidate | Primary evidence | Risk and next check |
| --- | --- | --- | --- |
| All platforms / raw USB, especially optional DBI0 | **libusb** | https://github.com/libusb/libusb and https://github.com/libusb/libusb/wiki/FAQ | LGPL-2.1+. Driver ownership, macOS entitlement/permissions, Windows driver installation, and redistribution must be qualified. |
| Linux/macOS MTP | **libmtp** on libusb | https://github.com/libmtp/libmtp | LGPL (repository identifies LGPL-2.1; inspect upstream COPYING for obligations). It is an MTP initiator, **not** proof that DBI-specific virtual objects and write/install control semantics work. Confirm macOS build/deployment. |
| Windows MTP | **Windows Portable Devices COM API**, preferably Rust wrappers/bindings | https://learn.microsoft.com/en-us/windows/desktop/wpd_sdk/client-interfaces and https://github.com/microsoft/windows-rs | OS-provided transport. `winmtp` exposes a partial abstraction: https://docs.rs/winmtp/latest/winmtp/ . Test custom DBI responder operations before committing to any wrapper; direct windows-rs bindings may be necessary. |
| Switch-side responder | **DBI** (user-operated, not bundled) | https://github.com/rashevskyv/dbi and https://github.com/rashevskyv/dbi/releases | MTP install/storage/dump claims must be verified with specific versions and devices. As of Oct 2026 repository releases include Russian-only variants and distinguish official English releases; no blanket version assumption. Never install or manage DBI remotely. |

Exact MTP transport mechanics, capacity reporting, installed title inventory, gamecard data, save categories, and privacy-sensitive separate certificate transfer are **qualification blockers**, not established by an MTP library's README. DBI0 remains conditional on all four host targets.

## Ordinary Rust dependency candidates (not external managed providers)

- CLI: **clap** (MIT OR Apache-2.0), https://github.com/clap-rs/clap .
- TUI: **ratatui** (MIT), https://github.com/ratatui/ratatui ; validate terminal input/backend with an appropriate supporting crate such as crossterm before pinning.
- Serialization/config: **serde** (MIT OR Apache-2.0), https://github.com/serde-rs/serde , with qualified JSON/TOML implementations.
- Durable history: **rusqlite** (MIT; optional bundled public-domain SQLite), https://github.com/rusqlite/rusqlite .
- Cryptographic primitives rather than custom AES/hash/RSA implementations: evaluate applicable **RustCrypto** crates, https://github.com/RustCrypto/traits , and their individual implementations, padding, modes, key handling and supported MSRV.
- Windows OS bindings: **windows-rs**, https://github.com/microsoft/windows-rs (MIT OR Apache-2.0).
- Compression: **zstd-rs** as above. Use streaming codecs and inspect max-memory/large-file behavior under all supported targets.
- Additional foundational candidates to qualify rather than preselect: file locking/atomic publication, HTTP/TLS, Unicode normalization, safe path canonicalization, diagnostics, and platform config locations. Avoid crates that unintentionally impose host-visible Tokio or duplicate runtime constraints at the Rust embedding facade.

## Advisory services: not yet selected

- **TitleDB-compatible metadata:** https://github.com/blawar/titledb documents region/language metadata and title/version schemas. Its README says some previous `titles.US.en.json` files are no longer included; the repository currently has user reports of stale updates (https://github.com/blawar/titledb/issues). Audit actual current snapshots, schema, update frequency, provenance and source terms. Do not treat this repository as a proven durable service simply because its schema is familiar.
- **Translation provider:** both https://www.deepl.com/en/developers and https://docs.cloud.google.com/translate/docs/reference/rest provide documented official APIs. Product design permits one qualified official provider with user credentials and nonfatal fallback; do not freeze vendor until API scope, authentication, quotas/pricing and redistribution/terms review.

## Qualification gates before release-pinning

1. **Inventory:** per candidate, record upstream owner, source URL, license text, transitive licenses, stable revision/tag, reproducible build recipe and dependencies.
2. **Evidence:** select at most the necessary providers; build and run on macOS arm64, Windows 11 x86_64, Linux glibc 2.35+ x86_64 and arm64; test exact supported commands and error behavior with synthetic fixtures.
3. **Semantics:** never use provider exit=0 as sole success; verify typed output, postconditions and cryptographic/structural checks. Adapters must hide provider text and expose stable NSCB semantics.
4. **Supply chain:** pin SHA-256 and artifact architecture in immutable release-qualified manifest; verify downloads/cache atomically and require offline failure when missing.
5. **Licensing:** use approved MIT/ISC/BSD/Rust dependencies where possible; vet GPL/LGPL build, linking, runtime and redistribution obligations before bundling; ship required license/source notices.
6. **Security:** no proprietary keys or content in repository/release, no untrusted dynamic executable selection, sanitization of paths/args/logs, bounded subprocess and extraction behavior.
7. **Device:** physical MTP tests with exact responder builds on all four targets, and conditional DBI0 separately; no unsupported capability marketing.

## Recommendation

1. Begin ticket **#1** with a native Rust inspection tracer, one permissively licensed reader/provider if needed, and synthetic fixtures.
2. Ticket **#5** must turn the shortlist into an explicit provider **selection/qualification matrix and exact pinned manifest**; its scope includes proving who owns package creation and patch semantics, rather than presuming hactool/NSZ/hacPack collectively provide them.
3. Tickets **#29–31** should each prove their platform-native MTP adapter with a real DBI session, not simply compile a library. Ticket **#45** is the final all-target gate.
4. Treat all candidates in this document as provisional until an accepted provider-specific test matrix and license review have been recorded.
