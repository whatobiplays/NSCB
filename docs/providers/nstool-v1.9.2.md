# NSTool v1.9.2 provider contract

NSCB selects NSTool v1.9.2 only for the read-only `nca.inspect` capability.
The provider inspects one standalone NCA3 file after NSCB has independently
parsed its header, checked the input identity, and validated a local header
key. NSTool does not provide signature authenticity, signature verification,
integrity verification, general decryption, extraction, writing, repacking,
or patch application.

The immutable manifest identifies upstream repository
[`jakcron/nstool`](https://github.com/jakcron/nstool), release `v1.9.2`, and
commit `e89ea84bd70c11b67ebec9153fb4a446f18a9d3d`. NSTool is MIT-licensed;
the license and transitive notices are stored under `licenses/`. The
shortlisted hactool candidate was not selected for this operation because its
v1.4.0 release did not provide the required cross-target artifact evidence.
That decision does not rule out hactool for a future capability.

## Artifact selection

The manifest is compiled from `providers/nstool-v1.9.2.json`. NSCB accepts an
archive only from the pinned release URL and verifies its exact size and
SHA-256. The archive must contain exactly one regular file with the declared
name, size, and executable digest.

| Target | Release asset | Archive SHA-256 | Executable SHA-256 | Status |
| --- | --- | --- | --- | --- |
| macOS arm64 | `nstool-v1.9.2-macos_arm64.zip` | `fe3df0b0e7ec8205d56834577a20b26e42554456e086e86e3b9e5fe749d3b378` | `381343160daea53ae70205885bb111518643571c971aef3c695dc1a63aa2343e` | Artifact target selected for `nca.inspect`; production qualification is recorded in the evidence document. |
| macOS x86_64 | `nstool-v1.9.2-macos_x86_64.zip` | `4a483d9a04e353afc59cabc0070d92b2e9e98627ac631168830890dd8cf98ad0` | `a83b9552cd7f8ce2aee46f7f49067bb9aa9cad199194ad07a8db8b7205499247` | Unqualified |
| Linux x86_64 | `nstool-v1.9.2-ubuntu_x86_64.zip` | `2ab1b484d79199d1bb428cb920a49cece0ae4d7129c80120eaf48b7361785351` | `b77319d6fb1840599b822a710ec9260a9b32bd51e0f32a472852a8fd2430b67c` | Unqualified |
| Windows x86_64 | `nstool-v1.9.2-win_x64.zip` | `34659dc47249a3c00f7fc88a11f4e5ba14dfbec0a6a96b4f3f71368a7e1c9374` | `844648190dd8688098887a369da1126c1b3ab1c2a664fb603b01cb22e76b6ca9` | Unqualified |

The three non-arm64 rows are retained in the manifest for deterministic
target selection, not as support claims. macOS arm64 execution uses the
qualified CPU, open-file, file-size, and core-dump limits. NSCB does not set
`RLIMIT_AS`; no hard memory or process-tree aggregate limit is claimed.
This host has no supported physical-footprint sampler. An optional requested
threshold does not block Inspection; sampling and enforcement remain
unavailable and `InspectionHost::memory_monitoring_status()` reports that
status. No telemetry-triggered termination is claimed. See the production run
record in the qualification evidence.

## NCA3 header interpretation

The relevant packed NCA3 header fields are:

| Offset | Field | NSCB interpretation |
| --- | --- | --- |
| `0x206` | Legacy key generation | First generation candidate |
| `0x207` | Key-area encryption key index (KAEK) | Independent numeric field |
| `0x220` | Modern key generation | Second generation candidate |
| `0x221` | Signature key generation | Preserved separately when present |

The effective key generation is `max(legacy_generation, modern_generation)`.
NSTool's pinned `libpietendo` source implements that rule and reads signature
generation and KAEK separately. NSCB's parser independently derives and
corroborates all these values. The fixture deliberately sets legacy
generation `3`, modern generation `8`, signature generation `5`, and KAEK
index `1`, so substituting the legacy byte for the effective generation or
mixing the other fields is observable. See the [pinned source
implementation](https://github.com/jakcron/libpietendo/blob/5d50d02f8f3b8918bdfbbb599b8c4c1628660d89/src/hac/ContentArchiveHeader.cpp#L123-L127)
and [packed NCA structure](https://github.com/jakcron/libpietendo/blob/5d50d02f8f3b8918bdfbbb599b8c4c1628660d89/include/pietendo/hac/define/nca.h#L110-L124).

## Invocation and containment

NSCB invokes the verified executable directly from a fresh temporary working
directory, without a shell:

```text
-k <temporary-sanitized-keyset> -t nca -v --fstree <absolute-input-path>
```

The temporary keyset contains only the selected header-key entry. The
original key file is not copied into the provider directory. NSTool receives
a cleared environment, null standard input, a controlled working directory,
and process-tree ownership. Standard output is capped at 32 MiB and standard
error at 1 MiB; exceeding either cap invalidates the capture. The operation
deadline is 60 seconds.

On macOS, launch setup applies a 60-second CPU cap, a 64 MiB file-size cap,
at most 64 open descriptors, and disabled core dumps. Any required hard-control
setup failure prevents the child from starting and returns
`provider_containment_unsupported`. NSCB does not set `RLIMIT_AS`, and it does
not claim physical-resident-memory or aggregate process-tree containment.
Physical-footprint sampling is disabled by default because no supported sampler
is available on this host. A host that requests a physical-footprint threshold
continues without sampling or enforcement; the reported status remains
unavailable. This policy follows [ADR-0029](../adr/0029-qualified-native-helper-execution.md).

## Supported NCA profile

| Dimension | Supported value |
| --- | --- |
| Container | Standalone NCA3 |
| NCA header | Encrypted, with a valid header key |
| Content type | Program |
| Distribution | Game Card or Download |
| Effective key generation | `0x00` through `0x20` |
| Partitions | One through four |
| Partition filesystem | PartitionFs (PFS0) |
| Partition hash type | `None` |
| Partition encryption | `None` |
| Extended partition metadata | Unsupported |
| Partition placement | At or after `0xC00`, page aligned |
| Entries per partition | At most 65,536 |
| Normalized path bytes | At most 16 MiB across the partition tree |

Inspection rejects a plaintext NCA3 header with the typed
`unsupported_inspection_profile` error. This restriction applies only to
Inspection; Content Recognition's existing support is unchanged. Clear PFS0
partitions require no partition key. The header key does not authorize
encrypted partition content, title keys, tickets, or general content
decryption. RomFs, hierarchical hash layers, extended metadata, and other
content types are outside this capability.

## Key-file and provider-output rules

The CLI resolves the key source in this order: explicit `--keys <path>`, then
`~/.switch/prod.keys` when the option is omitted. There is no other configured
key-path setting in this release. Embedding callers pass an explicit key path
in `InspectionRequest`.

The bounded text key file may contain `header_key` or `nca_header_key`; either
alias is sufficient, but duplicate aliases with differing values fail
without exposing either value. Provider output parsing rejects every repeated
field, including identical KAEK, SDK, and partition facts. Unknown fields,
contradictory partitions, unreadable-partition warnings, unsupported profiles,
and malformed trees are rejected. Known warnings for missing `title.keys` and
an invalid main signature are retained as warnings; they do not establish
authenticity or verification. Raw provider text is never returned through the
public API or CLI.

NSCB independently parses the NCA header and every PFS0 entry table. Provider
partition offsets, sizes, filesystem, hash, encryption, KAEK, SDK, root name,
directories, files, and file sizes must agree with the Rust-derived facts.
These checks establish structural agreement between two local parsers; they
do not establish that a valid PFS0 table describes authentic content. Input
and key changes are checked through opened-handle identity and metadata
snapshots. Filesystems without stable identity fail closed; an adversary able
to change bytes and restore every observable metadata field remains outside
that detection guarantee.

## Cache and download policy

`InspectionHost::cache_only` never accesses the network.
`InspectionHost::managed_download` permits installation of the digest-pinned
artifact only when an actual inspection needs it; preflight never downloads.
The cache root must be absolute. Each directory enumeration stops at 1,024
entries, and at most 256 pointer candidates are retained for sorting. Lookup,
sequence selection, and cleanup use the same bounds. Cleanup completes its
bounded enumeration and validation before mutating cache state.

Cache objects are immutable and content addressed. Installation verifies the
archive and executable digests, synchronizes where supported, and publishes a
new sequence pointer only after verification. Corrupt objects are quarantined
before repair; a malformed newest pointer does not remove older valid
generations. Cache locking serializes writers. On Unix, object ancestry is
opened relative to verified directories with `openat` and `O_NOFOLLOW`; the
executable is copied from the verified handle into a fresh private runtime
directory and hashed again.

The download client accepts HTTPS only, disables implicit environment proxy
configuration, follows at most five redirects, and requires HTTPS at every
hop. The fixed GitHub release URL may redirect to its release CDN. A single
120-second whole-request deadline starts before connecting and covers
redirects and response-body transfer. Cancellation is checked across request
handling and body reads; DNS or other blocking OS calls may not stop
immediately, so their cancellation latency follows the transport timeout and
OS behavior. The response size is bounded before extraction.

## Capability boundary

NSTool is a read-only observer for this one profile. NSCB has not selected or
qualified an NCA/NSP writer, repacker, package signer, patch engine, or
compatibility-patch provider. Those capabilities remain outside Issue #7 and
must not be inferred from NSTool inspection support.
