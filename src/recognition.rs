//! Bounded recognition of container families and archive representations.
use crate::{ContainerProbeError, ContainerProbeErrorCode};
use serde::Serialize;
use std::{
    fmt,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

/// A request for byte-derived recognition of one regular file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentRecognitionRequest {
    path: PathBuf,
}
impl ContentRecognitionRequest {
    /// Creates a request without keys or host runtime requirements.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
/// Positive top-level structural families, independently of filename conventions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecognizedFamily {
    /// PFS0 package framing.
    Pfs0,
    /// Validated gamecard header, HFS0 hierarchy, and declared card geometry.
    Xci,
    /// Readable supported NCA3 archive header.
    Nca,
    /// NCZ sections and encoded stream framing.
    Ncz,
}
/// Compression representation proof; absence of proof never establishes an uncompressed variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionVariant {
    /// Independently validated NCZ representation.
    Ncz,
    /// No compression representation established.
    NotEstablished,
}
/// Eligibility for consideration by future whole-container package/card-image operations.
/// The complete top-level evidence mapping is:
/// - PFS0 framing alone: `NotEstablished`.
/// - Positively established standalone NCA or NCZ: `Ineligible`.
/// - Validated PFS0 containing independently validated NCZ: `Eligible`.
/// - Validated XCI header and required HFS0 hierarchy, with the RomArea page
///   inside the capacity its RomSize code declares and no later than the
///   declared valid-data end: `Eligible`, including XCZ with independently
///   validated nested NCZ.
/// - Unknown, insufficient, or conflicting evidence: `NotEstablished`.
///
/// Embedded NCA/NCZ never makes its enclosing container ineligible. This scalar
/// grants no execution authorization, implemented-operation readiness, keys,
/// prerequisites, Verification, authenticity, or decoded-content correctness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralEligibility {
    /// Validated package/card container.
    Eligible,
    /// Positively established standalone content archive.
    Ineligible,
    /// Insufficient uncontested structural evidence.
    NotEstablished,
}
/// Observation of validated PFS0 member names, never ticket validity or NSX identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketNameObservation {
    /// At least one name has a case-insensitive .tik suffix.
    Present,
    /// No such name was observed in validated PFS0 metadata.
    NotObserved,
    /// No validated PFS0 metadata applies.
    NotApplicable,
}
/// Separate filename observation; it never changes structural conclusions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionObservation {
    /// Compatible with established evidence.
    Compatible,
    /// Contradicted by established evidence.
    Mismatch,
    /// A supported convention whose precise identity remains unproven.
    NotEstablished,
    /// Not a known content filename convention.
    Unrecognized,
}
/// Typed recognition disposition. Multiple independent top-level claims fail closed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RecognitionOutcome {
    /// Exactly one family established.
    Recognized {
        /// Positive family.
        family: RecognizedFamily,
        /// Independently proven compression representation.
        compression_variant: CompressionVariant,
    },
    /// No supported positive evidence.
    Unknown,
    /// Multiple conflicting positive families.
    Ambiguous {
        /// Families in deterministic probe order.
        families: Vec<RecognizedFamily>,
    },
}
/// Sanitized recognition facts without payload, cryptographic material, or paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContentRecognitionResult {
    /// Byte-derived conclusion independent of the supplied filename.
    pub recognition: RecognitionOutcome,
    /// Future whole-container package/card consideration only; never execution authorization.
    pub package_structure_eligibility: StructuralEligibility,
    /// Filename metadata observation only; never establishes NSX or eligibility.
    pub ticket_name_observation: TicketNameObservation,
    /// Separate extension observation.
    pub extension_observation: ExtensionObservation,
}
/// Stable sanitized operational, malformed-input, and resource failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentRecognitionErrorCode {
    /// Input could not be read.
    InputUnavailable,
    /// Declared framing extends beyond its enclosing span.
    TruncatedInput,
    /// Structural relationships are inconsistent.
    MalformedInput,
    /// A supported structural profile is unavailable.
    UnsupportedStructure,
    /// Cumulative parsing ceiling exceeded.
    LimitExceeded,
    /// Bounded allocation failed.
    ResourceLimitExceeded,
}
impl ContentRecognitionErrorCode {
    /// Stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputUnavailable => "input_unavailable",
            Self::TruncatedInput => "truncated_input",
            Self::MalformedInput => "malformed_input",
            Self::UnsupportedStructure => "unsupported_structure",
            Self::LimitExceeded => "limit_exceeded",
            Self::ResourceLimitExceeded => "resource_limit_exceeded",
        }
    }
}
/// An error retaining no input bytes or OS diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentRecognitionError {
    code: ContentRecognitionErrorCode,
}
impl ContentRecognitionError {
    /// Returns the stable error category.
    pub const fn code(self) -> ContentRecognitionErrorCode {
        self.code
    }
}
impl fmt::Display for ContentRecognitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.as_str())
    }
}
impl std::error::Error for ContentRecognitionError {}
type Result<T> = std::result::Result<T, ContentRecognitionError>;
fn err(code: ContentRecognitionErrorCode) -> ContentRecognitionError {
    ContentRecognitionError { code }
}
use ContentRecognitionErrorCode::{
    LimitExceeded, MalformedInput, TruncatedInput, UnsupportedStructure,
};
pub(crate) fn from_probe_error(e: ContainerProbeError) -> ContentRecognitionError {
    err(match e.code() {
        ContainerProbeErrorCode::InputUnavailable => ContentRecognitionErrorCode::InputUnavailable,
        ContainerProbeErrorCode::TruncatedInput => TruncatedInput,
        ContainerProbeErrorCode::LimitExceeded | ContainerProbeErrorCode::NameTooLong => {
            LimitExceeded
        }
        ContainerProbeErrorCode::ResourceLimitExceeded => {
            ContentRecognitionErrorCode::ResourceLimitExceeded
        }
        _ => MalformedInput,
    })
}
const META_LIMIT: u64 = 16 * 1024 * 1024;
const READ_LIMIT: u64 = 256 * 1024 * 1024;
const ENTRY_LIMIT: u64 = 65_536;
/// Cumulative structural work-unit ceiling of 1,000,000 units for compressed
/// layouts.
///
/// Each NCZ section descriptor, NCZBLOCK block-size descriptor, Zstandard
/// frame, and Zstandard block header costs one unit, and the counter is
/// shared by every nested parse of one input. Only parser work is capped;
/// the metadata, read, entry, and name byte ceilings are unchanged. The
/// ceiling binds because every counted item also charges the metadata budget
/// at three bytes at minimum, so that budget alone admits at most about
/// 5.6 million units and this limit sits below it.
const WORK_LIMIT: u64 = 1_000_000;
/// File offset of the root partition header in the supported gamecard profile.
/// A card image starts at the physical 0x1000 layout origin, so the documented
/// physical root at 0x10000 lands at file offset 0xF000.
const ROOT_PLACEMENT: u64 = 0xF000;
/// Root partition names understood by the supported gamecard profile.
const ROOT_NAMES: [&str; 4] = ["update", "normal", "logo", "secure"];
/// Root partitions every supported gamecard carries.
const REQUIRED_NAMES: [&str; 3] = ["update", "normal", "secure"];
#[derive(Default)]
struct Budget {
    metadata: u64,
    reads: u64,
    entries: u64,
    names: u64,
    work: u64,
}
fn charge(value: &mut u64, n: u64, limit: u64) -> Result<()> {
    *value = value.checked_add(n).ok_or(err(LimitExceeded))?;
    if *value > limit {
        return Err(err(LimitExceeded));
    }
    Ok(())
}
struct Parser<'a, R> {
    reader: &'a mut R,
    budget: Budget,
}
/// One validated HFS0 member table.
struct Members {
    /// Calculated header size in bytes before any writer alignment padding.
    header_size: u64,
    /// Data span of each member in table order.
    spans: Vec<(u64, u64)>,
    /// Name of each member in table order.
    names: Vec<String>,
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(err(MalformedInput))
}
fn u32le(b: &[u8]) -> u64 {
    u32::from_le_bytes(b.try_into().expect("fixed field")) as u64
}
fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("fixed field"))
}
/// Declared card capacity, in 0x200-byte pages, for the documented RomSize
/// codes: 0xFA 1 GiB, 0xF8 2 GiB, 0xF0 4 GiB, 0xE0 8 GiB, 0xE1 16 GiB, and
/// 0xE2 32 GiB. Returns `None` for a code that does not name a supported
/// card size.
fn rom_size_pages(code: u64) -> Option<u64> {
    Some(match code {
        0xFA => 1 << 21,
        0xF8 => 1 << 22,
        0xF0 => 1 << 23,
        0xE0 => 1 << 24,
        0xE1 => 1 << 25,
        0xE2 => 1 << 26,
        _ => return None,
    })
}
impl<R: Read + Seek> Parser<'_, R> {
    fn read(&mut self, pos: u64, end: u64, n: usize) -> Result<Vec<u8>> {
        if add(pos, n as u64)? > end {
            return Err(err(TruncatedInput));
        }
        charge(&mut self.budget.metadata, n as u64, META_LIMIT)?;
        charge(&mut self.budget.reads, n as u64, READ_LIMIT)?;
        let mut b = Vec::new();
        b.try_reserve_exact(n)
            .map_err(|_| err(ContentRecognitionErrorCode::ResourceLimitExceeded))?;
        b.resize(n, 0);
        self.reader
            .seek(SeekFrom::Start(pos))
            .map_err(|_| err(ContentRecognitionErrorCode::InputUnavailable))?;
        self.reader.read_exact(&mut b).map_err(|e| {
            err(if e.kind() == std::io::ErrorKind::UnexpectedEof {
                TruncatedInput
            } else {
                ContentRecognitionErrorCode::InputUnavailable
            })
        })?;
        Ok(b)
    }
    fn marker(&mut self, start: u64, end: u64, offset: u64, magic: &[u8]) -> Result<bool> {
        let pos = add(start, offset)?;
        if add(pos, magic.len() as u64)? > end {
            return Ok(false);
        }
        Ok(self.read(pos, end, magic.len())? == magic)
    }
    fn members(&mut self, n: u64) -> Result<()> {
        charge(&mut self.budget.entries, n, ENTRY_LIMIT)
    }
    /// Validates a table, names, hash-target spans, and immediate-parent bounds.
    /// Returns the calculated header size, and each member's span and name in
    /// table order.
    fn hfs(&mut self, start: u64, end: u64) -> Result<Members> {
        let h = self.read(start, end, 16)?;
        if &h[..4] != b"HFS0" || h[12..].iter().any(|b| *b != 0) {
            return Err(err(MalformedInput));
        }
        let count = u32le(&h[4..8]);
        self.members(count)?;
        let names = u32le(&h[8..12]);
        if names > META_LIMIT || (count == 0) != (names == 0) {
            return Err(err(MalformedInput));
        }
        let table = count.checked_mul(64).ok_or(err(MalformedInput))?;
        let size = add(add(16, table)?, names)?;
        let data = add(start, size)?;
        let b = self.read(
            add(start, 16)?,
            end,
            usize::try_from(add(table, names)?).map_err(|_| err(LimitExceeded))?,
        )?;
        let strings = &b[table as usize..];
        if !strings.is_empty()
            && (strings.last() != Some(&0) || std::str::from_utf8(strings).is_err())
        {
            return Err(err(MalformedInput));
        }
        let mut spans = Vec::new();
        let mut names_out = Vec::new();
        spans
            .try_reserve_exact(count as usize)
            .map_err(|_| err(ContentRecognitionErrorCode::ResourceLimitExceeded))?;
        names_out
            .try_reserve_exact(count as usize)
            .map_err(|_| err(ContentRecognitionErrorCode::ResourceLimitExceeded))?;
        let mut previous = 0;
        for r in b[..table as usize].as_chunks::<64>().0.iter() {
            let off = u64le(&r[..8]);
            let len = u64le(&r[8..16]);
            let name = u32le(&r[16..20]) as usize;
            let hashed = u32le(&r[20..24]);
            let target = u64le(&r[24..32]);
            if add(target, hashed)? > len || off < previous {
                return Err(err(MalformedInput));
            }
            let tail = strings.get(name..).ok_or(err(MalformedInput))?;
            if name > 0 && strings[name - 1] != 0 {
                return Err(err(MalformedInput));
            }
            let length = tail
                .iter()
                .position(|b| *b == 0)
                .ok_or(err(MalformedInput))?;
            if length == 0 || length > 4096 {
                return Err(err(MalformedInput));
            }
            charge(&mut self.budget.names, length as u64, META_LIMIT)?;
            let mut member_name = String::new();
            member_name
                .try_reserve_exact(length)
                .map_err(|_| err(ContentRecognitionErrorCode::ResourceLimitExceeded))?;
            member_name
                .push_str(std::str::from_utf8(&tail[..length]).map_err(|_| err(MalformedInput))?);
            names_out.push(member_name);
            previous = add(off, len)?;
            let s = add(data, off)?;
            let e = add(s, len)?;
            if e > end {
                return Err(err(TruncatedInput));
            }
            spans.push((s, e));
        }
        Ok(Members {
            header_size: size,
            spans,
            names: names_out,
        })
    }
    /// Validates the supported gamecard image profile.
    ///
    /// The root partition must sit at its documented placement, use only the
    /// known root names once each, keep the update, normal, and secure
    /// partitions, and bound one nested HFS0 per entry. An ordinary card must
    /// also relate the RomArea page address to the secure partition placement.
    /// Compressed cards reuse the source card header, so a validated NCZ member
    /// permits a copied address that differs from the rebuilt secure partition.
    /// A copied address must still reach the documented root placement, start
    /// inside the capacity declared by its documented RomSize code and no
    /// later than the declared valid-data end, and keep that valid-data end
    /// within the same capacity.
    fn xci(&mut self, end: u64) -> Result<bool> {
        let h = self.read(0, end, 0x200)?;
        let page = u32le(&h[0x104..0x108]);
        let root = u64le(&h[0x130..0x138]);
        let declared = u64le(&h[0x138..0x140]);
        if root != ROOT_PLACEMENT {
            return Err(err(UnsupportedStructure));
        }
        if declared < 16 || add(root, declared)? > end {
            return Err(err(MalformedInput));
        }
        let members = self.hfs(root, end)?;
        if members.header_size > declared || members.spans.is_empty() {
            return Err(err(MalformedInput));
        }
        if members.names.len() > ROOT_NAMES.len() {
            return Err(err(UnsupportedStructure));
        }
        let mut seen = Vec::new();
        for name in &members.names {
            if !ROOT_NAMES.contains(&name.as_str()) || seen.contains(&name.as_str()) {
                return Err(err(UnsupportedStructure));
            }
            seen.push(name.as_str());
        }
        if !REQUIRED_NAMES.iter().all(|name| seen.contains(name)) {
            return Err(err(UnsupportedStructure));
        }
        let mut compressed = false;
        let mut secure_start = 0;
        for (name, &(start, stop)) in members.names.iter().zip(&members.spans) {
            if start < add(root, declared)? || !start.is_multiple_of(0x200) {
                return Err(err(MalformedInput));
            }
            if name == "secure" {
                secure_start = start;
            }
            let partition = self.hfs(start, stop)?;
            for (begin, finish) in partition.spans {
                let ncz = self.ncz(begin, finish)?;
                compressed |= ncz;
                if !ncz {
                    self.optional_nca(begin, finish)?;
                }
            }
        }
        // A RomArea page address counts 0x200-byte pages from the physical card
        // origin, which sits 0x1000 bytes before this file's first byte.
        let secure = add(secure_start, 0x1000)?;
        if compressed {
            let minimum_page = (ROOT_PLACEMENT + 0x1000) / 0x200;
            if page < minimum_page {
                return Err(err(UnsupportedStructure));
            }
            // The copied address must also fit the geometry the card header
            // declares: a documented RomSize capacity, a ROM area that starts
            // inside that capacity and no later than the valid-data end, and a
            // valid-data end the card can represent.
            let capacity = rom_size_pages(u64::from(h[0x10D])).ok_or(err(UnsupportedStructure))?;
            let valid_end = u32le(&h[0x118..0x11c]);
            if page >= capacity || valid_end > capacity || page > valid_end {
                return Err(err(UnsupportedStructure));
            }
        } else if page != secure / 0x200 {
            return Err(err(UnsupportedStructure));
        }
        Ok(compressed)
    }
    /// Validates NCZ layout without reading key/counter fields or decoding encoded payload.
    fn ncz(&mut self, start: u64, end: u64) -> Result<bool> {
        if !self.marker(start, end, 0x4000, b"NCZSECTN")? {
            return Ok(false);
        }
        let count = u64le(&self.read(add(start, 0x4008)?, end, 8)?);
        if count == 0 {
            return Err(err(MalformedInput));
        }
        self.members(count)?;
        let table = count.checked_mul(64).ok_or(err(MalformedInput))?;
        let mut pos = add(start, 0x4010)?;
        let data = add(pos, table)?;
        if data > end {
            return Err(err(TruncatedInput));
        }
        // Charge opaque key/counter slots as metadata, but never read or retain them.
        charge(
            &mut self.budget.metadata,
            count.checked_mul(32).ok_or(err(LimitExceeded))?,
            META_LIMIT,
        )?;
        let mut prior = None;
        for _ in 0..count {
            charge(&mut self.budget.work, 1, WORK_LIMIT)?;
            let r = self.read(pos, end, 32)?;
            let off = u64le(&r[..8]);
            let size = u64le(&r[8..16]);
            let crypto = u64le(&r[16..24]);
            if size == 0 || !matches!(crypto, 1 | 3 | 4) || r[24..].iter().any(|b| *b != 0) {
                return Err(err(MalformedInput));
            }
            if let Some(p) = prior
                && off != p
            {
                return Err(err(UnsupportedStructure));
            }
            prior = Some(add(off, size)?);
            pos = add(pos, 64)?;
        }
        let decoded = prior
            .ok_or(err(MalformedInput))?
            .checked_sub(0x4000)
            .filter(|n| *n > 0)
            .ok_or(err(MalformedInput))?;
        if self.marker(data, end, 0, b"NCZBLOCK")? {
            let h = self.read(data, end, 24)?;
            if h[8..11] != [2, 1, 0] || !(14..=32).contains(&h[11]) {
                return Err(err(MalformedInput));
            }
            let block = 1u64 << h[11];
            let count = u32le(&h[12..16]);
            let size = u64le(&h[16..24]);
            if size != decoded || count != size.div_ceil(block) {
                return Err(err(MalformedInput));
            }
            self.members(count)?;
            let list_start = add(data, 24)?;
            let list_bytes = count.checked_mul(4).ok_or(err(LimitExceeded))?;
            let mut cursor = add(list_start, list_bytes)?;
            if cursor > end {
                return Err(err(TruncatedInput));
            }
            for i in 0..count {
                charge(&mut self.budget.work, 1, WORK_LIMIT)?;
                let len = u32le(&self.read(add(list_start, i * 4)?, end, 4)?);
                let expected = (size - i * block).min(block);
                if len == 0 || len > expected {
                    return Err(err(MalformedInput));
                }
                let next = add(cursor, len)?;
                if next > end {
                    return Err(err(TruncatedInput));
                }
                if len < expected {
                    self.frames(cursor, next, Some(expected))?;
                }
                cursor = next;
            }
            if cursor != end {
                return Err(err(MalformedInput));
            }
        } else {
            self.frames(data, end, Some(decoded))?;
        }
        Ok(true)
    }
    /// Walks Zstandard headers and encoded block spans; checksums are bounded, not verified.
    fn frames(&mut self, mut pos: u64, end: u64, expected: Option<u64>) -> Result<()> {
        let mut total = 0u64;
        let mut known = true;
        let mut frames = 0;
        while pos < end {
            frames += 1;
            charge(&mut self.budget.work, 1, WORK_LIMIT)?;
            let h = self.read(pos, end, 5)?;
            pos = add(pos, 5)?;
            if h[..4] != [0x28, 0xb5, 0x2f, 0xfd] || h[4] & 0x18 != 0 {
                return Err(err(MalformedInput));
            }
            let d = h[4];
            let single = d & 0x20 != 0;
            let checksum = d & 4 != 0;
            let window = if !single {
                let w = self.read(pos, end, 1)?[0];
                pos = add(pos, 1)?;
                let base = 1u64 << (10 + (w >> 3));
                base + (base / 8) * u64::from(w & 7)
            } else {
                u64::MAX
            };
            let dictionary = [0, 1, 2, 4][(d & 3) as usize];
            if dictionary > 0 {
                let id = self.read(pos, end, dictionary)?;
                pos = add(pos, dictionary as u64)?;
                if id.iter().any(|b| *b != 0) {
                    return Err(err(UnsupportedStructure));
                }
            }
            let fcs = match d >> 6 {
                0 => usize::from(single),
                1 => 2,
                2 => 4,
                _ => 8,
            };
            let declared = if fcs > 0 {
                let b = self.read(pos, end, fcs)?;
                pos = add(pos, fcs as u64)?;
                let mut v = 0u64;
                for (i, b) in b.iter().enumerate() {
                    v |= u64::from(*b) << (i * 8);
                }
                if fcs == 2 {
                    v += 256;
                }
                Some(v)
            } else {
                None
            };
            let max_block = window
                .min(declared.filter(|_| single).unwrap_or(u64::MAX))
                .min(128 * 1024);
            let mut plain = 0u64;
            let mut all_plain = true;
            loop {
                charge(&mut self.budget.work, 1, WORK_LIMIT)?;
                let b = self.read(pos, end, 3)?;
                pos = add(pos, 3)?;
                let v = u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16);
                let kind = (v >> 1) & 3;
                let len = u64::from(v >> 3);
                if kind == 3 || len > max_block {
                    return Err(err(MalformedInput));
                }
                if kind == 2 {
                    all_plain = false;
                    if len == 0 {
                        return Err(err(MalformedInput));
                    }
                } else {
                    plain = add(plain, len)?;
                }
                pos = add(pos, if kind == 1 { 1 } else { len })?;
                if pos > end {
                    return Err(err(TruncatedInput));
                }
                if v & 1 != 0 {
                    break;
                }
            }
            if checksum {
                self.read(pos, end, 4)?;
                pos = add(pos, 4)?;
            }
            if all_plain && declared.is_some_and(|n| n != plain) {
                return Err(err(MalformedInput));
            }
            if let Some(n) = declared {
                total = add(total, n)?;
            } else if all_plain {
                total = add(total, plain)?;
            } else {
                known = false;
            }
        }
        if frames == 0 || (known && expected.is_some_and(|n| n != total)) {
            return Err(err(MalformedInput));
        }
        Ok(())
    }
    /// Supports readable NCA3 headers with ordinary, nonextended FS semantics.
    fn nca(&mut self, start: u64, end: u64) -> Result<bool> {
        if !self.marker(start, end, 0x200, b"NCA3")? {
            return Ok(false);
        }
        let h = self.read(start, end, 0xc00)?;
        let block: [u8; crate::nca::HEADER_SIZE] =
            h.as_slice().try_into().map_err(|_| err(MalformedInput))?;
        let header =
            crate::nca::parse_header_block(&block, end - start).map_err(|error| match error {
                crate::nca::HeaderError::UnsupportedFormat
                | crate::nca::HeaderError::MalformedInput => err(MalformedInput),
                crate::nca::HeaderError::TruncatedInput => err(TruncatedInput),
                crate::nca::HeaderError::InputUnavailable => err(MalformedInput),
            })?;
        for partition in &header.partitions {
            let i = usize::from(partition.index);
            let fs = &h[0x400 + i * 0x200..0x600 + i * 0x200];
            // Extended patch/sparse/compression/metadata-hash layouts need separate qualification.
            if fs[5] != 0
                || fs[0x100..0x140].iter().any(|b| *b != 0)
                || fs[0x148..0x200].iter().any(|b| *b != 0)
                || fs[4] > 3
            {
                return Err(err(UnsupportedStructure));
            }
            // Atmosphere names byte 2 FsType and byte 3 HashType. Older
            // hactool names these partition_type and fs_type respectively.
            if fs[2] != 1 || fs[3] != 2 {
                return Err(err(UnsupportedStructure));
            }
            let block = u32le(&fs[0x28..0x2c]);
            let layers = u32le(&fs[0x2c..0x30]);
            if !block.is_power_of_two() || block < 32 || !(2..=5).contains(&layers) {
                return Err(err(MalformedInput));
            }
            let mut last = 0;
            let mut previous_size = None;
            for layer in 0..layers as usize {
                let field = 0x30 + layer * 16;
                let offset = u64le(&fs[field..field + 8]);
                let length = u64le(&fs[field + 8..field + 16]);
                if offset > i64::MAX as u64
                    || length == 0
                    || length > i64::MAX as u64
                    || offset < last
                    || add(offset, length)? > partition.size
                {
                    return Err(err(MalformedInput));
                }
                if let Some(parent_size) = previous_size
                    && length
                        .div_ceil(block)
                        .checked_mul(32)
                        .is_none_or(|n| n > parent_size)
                {
                    return Err(err(MalformedInput));
                }
                previous_size = Some(length);
                last = add(offset, length)?;
            }
            if fs[0x30 + layers as usize * 16..0x100]
                .iter()
                .any(|b| *b != 0)
            {
                return Err(err(MalformedInput));
            }
        }
        Ok(true)
    }
    /// Parses an optional nested NCA member.
    ///
    /// Truncated, malformed, or unsupported optional NCA bytes leave an
    /// independently proven container intact. Input and budget failures remain
    /// typed errors.
    fn optional_nca(&mut self, start: u64, end: u64) -> Result<()> {
        match self.nca(start, end) {
            Ok(_) => Ok(()),
            Err(error)
                if matches!(
                    error.code(),
                    MalformedInput | TruncatedInput | UnsupportedStructure
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}
pub(crate) fn recognize<R: Read + Seek>(
    reader: &mut R,
    size: u64,
    path: &Path,
) -> Result<ContentRecognitionResult> {
    let mut p = Parser {
        reader,
        budget: Budget::default(),
    };
    let mut claims = Vec::new();
    let mut ticket = TicketNameObservation::NotApplicable;
    if p.marker(0, size, 0, b"PFS0")? {
        // The existing probe is unchanged; account its tables before invoking it.
        let h = p.read(0, size, 16)?;
        let count = u32le(&h[4..8]);
        p.members(count)?;
        let metadata = add(
            count.checked_mul(24).ok_or(err(LimitExceeded))?,
            u32le(&h[8..12]),
        )?;
        charge(&mut p.budget.metadata, metadata, META_LIMIT)?;
        charge(&mut p.budget.reads, add(metadata, 16)?, READ_LIMIT)?;
        let result = crate::pfs0::probe(p.reader, size).map_err(from_probe_error)?;
        ticket = TicketNameObservation::NotObserved;
        let mut compressed = false;
        for e in result.entries {
            charge(&mut p.budget.names, e.name.len() as u64, META_LIMIT)?;
            if e.name.to_ascii_lowercase().ends_with(".tik") {
                ticket = TicketNameObservation::Present;
            }
            let end = add(e.file_offset, e.size)?;
            let ncz = p.ncz(e.file_offset, end)?;
            compressed |= ncz;
            if !ncz {
                p.optional_nca(e.file_offset, end)?;
            }
        }
        claims.push((RecognizedFamily::Pfs0, compressed));
    }
    if p.marker(0, size, 0x100, b"HEAD")? {
        let compressed = p.xci(size)?;
        claims.push((RecognizedFamily::Xci, compressed));
    }
    let ncz = p.ncz(0, size)?;
    if ncz {
        claims.push((RecognizedFamily::Ncz, true));
    }
    // NCZ preserves the original NCA header. Its archive size describes the
    // reconstructed image, not this representation's physical span, so it
    // cannot establish an independent standalone NCA claim.
    if !ncz && p.nca(0, size)? {
        claims.push((RecognizedFamily::Nca, false));
    }
    let (recognition, eligibility) = match claims.as_slice() {
        [] => (
            RecognitionOutcome::Unknown,
            StructuralEligibility::NotEstablished,
        ),
        [(family, compressed)] => (
            RecognitionOutcome::Recognized {
                family: *family,
                compression_variant: if *compressed {
                    CompressionVariant::Ncz
                } else {
                    CompressionVariant::NotEstablished
                },
            },
            match family {
                RecognizedFamily::Nca | RecognizedFamily::Ncz => StructuralEligibility::Ineligible,
                RecognizedFamily::Pfs0 if !compressed => StructuralEligibility::NotEstablished,
                _ => StructuralEligibility::Eligible,
            },
        ),
        _ => (
            RecognitionOutcome::Ambiguous {
                families: claims.iter().map(|c| c.0).collect(),
            },
            StructuralEligibility::NotEstablished,
        ),
    };
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase);
    let extension_observation = match ext.as_deref() {
        Some("nsp" | "nsz" | "nsx" | "xci" | "xcz" | "nca" | "ncz") => match &recognition {
            RecognitionOutcome::Recognized {
                family,
                compression_variant,
            } => {
                let ext = ext.as_deref().unwrap_or("");
                let compatible = matches!(
                    (family, ext),
                    (RecognizedFamily::Pfs0, "nsp" | "nsz" | "nsx")
                        | (RecognizedFamily::Xci, "xci" | "xcz")
                        | (RecognizedFamily::Nca, "nca")
                        | (RecognizedFamily::Ncz, "ncz")
                );
                if !compatible
                    || (*compression_variant == CompressionVariant::Ncz
                        && matches!(ext, "nsp" | "xci"))
                {
                    ExtensionObservation::Mismatch
                } else if ext == "nsx"
                    || (*compression_variant == CompressionVariant::NotEstablished
                        && matches!(ext, "nsp" | "nsz" | "xci" | "xcz"))
                {
                    ExtensionObservation::NotEstablished
                } else {
                    ExtensionObservation::Compatible
                }
            }
            _ => ExtensionObservation::NotEstablished,
        },
        _ => ExtensionObservation::Unrecognized,
    };
    Ok(ContentRecognitionResult {
        recognition,
        package_structure_eligibility: eligibility,
        ticket_name_observation: ticket,
        extension_observation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn parse(b: Vec<u8>, name: &str) -> Result<ContentRecognitionResult> {
        recognize(&mut Cursor::new(&b), b.len() as u64, Path::new(name))
    }
    fn ncz(block: bool) -> Vec<u8> {
        let mut b = vec![0; 0x4000];
        b.extend_from_slice(b"NCZSECTN");
        b.extend_from_slice(&1u64.to_le_bytes());
        for v in [0x4000u64, 16, 1, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[0; 32]);
        if block {
            b.extend_from_slice(b"NCZBLOCK");
            b.extend_from_slice(&[2, 1, 0, 14]);
            b.extend_from_slice(&1u32.to_le_bytes());
            b.extend_from_slice(&16u64.to_le_bytes());
            b.extend_from_slice(&16u32.to_le_bytes());
            b.extend_from_slice(&[0; 16]);
        } else {
            b.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 16, 0x81, 0, 0]);
            b.extend_from_slice(&[0; 16]);
        }
        b
    }
    /// Two concatenated single-segment frames whose declared content fills
    /// both raw blocks.
    fn ncz_two_frames() -> Vec<u8> {
        let mut b = vec![0; 0x4000];
        b.extend_from_slice(b"NCZSECTN");
        b.extend_from_slice(&1u64.to_le_bytes());
        for v in [0x4000u64, 32, 1, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[0; 32]);
        for _ in 0..2 {
            b.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 16, 0x81, 0, 0]);
            b.extend_from_slice(&[0; 16]);
        }
        b
    }
    fn package(member: &[u8], name: &str) -> Vec<u8> {
        let mut b = b"PFS0".to_vec();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&((name.len() + 1) as u32).to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&(member.len() as u64).to_le_bytes());
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(name.as_bytes());
        b.push(0);
        b.extend_from_slice(member);
        b
    }
    /// Builds one HFS0 image whose members are placed in order after the
    /// header, with the name table zero-padded so the header ends on a 0x200
    /// boundary. Returns the image and its aligned header size.
    fn hfs_image(members: &[(&str, &[u8])]) -> (Vec<u8>, u64) {
        let mut table = Vec::new();
        let mut strings = Vec::new();
        let mut data = Vec::new();
        let mut offset = 0u64;
        for (name, member) in members {
            table.extend_from_slice(&offset.to_le_bytes());
            table.extend_from_slice(&(member.len() as u64).to_le_bytes());
            table.extend_from_slice(&(strings.len() as u32).to_le_bytes());
            table.extend_from_slice(&0u32.to_le_bytes());
            table.extend_from_slice(&0u64.to_le_bytes());
            table.extend_from_slice(&[0; 32]);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            data.extend_from_slice(member);
            offset += member.len() as u64;
        }
        let mut header_size = 16 + table.len() + strings.len();
        while header_size % 0x200 != 0 {
            strings.push(0);
            header_size += 1;
        }
        let mut b = b"HFS0".to_vec();
        b.extend_from_slice(&(members.len() as u32).to_le_bytes());
        b.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&table);
        b.extend_from_slice(&strings);
        b.extend_from_slice(&data);
        (b, header_size as u64)
    }

    /// Builds the standard supported card image: update, normal, and secure
    /// partitions inside the documented root placement, each carrying one copy
    /// of the provided member bytes with a consistent RomArea page address.
    fn xci(member: &[u8]) -> Vec<u8> {
        card(
            &[("update", member), ("normal", member), ("secure", member)],
            0xF000,
            None,
        )
    }

    /// Builds one partition image: a single member inside a 0x200-padded HFS0
    /// so the following partition starts stay aligned.
    fn partition(member: &[u8]) -> Vec<u8> {
        let (mut b, _) = hfs_image(&[("arbitrary", member)]);
        while b.len() % 0x200 != 0 {
            b.push(0);
        }
        b
    }

    /// Builds a card image that follows the documented gamecard layout: the
    /// card header at 0x0 with HEAD at 0x100, the root HFS0 at the requested
    /// file placement, and one bounded partition HFS0 per root entry. The
    /// RomAreaStartPageAddress page is derived from the secure partition
    /// placement unless the caller overrides it.
    fn card(parts: &[(&str, &[u8])], root: u64, rom_page: Option<u64>) -> Vec<u8> {
        let images: Vec<Vec<u8>> = parts.iter().map(|(_, member)| partition(member)).collect();
        let owned: Vec<(&str, &[u8])> = parts
            .iter()
            .zip(images.iter())
            .map(|((name, _), image)| (*name, image.as_slice()))
            .collect();
        let (root_image, header_size) = hfs_image(&owned);
        let mut b = vec![0u8; usize::try_from(root).expect("test placement fits usize")];
        if b.len() < 0x200 {
            b.resize(0x200, 0);
        }
        b[0x100..0x104].copy_from_slice(b"HEAD");
        b[0x10D] = 0xFA; // Declares the 1 GiB standard supported card size.
        // Valid data reaching the declared 1 GiB capacity end.
        b[0x118..0x11c].copy_from_slice(&0x20_0000u32.to_le_bytes());
        b.extend_from_slice(&root_image);
        let mut offset = root + header_size;
        let mut secure = None;
        for ((name, _), image) in parts.iter().zip(images.iter()) {
            if *name == "secure" {
                secure = Some(offset);
            }
            offset += image.len() as u64;
        }
        let page = match (rom_page, secure) {
            (Some(page), _) => page,
            (None, Some(start)) => (start + 0x1000) / 0x200,
            (None, None) => 0x80,
        };
        b[0x104..0x108].copy_from_slice(&(page as u32).to_le_bytes());
        b[0x130..0x138].copy_from_slice(&root.to_le_bytes());
        b[0x138..0x140].copy_from_slice(&header_size.to_le_bytes());
        b
    }
    fn nca() -> Vec<u8> {
        let mut b = vec![0; 0xe00];
        b[0x200..0x204].copy_from_slice(b"NCA3");
        b[0x208..0x210].copy_from_slice(&0xe00u64.to_le_bytes());
        b[0x240..0x244].copy_from_slice(&6u32.to_le_bytes());
        b[0x244..0x248].copy_from_slice(&7u32.to_le_bytes());
        b[0x400] = 2;
        b[0x402] = 1;
        b[0x403] = 2;
        b[0x404] = 1;
        b[0x428..0x42c].copy_from_slice(&0x200u32.to_le_bytes());
        b[0x42c..0x430].copy_from_slice(&2u32.to_le_bytes());
        b[0x438..0x440].copy_from_slice(&32u64.to_le_bytes());
        b[0x440..0x448].copy_from_slice(&32u64.to_le_bytes());
        b[0x448..0x450].copy_from_slice(&16u64.to_le_bytes());
        b
    }
    #[test]
    fn ncz_preserved_readable_nca_header_is_not_a_standalone_claim() {
        for block in [false, true] {
            let mut archive = ncz(block);
            let original = nca();
            archive[..0xc00].copy_from_slice(&original[..0xc00]);
            archive[0x208..0x210].copy_from_slice(&0x4010u64.to_le_bytes());
            assert_ne!(archive.len() as u64, 0x4010);
            let standalone = parse(archive.clone(), "a.ncz").unwrap();
            assert!(matches!(
                standalone.recognition,
                RecognitionOutcome::Recognized {
                    family: RecognizedFamily::Ncz,
                    ..
                }
            ));
            assert_eq!(
                standalone.package_structure_eligibility,
                StructuralEligibility::Ineligible
            );
            for (container, family) in [
                (package(&archive, "arbitrary"), RecognizedFamily::Pfs0),
                (xci(&archive), RecognizedFamily::Xci),
            ] {
                let result = parse(container, "a.bin").unwrap();
                assert!(
                    matches!(result.recognition, RecognitionOutcome::Recognized { family: actual, compression_variant: CompressionVariant::Ncz } if actual == family)
                );
                assert_eq!(
                    result.package_structure_eligibility,
                    StructuralEligibility::Eligible
                );
            }
        }
    }
    #[test]
    fn empty_xci_root_does_not_establish_required_partition_hierarchy() {
        let mut bytes = xci(&[0; 8]);
        bytes[0xF004..0xF00C].fill(0);
        assert_eq!(parse(bytes, "a.xci").unwrap_err().code(), MalformedInput);
    }
    #[test]
    fn zstd_without_content_size_checks_derivable_raw_and_rle_totals() {
        for rle in [false, true] {
            let mut bytes = ncz(false);
            bytes.truncate(0x4050);
            // Non-single-segment frame, absent FCS, 1 KiB window; last raw/RLE
            // block represents sixteen bytes. No entropy decoding is needed.
            bytes.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0]);
            bytes.extend_from_slice(&[if rle { 0x83 } else { 0x81 }, 0, 0]);
            bytes.extend_from_slice(&vec![0; if rle { 1 } else { 16 }]);
            assert!(parse(bytes.clone(), "a.ncz").is_ok());
            bytes[0x4018..0x4020].copy_from_slice(&17u64.to_le_bytes());
            assert_eq!(parse(bytes, "a.ncz").unwrap_err().code(), MalformedInput);
        }
    }
    #[test]
    fn positive_top_level_mapping_and_ticket_independence() {
        for block in [false, true] {
            let archive = ncz(block);
            let a = parse(archive.clone(), "a.ncz").unwrap();
            assert_eq!(
                a.package_structure_eligibility,
                StructuralEligibility::Ineligible
            );
            for name in ["unrelated", "ticket.tik"] {
                let b = package(&archive, name);
                let r = parse(b.clone(), "a.nsz").unwrap();
                assert_eq!(
                    r.package_structure_eligibility,
                    StructuralEligibility::Eligible
                );
                let other = parse(b, "a.nsx").unwrap();
                assert_eq!(r.recognition, other.recognition);
                assert_eq!(
                    r.package_structure_eligibility,
                    other.package_structure_eligibility
                );
                assert_eq!(
                    r.ticket_name_observation,
                    if name.ends_with(".tik") {
                        TicketNameObservation::Present
                    } else {
                        TicketNameObservation::NotObserved
                    }
                );
            }
            assert_eq!(
                parse(xci(&archive), "a.xcz")
                    .unwrap()
                    .package_structure_eligibility,
                StructuralEligibility::Eligible
            );
        }
        assert_eq!(
            parse(nca(), "a.nca").unwrap().package_structure_eligibility,
            StructuralEligibility::Ineligible
        );
        assert_eq!(
            parse(package(&nca(), "n"), "a.nsp")
                .unwrap()
                .package_structure_eligibility,
            StructuralEligibility::NotEstablished
        );
        assert_eq!(
            parse(xci(&nca()), "a.xci")
                .unwrap()
                .package_structure_eligibility,
            StructuralEligibility::Eligible
        );
    }
    #[test]
    fn unknown_and_polyglot_ambiguity_fail_closed() {
        let r = parse(vec![0; 0x5000], "a.nca").unwrap();
        assert_eq!(r.recognition, RecognitionOutcome::Unknown);
        // One file can carry both a complete PFS0 frame and the supported
        // card profile: the card signature area doubles as PFS0 metadata.
        let mut b = xci(&[0; 8]);
        b[..4].copy_from_slice(b"PFS0");
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[8..12].copy_from_slice(&2u32.to_le_bytes());
        b[12..16].copy_from_slice(&[0; 4]);
        let span = b.len() as u64 - 42;
        b[16..24].copy_from_slice(&0u64.to_le_bytes());
        b[24..32].copy_from_slice(&span.to_le_bytes());
        b[32..36].copy_from_slice(&0u32.to_le_bytes());
        b[36..40].copy_from_slice(&0u32.to_le_bytes());
        b[40..42].copy_from_slice(b"a\0");
        let r = parse(b, "a.nsp").unwrap();
        assert!(matches!(
            r.recognition,
            RecognitionOutcome::Ambiguous { .. }
        ));
        assert_eq!(
            r.package_structure_eligibility,
            StructuralEligibility::NotEstablished
        );
    }
    #[test]
    fn ncz_truncation_lists_offsets_and_frames_are_checked() {
        for cut in [0x4008, 0x4010, 0x4030, 0x4050, 0x4058] {
            let mut b = ncz(true);
            b.truncate(cut);
            assert!(parse(b, "a.ncz").is_err());
        }
        let mut b = ncz(true);
        b[0x4068..0x406c].copy_from_slice(&17u32.to_le_bytes());
        assert_eq!(parse(b, "a.ncz").unwrap_err().code(), MalformedInput);
        let mut b = ncz(false);
        b[0x4050] = 0;
        assert_eq!(parse(b, "a.ncz").unwrap_err().code(), MalformedInput);
        let mut b = ncz(false);
        b[0x4010..0x4018].copy_from_slice(&0x5000u64.to_le_bytes());
        assert!(parse(b, "a.ncz").is_err());
    }
    #[test]
    fn cumulative_limits_and_sanitized_failures() {
        let mut b = b"PFS0".to_vec();
        b.extend_from_slice(&65537u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        assert_eq!(parse(b, "secret.nsp").unwrap_err().code(), LimitExceeded);
        let mut ledger = Budget::default();
        charge(&mut ledger.metadata, META_LIMIT, META_LIMIT).unwrap();
        assert_eq!(
            charge(&mut ledger.metadata, 1, META_LIMIT)
                .unwrap_err()
                .code(),
            LimitExceeded
        );
        assert_eq!(err(MalformedInput).to_string(), "malformed_input");
    }

    #[test]
    fn extensions_never_admit_or_reclassify_bytes() {
        let bytes = package(&ncz(false), "arbitrary.bin");
        let reference = parse(bytes.clone(), "input.nsz").unwrap();
        for suffix in ["nsp", "nsz", "nsx", "xci", "xcz", "nca", "ncz", "other"] {
            let result = parse(bytes.clone(), &format!("input.{suffix}")).unwrap();
            assert_eq!(result.recognition, reference.recognition);
            assert_eq!(
                result.package_structure_eligibility,
                reference.package_structure_eligibility
            );
            assert_eq!(
                parse(b"arbitrary".to_vec(), &format!("input.{suffix}"))
                    .unwrap()
                    .recognition,
                RecognitionOutcome::Unknown
            );
        }
        assert_eq!(
            reference.extension_observation,
            ExtensionObservation::Compatible
        );
        assert_eq!(
            parse(bytes.clone(), "input.nsp")
                .unwrap()
                .extension_observation,
            ExtensionObservation::Mismatch
        );
        assert_eq!(
            parse(bytes, "input.other").unwrap().extension_observation,
            ExtensionObservation::Unrecognized
        );
    }

    #[test]
    fn readable_nca_checks_authoritative_hash_layer_layout() {
        for (offset, value) in [(0x402, 2), (0x403, 1), (0x42c, 1), (0x428, 33), (0x448, 0)] {
            let mut bytes = nca();
            bytes[offset] = value;
            assert!(parse(bytes, "input.nca").is_err(), "field {offset:x}");
        }
        let mut bytes = nca();
        bytes[0x440..0x448].copy_from_slice(&0x1000u64.to_le_bytes());
        assert_eq!(
            parse(bytes, "input.nca").unwrap_err().code(),
            MalformedInput
        );
    }

    #[test]
    fn hfs_hash_target_and_parent_bounds_are_validated() {
        // The first partition HFS0 starts right after the 0x200 root header,
        // so its single member record begins at 0xF210.
        let mut bytes = xci(&[0; 8]);
        // Nonzero modern hash-target offset is valid when the hashed span fits.
        bytes[0xF224..0xF228].copy_from_slice(&2u32.to_le_bytes());
        bytes[0xF228..0xF230].copy_from_slice(&3u64.to_le_bytes());
        assert!(parse(bytes.clone(), "input.xci").is_ok());
        bytes[0xF228..0xF230].copy_from_slice(&8u64.to_le_bytes());
        assert_eq!(
            parse(bytes, "input.xci").unwrap_err().code(),
            MalformedInput
        );
        let mut bytes = xci(&[0; 8]);
        bytes[0xF210..0xF218].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse(bytes, "input.xci").is_err());
    }

    #[test]
    fn overlapping_hfs_member_spans_are_rejected_directly_and_nested() {
        // Direct: a two-member table whose second span starts inside the
        // first member's span.
        let member: &[u8] = &[0; 0x300];
        let (mut direct, _) = hfs_image(&[("alpha", member), ("beta", member)]);
        direct[16 + 64..16 + 72].copy_from_slice(&0x200u64.to_le_bytes());
        let mut reader = Cursor::new(&direct);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget::default(),
        };
        assert_eq!(
            parser.hfs(0, direct.len() as u64).err().unwrap().code(),
            MalformedInput
        );
        // Nested: the same overlap inside the root table of a card image.
        let mut bytes = card(
            &[("update", member), ("normal", member), ("secure", member)],
            0xF000,
            None,
        );
        bytes[0xF050..0xF058].copy_from_slice(&0x200u64.to_le_bytes());
        assert_eq!(parse(bytes, "a.xci").unwrap_err().code(), MalformedInput);
    }

    #[test]
    fn xci_root_must_sit_at_the_documented_placement() {
        let leaf: &[u8] = &[0; 8];
        let bytes = card(
            &[("update", leaf), ("normal", leaf), ("secure", leaf)],
            0x200,
            None,
        );
        assert_eq!(
            parse(bytes, "a.xci").unwrap_err().code(),
            UnsupportedStructure
        );
    }

    #[test]
    fn xci_root_partitions_must_use_unique_known_names() {
        let leaf: &[u8] = &[0; 8];
        let duplicate = card(
            &[("update", leaf), ("update", leaf), ("secure", leaf)],
            0xF000,
            None,
        );
        assert_eq!(
            parse(duplicate, "a.xci").unwrap_err().code(),
            UnsupportedStructure
        );
        let unknown = card(
            &[("update", leaf), ("bogus", leaf), ("secure", leaf)],
            0xF000,
            None,
        );
        assert_eq!(
            parse(unknown, "a.xci").unwrap_err().code(),
            UnsupportedStructure
        );
    }

    #[test]
    fn xci_missing_required_root_partitions_is_not_a_supported_profile() {
        let leaf: &[u8] = &[0; 8];
        let bytes = card(&[("update", leaf), ("normal", leaf)], 0xF000, None);
        assert_eq!(
            parse(bytes, "a.xci").unwrap_err().code(),
            UnsupportedStructure
        );
    }

    #[test]
    fn xci_ordinary_card_requires_the_documented_secure_area_page() {
        let leaf: &[u8] = &[0; 8];
        let bytes = card(
            &[("update", leaf), ("normal", leaf), ("secure", leaf)],
            0xF000,
            Some(0x80),
        );
        assert_eq!(
            parse(bytes, "a.xci").unwrap_err().code(),
            UnsupportedStructure
        );
    }

    #[test]
    fn xci_partition_member_must_be_a_bounded_hfs0() {
        let leaf: &[u8] = &[0; 8];
        let mut bytes = xci(leaf);
        // One root header plus two 0x400 partition images place the secure
        // partition header at 0xFA00.
        bytes[0xFA00..0xFA04].fill(0);
        assert_eq!(parse(bytes, "a.xci").unwrap_err().code(), MalformedInput);
    }

    #[test]
    fn xci_logo_partition_is_optional_but_known() {
        let leaf: &[u8] = &[0; 8];
        let bytes = card(
            &[
                ("update", leaf),
                ("normal", leaf),
                ("logo", leaf),
                ("secure", leaf),
            ],
            0xF000,
            None,
        );
        let result = parse(bytes, "a.xci").unwrap();
        assert!(matches!(
            result.recognition,
            RecognitionOutcome::Recognized {
                family: RecognizedFamily::Xci,
                compression_variant: CompressionVariant::NotEstablished,
            }
        ));
        assert_eq!(
            result.package_structure_eligibility,
            StructuralEligibility::Eligible
        );
    }

    #[test]
    fn xci_compressed_card_tolerates_the_copied_source_page_address() {
        let leaf: &[u8] = &[0; 8];
        let archive = ncz(false);
        let bytes = card(
            &[
                ("update", leaf),
                ("normal", leaf),
                ("secure", archive.as_slice()),
            ],
            0xF000,
            Some(0x80),
        );
        let result = parse(bytes, "a.xcz").unwrap();
        assert!(matches!(
            result.recognition,
            RecognitionOutcome::Recognized {
                family: RecognizedFamily::Xci,
                compression_variant: CompressionVariant::Ncz,
            }
        ));
        assert_eq!(
            result.package_structure_eligibility,
            StructuralEligibility::Eligible
        );
    }

    #[test]
    fn xci_compressed_card_rejects_zero_rom_area_page() {
        let leaf: &[u8] = &[0; 8];
        let archive = ncz(false);
        let bytes = card(
            &[
                ("update", leaf),
                ("normal", leaf),
                ("secure", archive.as_slice()),
            ],
            0xF000,
            Some(0),
        );
        assert_eq!(
            parse(bytes, "a.xcz").unwrap_err().code(),
            UnsupportedStructure
        );
    }

    #[test]
    fn xci_compressed_card_rejects_rom_area_page_beyond_declared_capacity() {
        let leaf: &[u8] = &[0; 8];
        let archive = ncz(false);
        let mut bytes = card(
            &[
                ("update", leaf),
                ("normal", leaf),
                ("secure", archive.as_slice()),
            ],
            0xF000,
            Some(0xFFFF_FFFF),
        );
        bytes[0x10D] = 0xFA;
        assert_eq!(
            parse(bytes, "a.xcz").unwrap_err().code(),
            UnsupportedStructure
        );
    }

    #[test]
    fn xci_compressed_card_bounds_page_and_valid_data_end_by_declared_size() {
        let leaf: &[u8] = &[0; 8];
        let archive = ncz(false);
        let parts = [
            ("update", leaf),
            ("normal", leaf),
            ("secure", archive.as_slice()),
        ];
        // A 1 GiB declaration names 0x20_0000 pages: the page after the last
        // one cannot start the ROM area, and a valid-data end past the
        // declared capacity is not representable on that card.
        let mut beyond_page = card(&parts, 0xF000, Some(0x20_0000));
        beyond_page[0x10D] = 0xFA;
        assert_eq!(
            parse(beyond_page, "a.xcz").unwrap_err().code(),
            UnsupportedStructure
        );
        let mut beyond_end = card(&parts, 0xF000, Some(0x80));
        beyond_end[0x10D] = 0xFA;
        beyond_end[0x118..0x11C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(
            parse(beyond_end, "a.xcz").unwrap_err().code(),
            UnsupportedStructure
        );
        let mut last_page = card(&parts, 0xF000, Some(0x1F_FFFF));
        last_page[0x10D] = 0xFA;
        assert!(matches!(
            parse(last_page, "a.xcz").unwrap().recognition,
            RecognitionOutcome::Recognized {
                family: RecognizedFamily::Xci,
                compression_variant: CompressionVariant::Ncz,
            }
        ));
    }

    #[test]
    fn xci_compressed_card_rejects_rom_area_page_after_valid_data_end() {
        let leaf: &[u8] = &[0; 8];
        let archive = ncz(false);
        let mut bytes = card(
            &[
                ("update", leaf),
                ("normal", leaf),
                ("secure", archive.as_slice()),
            ],
            0xF000,
            Some(0x80),
        );
        bytes[0x10D] = 0xFA;
        bytes[0x118..0x11C].copy_from_slice(&0x40u32.to_le_bytes());
        assert_eq!(
            parse(bytes, "a.xcz").unwrap_err().code(),
            UnsupportedStructure
        );
    }

    #[test]
    fn xci_compressed_card_page_bound_follows_declared_rom_size() {
        let leaf: &[u8] = &[0; 8];
        let archive = ncz(false);
        let parts = [
            ("update", leaf),
            ("normal", leaf),
            ("secure", archive.as_slice()),
        ];
        // The same page the 1 GiB declaration rejects stays within a 2 GiB
        // declaration, so the bound follows the declared card size.
        let mut two_gib = card(&parts, 0xF000, Some(0x20_0000));
        two_gib[0x10D] = 0xF8;
        assert!(matches!(
            parse(two_gib, "a.xcz").unwrap().recognition,
            RecognitionOutcome::Recognized {
                family: RecognizedFamily::Xci,
                compression_variant: CompressionVariant::Ncz,
            }
        ));
        // An undocumented size code cannot establish card geometry.
        let mut unknown = card(&parts, 0xF000, Some(0x80));
        unknown[0x10D] = 0;
        assert_eq!(
            parse(unknown, "a.xcz").unwrap_err().code(),
            UnsupportedStructure
        );
    }

    #[test]
    fn xci_unsupported_nested_nca_profile_does_not_invalidate_card_structure() {
        let leaf: &[u8] = &[0; 8];
        let mut member = nca();
        member[0x404] = 5;
        let bytes = card(
            &[
                ("update", leaf),
                ("normal", leaf),
                ("secure", member.as_slice()),
            ],
            0xF000,
            None,
        );
        let result = parse(bytes, "a.xci").unwrap();
        assert!(matches!(
            result.recognition,
            RecognitionOutcome::Recognized {
                family: RecognizedFamily::Xci,
                compression_variant: CompressionVariant::NotEstablished,
            }
        ));
        assert_eq!(
            result.package_structure_eligibility,
            StructuralEligibility::Eligible
        );
    }

    #[test]
    fn pfs0_member_with_incomplete_nca3_header_keeps_proven_structure() {
        let mut member = vec![0; 0x204];
        member[0x200..0x204].copy_from_slice(b"NCA3");
        let mut reader = Cursor::new(&member);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget::default(),
        };
        assert_eq!(
            parser.nca(0, member.len() as u64).unwrap_err().code(),
            TruncatedInput
        );
        let result = parse(package(&member, "member.nca"), "a.nsp").unwrap();
        assert!(matches!(
            result.recognition,
            RecognitionOutcome::Recognized {
                family: RecognizedFamily::Pfs0,
                compression_variant: CompressionVariant::NotEstablished,
            }
        ));
        assert_eq!(
            result.package_structure_eligibility,
            StructuralEligibility::NotEstablished
        );
    }

    #[test]
    fn pfs0_member_with_inconsistent_nca3_header_keeps_proven_structure() {
        let mut member = nca();
        member[0x208..0x210].copy_from_slice(&0xe01u64.to_le_bytes());
        let mut reader = Cursor::new(&member);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget::default(),
        };
        assert_eq!(
            parser.nca(0, member.len() as u64).unwrap_err().code(),
            MalformedInput
        );
        let result = parse(package(&member, "member.nca"), "a.nsp").unwrap();
        assert!(matches!(
            result.recognition,
            RecognitionOutcome::Recognized {
                family: RecognizedFamily::Pfs0,
                compression_variant: CompressionVariant::NotEstablished,
            }
        ));
        assert_eq!(
            result.package_structure_eligibility,
            StructuralEligibility::NotEstablished
        );
    }

    #[test]
    fn pfs0_member_with_unsupported_nca_profile_keeps_the_established_frame() {
        let mut member = nca();
        member[0x404] = 5;
        let mut reader = Cursor::new(&member);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget::default(),
        };
        assert_eq!(
            parser.nca(0, member.len() as u64).unwrap_err().code(),
            UnsupportedStructure
        );
        let result = parse(package(&member, "member.nca"), "a.nsp").unwrap();
        assert!(matches!(
            result.recognition,
            RecognitionOutcome::Recognized {
                family: RecognizedFamily::Pfs0,
                compression_variant: CompressionVariant::NotEstablished,
            }
        ));
        assert_eq!(
            result.package_structure_eligibility,
            StructuralEligibility::NotEstablished
        );
        assert_eq!(
            result.ticket_name_observation,
            TicketNameObservation::NotObserved
        );
        assert_eq!(
            result.extension_observation,
            ExtensionObservation::NotEstablished
        );
    }

    #[test]
    fn aggregate_member_budget_does_not_reset_in_nested_archive() {
        let bytes = ncz(false);
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget {
                entries: ENTRY_LIMIT,
                ..Budget::default()
            },
        };
        assert_eq!(
            parser.ncz(0, bytes.len() as u64).unwrap_err().code(),
            LimitExceeded
        );
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget {
                reads: READ_LIMIT,
                ..Budget::default()
            },
        };
        assert_eq!(
            parser.ncz(0, bytes.len() as u64).unwrap_err().code(),
            LimitExceeded
        );
    }

    #[test]
    fn parser_work_budget_counts_ncz_descriptors_frames_and_blocks() {
        let bytes = ncz(false);
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget::default(),
        };
        parser.ncz(0, bytes.len() as u64).unwrap();
        // One section descriptor, one frame header, one block header.
        assert_eq!(parser.budget.work, 3);
        let bytes = ncz(true);
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget::default(),
        };
        parser.ncz(0, bytes.len() as u64).unwrap();
        // One section descriptor and one block-size descriptor; block sizes
        // equal to the expected extents skip per-frame parsing.
        assert_eq!(parser.budget.work, 2);
    }

    #[test]
    fn parser_work_budget_is_cumulative_across_nested_ncz_parses() {
        let leaf: &[u8] = &[0; 8];
        let archive = ncz(false);
        let bytes = card(
            &[
                ("update", leaf),
                ("normal", archive.as_slice()),
                ("secure", archive.as_slice()),
            ],
            0xF000,
            Some(0x80),
        );
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget::default(),
        };
        parser.xci(bytes.len() as u64).unwrap();
        // Both nested archives share the one cumulative counter.
        assert_eq!(parser.budget.work, 6);
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget {
                work: WORK_LIMIT - 6,
                ..Budget::default()
            },
        };
        assert!(parser.xci(bytes.len() as u64).is_ok());
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget {
                work: WORK_LIMIT - 5,
                ..Budget::default()
            },
        };
        assert_eq!(
            parser.xci(bytes.len() as u64).unwrap_err().code(),
            LimitExceeded
        );
    }

    #[test]
    fn parser_work_budget_preserves_concatenated_frames() {
        let bytes = ncz_two_frames();
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget::default(),
        };
        parser.ncz(0, bytes.len() as u64).unwrap();
        // One section descriptor plus both frames and both block headers.
        assert_eq!(parser.budget.work, 5);
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget {
                work: WORK_LIMIT - 5,
                ..Budget::default()
            },
        };
        assert!(parser.ncz(0, bytes.len() as u64).is_ok());
        let mut reader = Cursor::new(&bytes);
        let mut parser = Parser {
            reader: &mut reader,
            budget: Budget {
                work: WORK_LIMIT - 4,
                ..Budget::default()
            },
        };
        assert_eq!(
            parser.ncz(0, bytes.len() as u64).unwrap_err().code(),
            LimitExceeded
        );
    }

    #[test]
    fn parser_work_ceiling_is_below_the_metadata_budget_maximum() {
        // Counted units also charge the metadata budget at three bytes each at
        // minimum, so the metadata budget alone admits at most META_LIMIT / 3
        // units; a larger work ceiling could never bind. The values pass
        // through black_box so the check stays a runtime assertion.
        let metadata_only_maximum = std::hint::black_box(META_LIMIT) / 3;
        assert!(WORK_LIMIT < metadata_only_maximum);
    }
}
