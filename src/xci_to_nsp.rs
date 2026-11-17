//! Conversion of the qualified synthetic base Application XCI profile.

use crate::operation::ConflictPolicy;
#[cfg(target_os = "macos")]
use crate::operation::OperationFailureCode;
use std::fmt;
use std::path::PathBuf;

/// Describes one XCI-to-NSP conversion request.
#[derive(Clone)]
pub struct XciToNspRequest {
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) workspace: PathBuf,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) key_file: PathBuf,
    pub(crate) conflict_policy: ConflictPolicy,
}

impl XciToNspRequest {
    /// Creates a request with explicit source, output, workspace, and key paths.
    pub fn new(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        workspace: impl Into<PathBuf>,
        key_file: impl Into<PathBuf>,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            workspace: workspace.into(),
            key_file: key_file.into(),
            conflict_policy: ConflictPolicy::Fail,
        }
    }

    /// Selects how execution handles an existing output file.
    #[must_use]
    pub fn with_conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }
}

impl fmt::Debug for XciToNspRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XciToNspRequest")
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("workspace", &self.workspace)
            .field("key_file", &"[REDACTED]")
            .field("conflict_policy", &self.conflict_policy)
            .finish()
    }
}

#[cfg(target_os = "macos")]
pub(crate) struct XciToNspPackagePlan {
    pub(crate) layout: crate::multi_content_format::Pfs0WriteLayout,
    pub(crate) members: Vec<crate::multi_content_format::Pfs0SourceMember>,
    pub(crate) facts: XciToNspQualificationFacts,
}

#[cfg(target_os = "macos")]
/// Profile-specific evidence retained for staged and existing-output checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum XciToNspQualificationFacts {
    /// Evidence established by the existing two-member qualifier.
    MetaProgram(crate::nsp_semantic_qualification::NspSemanticQualificationFacts),
    /// CNMT linkage plus the independent Control NCA integrity facts.
    MetaProgramControl {
        semantic: crate::nsp_semantic_qualification::NspApplicationControlFacts,
        control: crate::control_nca_qualification::ControlNcaQualificationFacts,
    },
}

#[cfg(target_os = "macos")]
struct DetectedMember {
    source: crate::recognition::XciSecureMember,
    sha256: crate::sha256::Sha256Digest,
}

#[cfg(target_os = "macos")]
pub(crate) fn qualify_xci(
    source_file: std::fs::File,
    source_path: &std::path::Path,
    source_length: u64,
    key_file: &std::path::Path,
    expected_source_snapshot: crate::file_identity::FileSnapshot,
    expected_key_snapshot: crate::file_identity::FileSnapshot,
) -> Result<XciToNspPackagePlan, OperationFailureCode> {
    qualify_xci_with_cancellation_probe(
        source_file,
        source_path,
        source_length,
        key_file,
        expected_source_snapshot,
        expected_key_snapshot,
        || false,
    )
}

#[cfg(target_os = "macos")]
pub(crate) fn qualify_xci_with_cancellation_probe<F>(
    mut source_file: std::fs::File,
    source_path: &std::path::Path,
    source_length: u64,
    key_file: &std::path::Path,
    expected_source_snapshot: crate::file_identity::FileSnapshot,
    expected_key_snapshot: crate::file_identity::FileSnapshot,
    mut is_cancelled: F,
) -> Result<XciToNspPackagePlan, OperationFailureCode>
where
    F: FnMut() -> bool,
{
    if is_cancelled() {
        return Err(OperationFailureCode::Cancelled);
    }
    let source = crate::recognition::inspect_xci_for_conversion(&mut source_file, source_length)
        .map_err(map_recognition_error)?;
    if !matches!(source.secure_members.len(), 2 | 3) {
        return Err(OperationFailureCode::UnsupportedXciProfile);
    }

    let mut detected = Vec::new();
    detected
        .try_reserve_exact(source.secure_members.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    for member in source.secure_members {
        let sha256 = hash_member(&mut source_file, &member, &mut is_cancelled)?;
        detected.push(DetectedMember {
            source: member,
            sha256,
        });
    }

    let mut input_members = Vec::new();
    input_members
        .try_reserve_exact(detected.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    for (index, member) in detected.iter().enumerate() {
        let name = match index {
            0 => "member-000.nca",
            1 => "member-001.nca",
            2 => "member-002.nca",
            _ => return Err(OperationFailureCode::UnsupportedXciProfile),
        };
        input_members.push(make_source_member(
            name,
            member.source.offset,
            member.source.length,
            member.sha256,
        )?);
    }
    let input_layout_members = layout_members(&input_members)?;
    let input_layout = crate::multi_content_format::build_pfs0_layout(&input_layout_members)
        .map_err(map_format_error)?;
    let request = crate::nsp_semantic_qualification::NspSemanticQualificationRequest::new(
        source_path,
        key_file,
    )
    .with_expected_key_snapshot(expected_key_snapshot.clone());
    let (facts, ordered_member_indices) = match detected.len() {
        2 => {
            use crate::nsp_semantic_qualification::{
                NspSemanticQualificationOutcome, NspSemanticQualificationRole,
            };

            let virtual_input = XciPfs0Input::new(
                source_file,
                source_path.to_path_buf(),
                input_layout,
                input_members,
                expected_source_snapshot.clone(),
            )
            .map_err(|_| OperationFailureCode::SourceChanged)?;
            let qualification =
                crate::nsp_semantic_qualification::qualify_with_input_and_cancellation_probe(
                    request,
                    virtual_input,
                    &mut is_cancelled,
                )
                .map_err(|error| map_qualification_error(error.code()))?;
            let facts = match qualification.outcome {
                NspSemanticQualificationOutcome::Qualified(facts) => facts,
                NspSemanticQualificationOutcome::NotQualified(_) => {
                    return Err(OperationFailureCode::UnsupportedContentProfile);
                }
            };
            if facts.members.len() != 2
                || facts.members[0].role != NspSemanticQualificationRole::Meta
                || facts.members[1].role != NspSemanticQualificationRole::Program
            {
                return Err(OperationFailureCode::UnsupportedContentProfile);
            }
            let meta_index = unique_member_for_fact(&detected, &facts.members[0])?;
            let program_index = unique_member_for_fact(&detected, &facts.members[1])?;
            if meta_index == program_index {
                return Err(OperationFailureCode::UnsupportedContentProfile);
            }
            (
                XciToNspQualificationFacts::MetaProgram(facts),
                [meta_index, program_index, 0],
            )
        }
        3 => {
            let virtual_input = XciPfs0Input::new(
                source_file,
                source_path.to_path_buf(),
                input_layout,
                input_members,
                expected_source_snapshot.clone(),
            )
            .map_err(|_| OperationFailureCode::SourceChanged)?;
            let qualification =
                crate::nsp_semantic_qualification::qualify_application_with_control_input(
                    request,
                    virtual_input,
                )
                .map_err(|error| map_qualification_error(error.code()))?;
            let candidate = match qualification.outcome {
                crate::nsp_semantic_qualification::NspApplicationControlOutcome::Qualified(
                    candidate,
                ) => candidate,
                crate::nsp_semantic_qualification::NspApplicationControlOutcome::NotQualified(
                    _,
                ) => return Err(OperationFailureCode::UnsupportedContentProfile),
            };
            let meta_index = unique_member_for_fact(&detected, &candidate.facts.meta)?;
            let program_index = unique_member_for_fact(&detected, &candidate.facts.program)?;
            let control_index = unique_member_for_evidence(
                &detected,
                candidate.facts.control_size,
                candidate.facts.control_sha256,
            )?;
            if meta_index == program_index
                || meta_index == control_index
                || program_index == control_index
            {
                return Err(OperationFailureCode::UnsupportedContentProfile);
            }
            let control_request =
                crate::control_nca_qualification::ControlNcaQualificationRequest::new(
                    source_path,
                    key_file,
                )
                .with_expected_key_snapshot(expected_key_snapshot.clone());
            let control = crate::control_nca_qualification::qualify_bounded_path(
                control_request,
                detected[control_index].source.offset,
                detected[control_index].source.length,
                Some(expected_source_snapshot),
            )
            .map_err(|error| map_control_qualification_error(error.code()))?;
            let control_facts = match control {
                crate::control_nca_qualification::ControlNcaQualificationOutcome::Qualified(
                    facts,
                ) if facts.program_id == candidate.facts.title_id => facts,
                crate::control_nca_qualification::ControlNcaQualificationOutcome::Qualified(_)
                | crate::control_nca_qualification::ControlNcaQualificationOutcome::NotQualified(
                    _,
                ) => return Err(OperationFailureCode::UnsupportedContentProfile),
            };
            (
                XciToNspQualificationFacts::MetaProgramControl {
                    semantic: candidate.facts,
                    control: control_facts,
                },
                [meta_index, program_index, control_index],
            )
        }
        _ => return Err(OperationFailureCode::UnsupportedXciProfile),
    };

    let mut output_members = Vec::new();
    output_members
        .try_reserve_exact(detected.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    for (role_index, member_index) in ordered_member_indices
        .into_iter()
        .take(detected.len())
        .enumerate()
    {
        let name = match role_index {
            0 => "meta.nca",
            1 => "program.nca",
            2 => "control.nca",
            _ => return Err(OperationFailureCode::UnsupportedContentProfile),
        };
        let member = &detected[member_index];
        output_members.push(make_source_member(
            name,
            member.source.offset,
            member.source.length,
            member.sha256,
        )?);
    }
    let output_layout_members = layout_members(&output_members)?;
    let layout = crate::multi_content_format::build_pfs0_layout(&output_layout_members)
        .map_err(map_format_error)?;
    Ok(XciToNspPackagePlan {
        layout,
        members: output_members,
        facts,
    })
}

#[cfg(target_os = "macos")]
fn unique_member_for_fact(
    members: &[DetectedMember],
    fact: &crate::nsp_semantic_qualification::NspSemanticQualificationMember,
) -> Result<usize, OperationFailureCode> {
    unique_member_for_evidence(members, fact.size, fact.sha256)
}

#[cfg(target_os = "macos")]
fn unique_member_for_evidence(
    members: &[DetectedMember],
    size: u64,
    sha256: crate::sha256::Sha256Digest,
) -> Result<usize, OperationFailureCode> {
    let mut found = None;
    for (index, member) in members.iter().enumerate() {
        if member.source.length == size && member.sha256 == sha256 {
            if found.is_some() {
                return Err(OperationFailureCode::UnsupportedContentProfile);
            }
            found = Some(index);
        }
    }
    found.ok_or(OperationFailureCode::UnsupportedContentProfile)
}

#[cfg(target_os = "macos")]
fn make_source_member(
    name: &str,
    source_offset: u64,
    size: u64,
    sha256: crate::sha256::Sha256Digest,
) -> Result<crate::multi_content_format::Pfs0SourceMember, OperationFailureCode> {
    let mut member_name = String::new();
    member_name
        .try_reserve_exact(name.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    member_name.push_str(name);
    Ok(crate::multi_content_format::Pfs0SourceMember {
        name: member_name,
        source_offset,
        size,
        sha256,
    })
}

#[cfg(target_os = "macos")]
fn layout_members(
    members: &[crate::multi_content_format::Pfs0SourceMember],
) -> Result<Vec<(String, u64)>, OperationFailureCode> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(members.len())
        .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    for member in members {
        let mut name = String::new();
        name.try_reserve_exact(member.name.len())
            .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        name.push_str(&member.name);
        result.push((name, member.size));
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
struct XciPfs0Input {
    file: std::fs::File,
    path: PathBuf,
    identity: crate::file_identity::FileIdentity,
    snapshot: crate::file_identity::FileSnapshot,
    layout: crate::multi_content_format::Pfs0WriteLayout,
    members: Vec<crate::multi_content_format::Pfs0SourceMember>,
    position: u64,
}

#[cfg(target_os = "macos")]
impl XciPfs0Input {
    fn new(
        file: std::fs::File,
        path: PathBuf,
        layout: crate::multi_content_format::Pfs0WriteLayout,
        members: Vec<crate::multi_content_format::Pfs0SourceMember>,
        expected_snapshot: crate::file_identity::FileSnapshot,
    ) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        let identity = crate::file_identity::handle_identity(&file)
            .ok_or_else(|| std::io::Error::other("source identity is unavailable"))?;
        let snapshot = crate::file_identity::file_snapshot(&metadata, Some(identity));
        if crate::file_identity::path_identity(&path) != Some(identity)
            || crate::file_identity::followed_path_identity(&path) != Some(identity)
            || snapshot != expected_snapshot
        {
            return Err(std::io::Error::other("source identity changed"));
        }
        Ok(Self {
            snapshot: expected_snapshot,
            file,
            path,
            identity,
            layout,
            members,
            position: 0,
        })
    }
}

#[cfg(target_os = "macos")]
impl std::io::Read for XciPfs0Input {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use std::io::{Seek, SeekFrom};

        if buffer.is_empty() || self.position >= self.layout.length {
            return Ok(0);
        }
        if self.position < self.layout.payload_offset {
            let metadata_start = usize::try_from(self.position)
                .map_err(|_| std::io::Error::other("virtual offset is too large"))?;
            let count = buffer
                .len()
                .min(self.layout.metadata.len() - metadata_start);
            buffer[..count]
                .copy_from_slice(&self.layout.metadata[metadata_start..metadata_start + count]);
            self.position = self
                .position
                .checked_add(
                    u64::try_from(count)
                        .map_err(|_| std::io::Error::other("virtual read length is too large"))?,
                )
                .ok_or_else(|| std::io::Error::other("virtual position overflow"))?;
            return Ok(count);
        }

        let payload_position = self.position - self.layout.payload_offset;
        let Some((layout_member, source_member)) = self
            .layout
            .members
            .iter()
            .zip(&self.members)
            .find(|(member, _)| {
                member.data_offset <= payload_position
                    && member
                        .data_offset
                        .checked_add(member.size)
                        .is_some_and(|end| payload_position < end)
            })
        else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "virtual package has an unaccounted payload range",
            ));
        };
        let member_offset = payload_position - layout_member.data_offset;
        let count = usize::try_from((layout_member.size - member_offset).min(buffer.len() as u64))
            .map_err(|_| std::io::Error::other("virtual read length is too large"))?;
        let source_offset = source_member
            .source_offset
            .checked_add(member_offset)
            .ok_or_else(|| std::io::Error::other("source member offset overflow"))?;
        self.file.seek(SeekFrom::Start(source_offset))?;
        let read = self.file.read(&mut buffer[..count])?;
        self.position = self
            .position
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| std::io::Error::other("virtual read length is too large"))?,
            )
            .ok_or_else(|| std::io::Error::other("virtual position overflow"))?;
        Ok(read)
    }
}

#[cfg(target_os = "macos")]
impl std::io::Seek for XciPfs0Input {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        let requested = match position {
            std::io::SeekFrom::Start(offset) => i128::from(offset),
            std::io::SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            std::io::SeekFrom::End(delta) => i128::from(self.layout.length) + i128::from(delta),
        };
        if requested < 0 || requested > i128::from(self.layout.length) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek is outside the virtual package",
            ));
        }
        self.position = u64::try_from(requested)
            .map_err(|_| std::io::Error::other("virtual offset is too large"))?;
        Ok(self.position)
    }
}

#[cfg(target_os = "macos")]
impl crate::nsp_semantic_qualification::NspSemanticInput for XciPfs0Input {
    fn input_size(&self) -> u64 {
        self.layout.length
    }

    fn revalidate(
        &self,
        code: crate::nsp_semantic_qualification::NspSemanticQualificationErrorCode,
    ) -> Result<(), crate::nsp_semantic_qualification::NspSemanticQualificationError> {
        use crate::nsp_semantic_qualification::NspSemanticQualificationError;

        let changed = || Err(NspSemanticQualificationError::new(code));
        let Ok(metadata) = self.file.metadata() else {
            return changed();
        };
        if !metadata.file_type().is_file()
            || crate::file_identity::handle_identity(&self.file) != Some(self.identity)
            || crate::file_identity::path_identity(&self.path) != Some(self.identity)
            || crate::file_identity::followed_path_identity(&self.path) != Some(self.identity)
            || crate::file_identity::file_snapshot(&metadata, Some(self.identity)) != self.snapshot
        {
            return changed();
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn hash_member(
    source: &mut std::fs::File,
    member: &crate::recognition::XciSecureMember,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<crate::sha256::Sha256Digest, OperationFailureCode> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};

    source
        .seek(SeekFrom::Start(member.offset))
        .map_err(|_| OperationFailureCode::SourceUnavailable)?;
    let mut remaining = member.length;
    let mut buffer = [0_u8; 64 * 1024];
    let mut hasher = Sha256::new();
    while remaining > 0 {
        if is_cancelled() {
            return Err(OperationFailureCode::Cancelled);
        }
        let count = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
        let read = source
            .read(&mut buffer[..count])
            .map_err(|_| OperationFailureCode::SourceUnavailable)?;
        if read == 0 {
            return Err(OperationFailureCode::SourceChanged);
        }
        hasher.update(&buffer[..read]);
        remaining -=
            u64::try_from(read).map_err(|_| OperationFailureCode::ResourceLimitExceeded)?;
    }
    Ok(crate::sha256::Sha256Digest::from_bytes(
        hasher.finalize().into(),
    ))
}

#[cfg(target_os = "macos")]
pub(crate) fn map_recognition_error(
    error: crate::recognition::ContentRecognitionError,
) -> OperationFailureCode {
    use crate::recognition::ContentRecognitionErrorCode as Code;

    match error.code() {
        Code::InputUnavailable => OperationFailureCode::SourceUnavailable,
        Code::TruncatedInput | Code::MalformedInput => OperationFailureCode::InvalidXciImage,
        Code::UnsupportedStructure => OperationFailureCode::UnsupportedXciProfile,
        Code::LimitExceeded | Code::ResourceLimitExceeded => {
            OperationFailureCode::ResourceLimitExceeded
        }
    }
}

#[cfg(target_os = "macos")]
fn map_format_error(error: crate::multi_content_format::FormatError) -> OperationFailureCode {
    use crate::multi_content_format::FormatError;

    match error {
        FormatError::ResourceLimit => OperationFailureCode::ResourceLimitExceeded,
        FormatError::SourceUnavailable => OperationFailureCode::SourceUnavailable,
        FormatError::InvalidPackage | FormatError::UnsupportedProfile => {
            OperationFailureCode::UnsupportedXciProfile
        }
        FormatError::DuplicateMember | FormatError::AmbiguousGrouping => {
            OperationFailureCode::UnsupportedXciProfile
        }
        FormatError::OutputUnavailable => OperationFailureCode::WriteFailed,
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn map_qualification_error(
    error: crate::nsp_semantic_qualification::NspSemanticQualificationErrorCode,
) -> OperationFailureCode {
    use crate::nsp_semantic_qualification::NspSemanticQualificationErrorCode as Code;

    match error {
        Code::InputUnavailable => OperationFailureCode::SourceUnavailable,
        Code::InputChangedDuringQualification => OperationFailureCode::SourceChanged,
        Code::KeyFileUnavailable => OperationFailureCode::KeyFileUnavailable,
        Code::KeyFileChangedDuringQualification => OperationFailureCode::KeyFileChanged,
        Code::KeyFileMalformed => OperationFailureCode::KeyFileMalformed,
        Code::MissingHeaderKey | Code::MissingApplicationKeyAreaKey => {
            OperationFailureCode::RequiredKeyMissing
        }
        Code::KeyFileLimitExceeded
        | Code::InputLimitExceeded
        | Code::Pfs0ResourceLimitExceeded
        | Code::AllocationFailed => OperationFailureCode::ResourceLimitExceeded,
        Code::KeyOrSectionIntegrityFailure => OperationFailureCode::KeyOrSectionIntegrityFailure,
        Code::Cancelled => OperationFailureCode::Cancelled,
        Code::InternalIo => OperationFailureCode::SourceUnavailable,
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn map_control_qualification_error(
    error: crate::control_nca_qualification::ControlNcaQualificationErrorCode,
) -> OperationFailureCode {
    use crate::control_nca_qualification::ControlNcaQualificationErrorCode as Code;

    match error {
        Code::InputUnavailable => OperationFailureCode::SourceUnavailable,
        Code::InputChangedDuringQualification => OperationFailureCode::SourceChanged,
        Code::KeyFileUnavailable => OperationFailureCode::KeyFileUnavailable,
        Code::KeyFileChangedDuringQualification => OperationFailureCode::KeyFileChanged,
        Code::KeyFileMalformed => OperationFailureCode::KeyFileMalformed,
        Code::MissingHeaderKey | Code::MissingApplicationKeyAreaKey => {
            OperationFailureCode::RequiredKeyMissing
        }
        Code::KeyFileLimitExceeded
        | Code::InputLimitExceeded
        | Code::ResourceLimitExceeded
        | Code::AllocationFailed => OperationFailureCode::ResourceLimitExceeded,
        Code::Cancelled => OperationFailureCode::Cancelled,
        Code::InternalIo => OperationFailureCode::SourceUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn source_snapshot_mismatch_rejects_virtual_input() {
        let root = tempfile::tempdir().expect("create source snapshot fixture");
        let source_path = root.path().join("source.xci");
        let expected_path = root.path().join("expected.xci");
        std::fs::write(&source_path, b"source").expect("write source fixture");
        std::fs::write(&expected_path, b"other").expect("write expected fixture");

        let source_file = std::fs::File::open(&source_path).expect("open source fixture");
        let expected_file = std::fs::File::open(&expected_path).expect("open expected fixture");
        let expected_metadata = expected_file.metadata().expect("read expected metadata");
        let expected_identity =
            crate::file_identity::handle_identity(&expected_file).expect("read expected identity");
        let expected_snapshot =
            crate::file_identity::file_snapshot(&expected_metadata, Some(expected_identity));
        let layout = crate::multi_content_format::Pfs0WriteLayout {
            metadata: Vec::new(),
            members: Vec::new(),
            payload_offset: 0,
            length: 0,
        };

        let result = XciPfs0Input::new(
            source_file,
            source_path,
            layout,
            Vec::new(),
            expected_snapshot,
        );

        assert!(
            result.is_err(),
            "a different source snapshot must be rejected"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn member_hashing_stops_between_bounded_chunks_when_cancelled() {
        use std::io::{Seek, SeekFrom, Write};

        let mut source = tempfile::tempfile().expect("create member source");
        let bytes = vec![0xA5; 128 * 1024];
        source.write_all(&bytes).expect("write member source");
        source
            .seek(SeekFrom::Start(0))
            .expect("rewind member source");
        let member = crate::recognition::XciSecureMember {
            name: String::from("program.nca"),
            offset: 0,
            length: u64::try_from(bytes.len()).expect("member size fits u64"),
        };
        let mut probes = 0;
        let error = hash_member(&mut source, &member, &mut || {
            probes += 1;
            probes > 1
        })
        .expect_err("cancellation between member chunks must stop hashing");

        assert_eq!(probes, 2);
        assert_eq!(error, OperationFailureCode::Cancelled);
        assert_eq!(
            source.stream_position().expect("member file position"),
            64 * 1024
        );
    }

    #[test]
    fn request_debug_redacts_the_key_path() {
        let request = XciToNspRequest::new(
            "/fixtures/source.xci",
            "/output/result.nsp",
            "/workspace",
            "/secrets/prod.keys",
        );

        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("/secrets/prod.keys"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn format_errors_map_to_stable_operation_failures() {
        use crate::multi_content_format::FormatError;

        let cases = [
            (
                FormatError::ResourceLimit,
                OperationFailureCode::ResourceLimitExceeded,
            ),
            (
                FormatError::SourceUnavailable,
                OperationFailureCode::SourceUnavailable,
            ),
            (
                FormatError::InvalidPackage,
                OperationFailureCode::UnsupportedXciProfile,
            ),
            (
                FormatError::UnsupportedProfile,
                OperationFailureCode::UnsupportedXciProfile,
            ),
            (
                FormatError::DuplicateMember,
                OperationFailureCode::UnsupportedXciProfile,
            ),
            (
                FormatError::AmbiguousGrouping,
                OperationFailureCode::UnsupportedXciProfile,
            ),
            (
                FormatError::OutputUnavailable,
                OperationFailureCode::WriteFailed,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(map_format_error(error), expected);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn semantic_qualification_errors_map_to_stable_operation_failures() {
        use crate::nsp_semantic_qualification::NspSemanticQualificationErrorCode as Code;

        let cases = [
            (
                Code::InputUnavailable,
                OperationFailureCode::SourceUnavailable,
            ),
            (
                Code::InputChangedDuringQualification,
                OperationFailureCode::SourceChanged,
            ),
            (
                Code::KeyFileUnavailable,
                OperationFailureCode::KeyFileUnavailable,
            ),
            (
                Code::KeyFileChangedDuringQualification,
                OperationFailureCode::KeyFileChanged,
            ),
            (
                Code::KeyFileMalformed,
                OperationFailureCode::KeyFileMalformed,
            ),
            (
                Code::MissingHeaderKey,
                OperationFailureCode::RequiredKeyMissing,
            ),
            (
                Code::MissingApplicationKeyAreaKey,
                OperationFailureCode::RequiredKeyMissing,
            ),
            (
                Code::KeyFileLimitExceeded,
                OperationFailureCode::ResourceLimitExceeded,
            ),
            (
                Code::InputLimitExceeded,
                OperationFailureCode::ResourceLimitExceeded,
            ),
            (
                Code::Pfs0ResourceLimitExceeded,
                OperationFailureCode::ResourceLimitExceeded,
            ),
            (
                Code::AllocationFailed,
                OperationFailureCode::ResourceLimitExceeded,
            ),
            (
                Code::KeyOrSectionIntegrityFailure,
                OperationFailureCode::KeyOrSectionIntegrityFailure,
            ),
            (Code::Cancelled, OperationFailureCode::Cancelled),
            (Code::InternalIo, OperationFailureCode::SourceUnavailable),
        ];

        for (error, expected) in cases {
            assert_eq!(map_qualification_error(error), expected);
        }
    }
}
