//! Strict parser for ordinary text emitted by the pinned NSTool v1.9.2.
//!
//! Provider-native text remains private. The parser accepts the exact labels
//! and warnings observed from the pinned executable, allows fields that NSTool
//! legitimately emits only for some NCA headers, and rejects unknown or
//! contradictory semantics.
use crate::inspection::InspectionErrorCode;
use std::collections::{BTreeSet, HashSet};

const MAX_LINE_BYTES: usize = 8 * 1024;
const MAX_TREE_NODES: usize = 131_072;
const MAX_TREE_NAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_TREE_PATH_BYTES: usize = 16 * 1024 * 1024;
const MAX_INDENT: usize = 64;
const MAX_PROVIDER_LINES: usize = MAX_TREE_NODES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Distribution {
    GameCard,
    Download,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContentType {
    Program,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderPartition {
    pub(crate) index: u8,
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) format: String,
    pub(crate) hash_type: String,
    pub(crate) encryption: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderFacts {
    pub(crate) format_version: u8,
    pub(crate) distribution: Distribution,
    pub(crate) content_type: ContentType,
    pub(crate) key_generation: u8,
    pub(crate) signature_generation: u8,
    pub(crate) kaek_index: u8,
    pub(crate) program_id: u64,
    pub(crate) content_index: u32,
    pub(crate) declared_size: u64,
    pub(crate) partitions: Vec<ProviderPartition>,
    pub(crate) tree_root: String,
    pub(crate) tree_directories: HashSet<String>,
    pub(crate) tree_files: HashSet<String>,
}

pub(crate) fn parse(stdout: &[u8], stderr: &[u8]) -> Result<ProviderFacts, InspectionErrorCode> {
    if !stderr.is_empty() {
        return Err(InspectionErrorCode::ProviderOutputMalformed);
    }
    let text =
        std::str::from_utf8(stdout).map_err(|_| InspectionErrorCode::ProviderOutputMalformed)?;
    let mut line_count = 0_usize;
    for line in text.lines() {
        line_count = line_count
            .checked_add(1)
            .ok_or(InspectionErrorCode::ProviderOutputExceeded)?;
        if line.len() > MAX_LINE_BYTES || line_count > MAX_PROVIDER_LINES {
            return Err(InspectionErrorCode::ProviderOutputExceeded);
        }
    }

    let mut lines = text.lines().peekable();
    let mut header_found = false;
    for raw_line in lines.by_ref() {
        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        if consume_warning(line)? {
            continue;
        }
        if line == "[NCA Header]" {
            header_found = true;
            break;
        }
        return Err(InspectionErrorCode::ProviderOutputMalformed);
    }
    if !header_found {
        return Err(InspectionErrorCode::ProviderOutputMalformed);
    }

    let mut header = HeaderBuilder::default();
    let mut current_partition: Option<PartitionBuilder> = None;
    let mut tree_found = false;
    for raw_line in lines.by_ref() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if consume_warning(trimmed)? {
            continue;
        }
        if trimmed == "[ContentArchive/Tree]" {
            if let Some(partition) = current_partition.take() {
                header.finish_partition(partition)?;
            }
            tree_found = true;
            break;
        }
        if current_partition.is_none()
            && let Some(value) = field(trimmed, "Format Type:")
        {
            header.set_format(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "Dist. Type:")
        {
            header.set_distribution(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "Content Type:")
        {
            header.set_content_type(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "Key Generation:")
        {
            header.set_key_generation(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "Sig. Generation:")
        {
            header.set_signature_generation(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "Kaek Index:")
        {
            header.set_kaek_index(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "Size:")
        {
            header.set_size(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "ProgID:")
        {
            header.set_program_id(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "Content Index:")
        {
            header.set_content_index(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "SdkAddon Ver.:")
        {
            header.set_sdk_addon(value)?;
        } else if current_partition.is_none()
            && let Some(value) = field(trimmed, "RightsId:")
        {
            validate_rights_id(value)?;
            set_once(&mut header.rights_id, value.to_owned())?;
        } else if trimmed == "Partitions:" {
            if header.has_partitions {
                return Err(InspectionErrorCode::ProviderOutputMalformed);
            }
            header.has_partitions = true;
        } else if let Some(index) = partition_index(trimmed) {
            if !header.has_partitions {
                return Err(InspectionErrorCode::ProviderOutputMalformed);
            }
            if let Some(partition) = current_partition.take() {
                header.finish_partition(partition)?;
            }
            current_partition = Some(PartitionBuilder::new(index));
        } else if let Some(partition) = current_partition.as_mut() {
            if let Some(value) = field(trimmed, "Offset:") {
                partition.set_offset(parse_hex(value)?)?;
            } else if let Some(value) = field(trimmed, "Size:") {
                partition.set_size(parse_hex(value)?)?;
            } else if let Some(value) = field(trimmed, "Format Type:") {
                partition.set_format(value)?;
            } else if let Some(value) = field(trimmed, "Hash Type:") {
                partition.set_hash_type(value)?;
            } else if let Some(value) = field(trimmed, "Enc. Type:") {
                partition.set_encryption(value)?;
            } else {
                return Err(InspectionErrorCode::ProviderOutputMalformed);
            }
        } else {
            return Err(InspectionErrorCode::ProviderOutputMalformed);
        }
    }
    if !tree_found {
        return Err(InspectionErrorCode::ProviderOutputMalformed);
    }

    let header = header.finish()?;
    let (tree_root, tree_directories, tree_files) = parse_tree(lines)?;
    let expected_root = match header.content_type {
        ContentType::Program => "program",
    };
    if tree_root != expected_root {
        return Err(InspectionErrorCode::ProviderInconsistent);
    }
    let declared = header
        .partitions
        .iter()
        .map(|partition| partition.index.to_string())
        .collect::<BTreeSet<_>>();
    let mounted = tree_directories
        .iter()
        .filter_map(|path| path.split('/').next().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    if declared != mounted {
        return Err(InspectionErrorCode::ProviderInconsistent);
    }
    if tree_files.is_empty() {
        return Err(InspectionErrorCode::ProviderContentUnreadable);
    }
    Ok(ProviderFacts {
        format_version: header.format_version,
        distribution: header.distribution,
        content_type: header.content_type,
        key_generation: header.key_generation,
        signature_generation: header.signature_generation,
        kaek_index: header.kaek_index,
        program_id: header.program_id,
        content_index: header.content_index,
        declared_size: header.size,
        partitions: header.partitions,
        tree_root,
        tree_directories,
        tree_files,
    })
}

#[derive(Default)]
struct HeaderBuilder {
    format_version: Option<u8>,
    distribution: Option<Distribution>,
    content_type: Option<ContentType>,
    key_generation: Option<u8>,
    signature_generation: Option<u8>,
    kaek_index: Option<u8>,
    size: Option<u64>,
    program_id: Option<u64>,
    content_index: Option<u32>,
    sdk_addon: Option<String>,
    rights_id: Option<String>,
    has_partitions: bool,
    partitions: Vec<ProviderPartition>,
}

struct FinishedHeader {
    format_version: u8,
    distribution: Distribution,
    content_type: ContentType,
    key_generation: u8,
    signature_generation: u8,
    kaek_index: u8,
    size: u64,
    program_id: u64,
    content_index: u32,
    partitions: Vec<ProviderPartition>,
}

impl HeaderBuilder {
    fn set_format(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        let version = match value {
            "NCA3" => 3,
            "NCA0" | "NCA1" | "NCA2" => {
                return Err(InspectionErrorCode::UnsupportedInspectionProfile);
            }
            _ => return Err(InspectionErrorCode::ProviderOutputMalformed),
        };
        set_once(&mut self.format_version, version)
    }

    fn set_distribution(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        let distribution = match value {
            "Game Card" => Distribution::GameCard,
            "Download" => Distribution::Download,
            "Unknown" => return Err(InspectionErrorCode::UnsupportedInspectionProfile),
            _ => return Err(InspectionErrorCode::ProviderOutputMalformed),
        };
        set_once(&mut self.distribution, distribution)
    }

    fn set_content_type(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        let content_type = match value {
            "Program" => ContentType::Program,
            "Meta" | "Control" | "Manual" | "Data" | "PublicData" | "Unknown" => {
                return Err(InspectionErrorCode::UnsupportedInspectionProfile);
            }
            _ => return Err(InspectionErrorCode::ProviderOutputMalformed),
        };
        set_once(&mut self.content_type, content_type)
    }

    fn set_key_generation(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        let generation = value
            .parse::<u8>()
            .map_err(|_| InspectionErrorCode::ProviderOutputMalformed)?;
        if generation > 0x20 {
            return Err(InspectionErrorCode::UnsupportedInspectionProfile);
        }
        set_once(&mut self.key_generation, generation)
    }

    fn set_signature_generation(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        let generation = value
            .parse::<u8>()
            .map_err(|_| InspectionErrorCode::ProviderOutputMalformed)?;
        set_once(&mut self.signature_generation, generation)
    }

    fn set_kaek_index(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        set_once(&mut self.kaek_index, validate_kaek(value)?)
    }

    fn set_size(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        set_once(&mut self.size, parse_hex(value)?)
    }

    fn set_program_id(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        set_once(&mut self.program_id, parse_hex(value)?)
    }

    fn set_content_index(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        let index = value
            .parse::<u32>()
            .map_err(|_| InspectionErrorCode::ProviderOutputMalformed)?;
        set_once(&mut self.content_index, index)
    }

    fn set_sdk_addon(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        validate_sdk_version(value)?;
        set_once(&mut self.sdk_addon, value.to_owned())
    }

    fn finish_partition(&mut self, partition: PartitionBuilder) -> Result<(), InspectionErrorCode> {
        let partition = partition.finish()?;
        if self
            .partitions
            .last()
            .is_some_and(|previous| previous.index >= partition.index)
        {
            return Err(InspectionErrorCode::ProviderInconsistent);
        }
        self.partitions.push(partition);
        Ok(())
    }

    fn finish(self) -> Result<FinishedHeader, InspectionErrorCode> {
        if !self.has_partitions
            || self.partitions.is_empty()
            || self.partitions.len() > 4
            || self.format_version.is_none()
            || self.distribution.is_none()
            || self.content_type.is_none()
            || self.key_generation.is_none()
            || self.signature_generation.is_none()
            || self.kaek_index.is_none()
            || self.size.is_none()
            || self.program_id.is_none()
            || self.content_index.is_none()
            || self.sdk_addon.is_none()
        {
            return Err(InspectionErrorCode::ProviderOutputMalformed);
        }
        Ok(FinishedHeader {
            format_version: self.format_version.expect("checked"),
            distribution: self.distribution.expect("checked"),
            content_type: self.content_type.expect("checked"),
            key_generation: self.key_generation.expect("checked"),
            signature_generation: self.signature_generation.expect("checked"),
            kaek_index: self.kaek_index.expect("checked"),
            size: self.size.expect("checked"),
            program_id: self.program_id.expect("checked"),
            content_index: self.content_index.expect("checked"),
            partitions: self.partitions,
        })
    }
}

struct PartitionBuilder {
    index: u8,
    offset: Option<u64>,
    size: Option<u64>,
    format: Option<String>,
    hash_type: Option<String>,
    encryption: Option<String>,
}

impl PartitionBuilder {
    fn new(index: u8) -> Self {
        Self {
            index,
            offset: None,
            size: None,
            format: None,
            hash_type: None,
            encryption: None,
        }
    }

    fn set_offset(&mut self, value: u64) -> Result<(), InspectionErrorCode> {
        set_once(&mut self.offset, value)
    }

    fn set_size(&mut self, value: u64) -> Result<(), InspectionErrorCode> {
        set_once(&mut self.size, value)
    }

    fn set_format(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        set_once(&mut self.format, value.to_owned())
    }

    fn set_hash_type(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        set_once(&mut self.hash_type, value.to_owned())
    }

    fn set_encryption(&mut self, value: &str) -> Result<(), InspectionErrorCode> {
        set_once(&mut self.encryption, value.to_owned())
    }

    fn finish(self) -> Result<ProviderPartition, InspectionErrorCode> {
        let partition = ProviderPartition {
            index: self.index,
            offset: self
                .offset
                .ok_or(InspectionErrorCode::ProviderOutputMalformed)?,
            size: self
                .size
                .ok_or(InspectionErrorCode::ProviderOutputMalformed)?,
            format: self
                .format
                .ok_or(InspectionErrorCode::ProviderOutputMalformed)?,
            hash_type: self
                .hash_type
                .ok_or(InspectionErrorCode::ProviderOutputMalformed)?,
            encryption: self
                .encryption
                .ok_or(InspectionErrorCode::ProviderOutputMalformed)?,
        };
        match partition.hash_type.as_str() {
            "None" => {}
            "HierarchicalSha256" | "HierarchicalIntegrity" => {
                return Err(InspectionErrorCode::UnsupportedInspectionProfile);
            }
            _ => return Err(InspectionErrorCode::ProviderOutputMalformed),
        }
        match partition.encryption.as_str() {
            "None" => {}
            "AesCtr" | "AesXts" => return Err(InspectionErrorCode::UnsupportedInspectionProfile),
            _ => return Err(InspectionErrorCode::ProviderOutputMalformed),
        }
        match partition.format.as_str() {
            "PartitionFs" => {}
            "RomFs" => return Err(InspectionErrorCode::UnsupportedInspectionProfile),
            _ => return Err(InspectionErrorCode::ProviderOutputMalformed),
        }
        if partition.size == 0 {
            return Err(InspectionErrorCode::ProviderOutputMalformed);
        }
        Ok(partition)
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), InspectionErrorCode> {
    if slot.is_some() {
        return Err(InspectionErrorCode::ProviderOutputMalformed);
    }
    *slot = Some(value);
    Ok(())
}

fn parse_tree<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<(String, HashSet<String>, HashSet<String>), InspectionErrorCode> {
    let mut root = None;
    let mut directories = HashSet::new();
    let mut files = HashSet::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut nodes = 0_usize;
    let mut name_bytes = 0_usize;
    let mut path_bytes = 0_usize;

    for raw_line in lines {
        let line = raw_line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if consume_warning(line.trim())? {
            continue;
        }
        let indent = line.bytes().take_while(|byte| *byte == b' ').count();
        if indent == 0 || indent > MAX_INDENT {
            return Err(InspectionErrorCode::ProviderOutputMalformed);
        }
        let content = &line[indent..];
        if content.is_empty() {
            return Err(InspectionErrorCode::ProviderOutputMalformed);
        }
        nodes = nodes
            .checked_add(1)
            .ok_or(InspectionErrorCode::ProviderOutputExceeded)?;
        if nodes > MAX_TREE_NODES {
            return Err(InspectionErrorCode::ProviderOutputExceeded);
        }
        name_bytes = name_bytes
            .checked_add(content.len())
            .ok_or(InspectionErrorCode::ProviderOutputExceeded)?;
        if name_bytes > MAX_TREE_NAME_BYTES {
            return Err(InspectionErrorCode::ProviderOutputExceeded);
        }

        if root.is_none() {
            if indent != 1 || !content.ends_with(":/") || content[..content.len() - 2].contains('/')
            {
                return Err(InspectionErrorCode::ProviderOutputMalformed);
            }
            let mut label = String::new();
            label
                .try_reserve_exact(content.len() - 2)
                .map_err(|_| InspectionErrorCode::ProviderOutputExceeded)?;
            label.push_str(&content[..content.len() - 2]);
            if label.is_empty() {
                return Err(InspectionErrorCode::ProviderOutputMalformed);
            }
            charge_tree_path_bytes(&mut path_bytes, label.len())?;
            root = Some(label.clone());
            stack
                .try_reserve(1)
                .map_err(|_| InspectionErrorCode::ProviderOutputExceeded)?;
            stack.push((1, String::new()));
            continue;
        }

        let is_directory = content.ends_with('/');
        let parent_depth = indent.saturating_sub(1);
        if parent_depth == 0 {
            return Err(InspectionErrorCode::ProviderOutputMalformed);
        }
        let name = if is_directory {
            &content[..content.len() - 1]
        } else {
            content
        };
        if name.is_empty() || name.contains('/') || name.contains('\0') {
            return Err(InspectionErrorCode::ProviderOutputMalformed);
        }
        while stack.last().is_some_and(|(level, _)| *level > parent_depth) {
            stack.pop();
        }
        let parent = stack
            .last()
            .filter(|(level, _)| *level == parent_depth)
            .map(|(_, path)| path.as_str())
            .ok_or(InspectionErrorCode::ProviderOutputMalformed)?;
        let path_len = parent
            .len()
            .checked_add(usize::from(!parent.is_empty()))
            .and_then(|length| length.checked_add(name.len()))
            .ok_or(InspectionErrorCode::ProviderOutputExceeded)?;
        let retained_path_bytes = if is_directory {
            path_len
                .checked_mul(2)
                .ok_or(InspectionErrorCode::ProviderOutputExceeded)?
        } else {
            path_len
        };
        charge_tree_path_bytes(&mut path_bytes, retained_path_bytes)?;
        let mut path = String::new();
        path.try_reserve_exact(path_len)
            .map_err(|_| InspectionErrorCode::ProviderOutputExceeded)?;
        if !parent.is_empty() {
            path.push_str(parent);
            path.push('/');
        }
        path.push_str(name);
        if is_directory {
            if directories.contains(&path) {
                return Err(InspectionErrorCode::ProviderInconsistent);
            }
            directories
                .try_reserve(1)
                .map_err(|_| InspectionErrorCode::ProviderOutputExceeded)?;
            stack
                .try_reserve(1)
                .map_err(|_| InspectionErrorCode::ProviderOutputExceeded)?;
            let mut stack_path = String::new();
            stack_path
                .try_reserve_exact(path_len)
                .map_err(|_| InspectionErrorCode::ProviderOutputExceeded)?;
            stack_path.push_str(&path);
            directories.insert(path);
            stack.push((indent, stack_path));
        } else {
            if files.contains(&path) {
                return Err(InspectionErrorCode::ProviderInconsistent);
            }
            files
                .try_reserve(1)
                .map_err(|_| InspectionErrorCode::ProviderOutputExceeded)?;
            files.insert(path);
        }
    }
    Ok((
        root.ok_or(InspectionErrorCode::ProviderOutputMalformed)?,
        directories,
        files,
    ))
}

fn charge_tree_path_bytes(total: &mut usize, amount: usize) -> Result<(), InspectionErrorCode> {
    *total = total
        .checked_add(amount)
        .ok_or(InspectionErrorCode::ProviderOutputExceeded)?;
    if *total > MAX_TREE_PATH_BYTES {
        return Err(InspectionErrorCode::ProviderOutputExceeded);
    }
    Ok(())
}

fn consume_warning(line: &str) -> Result<bool, InspectionErrorCode> {
    if !line.starts_with('[') {
        return Ok(false);
    }
    if line.starts_with("[WARNING] NCA Header Main Signature: FAIL")
        || line.starts_with("[WARNING] NCA Header ACID Signature: FAIL (")
    {
        return Ok(true);
    }
    match line {
        "[NCA Header]" | "[ContentArchive/Tree]" => Ok(false),
        "[WARNING] Failed to load \"title.keys\" keyfile."
        | "[WARNING] Failed to locate \"title.keys\" keyfile."
        | "[WARNING] Failed to load NCA Header Key." => Ok(true),
        _ if line.starts_with("[WARNING] NCA Partition ") && line.contains("UNSUPPORTED") => {
            Err(InspectionErrorCode::UnsupportedInspectionProfile)
        }
        _ if line.starts_with("[WARNING] NCA Partition ") && line.contains("not readable") => {
            Err(InspectionErrorCode::ProviderContentUnreadable)
        }
        _ => Err(InspectionErrorCode::ProviderOutputMalformed),
    }
}

fn field<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    line.strip_prefix(label).map(str::trim)
}

fn partition_index(line: &str) -> Option<u8> {
    let value = line.strip_suffix(':')?;
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let index = value.parse::<u8>().ok()?;
    (index < 4).then_some(index)
}

fn parse_hex(value: &str) -> Result<u64, InspectionErrorCode> {
    let value = value
        .strip_prefix("0x")
        .ok_or(InspectionErrorCode::ProviderOutputMalformed)?;
    if value.is_empty() || value.len() > 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(InspectionErrorCode::ProviderOutputMalformed);
    }
    u64::from_str_radix(value, 16).map_err(|_| InspectionErrorCode::ProviderOutputMalformed)
}

fn validate_kaek(value: &str) -> Result<u8, InspectionErrorCode> {
    let (name, number) = value
        .split_once(" (")
        .and_then(|(name, rest)| rest.strip_suffix(')').map(|number| (name, number)))
        .ok_or(InspectionErrorCode::ProviderOutputMalformed)?;
    let number = number
        .parse::<u8>()
        .map_err(|_| InspectionErrorCode::ProviderOutputMalformed)?;
    let expected = match number {
        0 => "Application",
        1 => "Ocean",
        2 => "System",
        _ => return Err(InspectionErrorCode::UnsupportedInspectionProfile),
    };
    if name != expected {
        return Err(InspectionErrorCode::ProviderOutputMalformed);
    }
    Ok(number)
}

fn validate_sdk_version(value: &str) -> Result<(), InspectionErrorCode> {
    let (version, generation) = value
        .split_once(" (v")
        .and_then(|(version, rest)| rest.strip_suffix(')').map(|rest| (version, rest)))
        .ok_or(InspectionErrorCode::ProviderOutputMalformed)?;
    let components = version.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components
            .iter()
            .any(|component| component.is_empty() || !component.bytes().all(|b| b.is_ascii_digit()))
        || generation.is_empty()
        || !generation.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(InspectionErrorCode::ProviderOutputMalformed);
    }
    Ok(())
}

fn validate_rights_id(value: &str) -> Result<(), InspectionErrorCode> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(InspectionErrorCode::ProviderOutputMalformed);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) const CAPTURED_OUTPUT: &str = r#"[WARNING] Failed to load "title.keys" keyfile.
[NCA Header]
  Format Type:     NCA3
  Dist. Type:      Game Card
  Content Type:    Program
  Key Generation:  0
  Sig. Generation: 0
  Kaek Index:      Application (0)
  Size:            0xe00
  ProgID:          0x0102030405060708
  Content Index:   0
  SdkAddon Ver.:   0.0.0 (v0)
  Partitions:
    0:
      Offset:      0xc00
      Size:        0x200
      Format Type: PartitionFs
      Hash Type:   None
      Enc. Type:   None
[ContentArchive/Tree]
 program:/
  0/
   hello.nca
"#;

#[cfg(test)]
mod tests {
    use super::{ContentType, Distribution, MAX_TREE_NAME_BYTES, parse, parse_tree};
    use crate::inspection::InspectionErrorCode;
    use crate::provider::manifest::manifest;

    const CAPTURED: &str = super::CAPTURED_OUTPUT;

    #[test]
    fn parses_captured_nstool_1_9_2_output() {
        let facts = parse(CAPTURED.as_bytes(), b"").unwrap();
        assert_eq!(facts.format_version, 3);
        assert_eq!(facts.distribution, Distribution::GameCard);
        assert_eq!(facts.content_type, ContentType::Program);
        assert_eq!(facts.declared_size, 0xe00);
        assert_eq!(facts.kaek_index, 0);
        assert_eq!(facts.partitions.len(), 1);
        assert_eq!(facts.partitions[0].offset, 0xc00);
        assert_eq!(facts.tree_root, "program");
        assert_eq!(facts.tree_files.iter().next().unwrap(), "0/hello.nca");
    }

    #[test]
    fn every_repeated_provider_field_is_rejected_even_when_identical() {
        for field in [
            "  Format Type:     NCA3\n",
            "  Dist. Type:      Game Card\n",
            "  Content Type:    Program\n",
            "  Key Generation:  0\n",
            "  Sig. Generation: 0\n",
            "  Kaek Index:      Application (0)\n",
            "  Size:            0xe00\n",
            "  ProgID:          0x0102030405060708\n",
            "  Content Index:   0\n",
            "  SdkAddon Ver.:   0.0.0 (v0)\n",
            "      Offset:      0xc00\n",
            "      Size:        0x200\n",
            "      Format Type: PartitionFs\n",
            "      Hash Type:   None\n",
            "      Enc. Type:   None\n",
        ] {
            let text = CAPTURED.replace(field, &format!("{field}{field}"));
            assert_eq!(
                parse(text.as_bytes(), b"").unwrap_err(),
                InspectionErrorCode::ProviderOutputMalformed,
                "repeated field: {field:?}"
            );
        }

        let rights_id = "  RightsId: 0102030405060708090a0b0c0d0e0f10\n";
        let with_rights = CAPTURED.replace(
            "  SdkAddon Ver.:   0.0.0 (v0)\n",
            &format!("  SdkAddon Ver.:   0.0.0 (v0)\n{rights_id}{rights_id}"),
        );
        assert_eq!(
            parse(with_rights.as_bytes(), b"").unwrap_err(),
            InspectionErrorCode::ProviderOutputMalformed
        );

        let repeated_partition_header =
            CAPTURED.replace("  Partitions:\n", "  Partitions:\n  Partitions:\n");
        assert_eq!(
            parse(repeated_partition_header.as_bytes(), b"").unwrap_err(),
            InspectionErrorCode::ProviderOutputMalformed
        );
    }

    #[test]
    fn conflicting_kaek_sdk_and_partition_fields_are_rejected() {
        for (original, conflicting) in [
            (
                "  Kaek Index:      Application (0)\n",
                "  Kaek Index:      Ocean (1)\n",
            ),
            (
                "  SdkAddon Ver.:   0.0.0 (v0)\n",
                "  SdkAddon Ver.:   1.0.0 (v1)\n",
            ),
            ("      Offset:      0xc00\n", "      Offset:      0xe00\n"),
            ("      Size:        0x200\n", "      Size:        0x100\n"),
            (
                "      Format Type: PartitionFs\n",
                "      Format Type: RomFs\n",
            ),
            (
                "      Hash Type:   None\n",
                "      Hash Type:   HierarchicalSha256\n",
            ),
            ("      Enc. Type:   None\n", "      Enc. Type:   AesCtr\n"),
        ] {
            let text = CAPTURED.replace(original, &format!("{original}{conflicting}"));
            assert_eq!(
                parse(text.as_bytes(), b"").unwrap_err(),
                InspectionErrorCode::ProviderOutputMalformed,
                "conflicting field: {original:?}"
            );
        }
    }

    #[test]
    fn accepts_optional_rights_id_and_signature_warning() {
        let text = CAPTURED
            .replace(
                "[NCA Header]\n",
                "[WARNING] NCA Header Main Signature: FAIL\n[NCA Header]\n",
            )
            .replace(
                "  SdkAddon Ver.:   0.0.0 (v0)\n",
                "  SdkAddon Ver.:   0.0.0 (v0)\n  RightsId: 0102030405060708090a0b0c0d0e0f10\n",
            );
        parse(text.as_bytes(), b"").unwrap();
    }

    #[test]
    fn rejects_unknown_output_semantics() {
        let text = CAPTURED.replace("Enc. Type:   None", "Enc. Type:   Surprise");
        assert_eq!(
            parse(text.as_bytes(), b"").unwrap_err(),
            InspectionErrorCode::ProviderOutputMalformed
        );
        let text = CAPTURED.replace("Format Type:     NCA3", "Format Type:     NCA4");
        assert_eq!(
            parse(text.as_bytes(), b"").unwrap_err(),
            InspectionErrorCode::ProviderOutputMalformed
        );
    }

    #[test]
    fn rejects_unreadable_or_unqualified_partition_warnings() {
        let unreadable = format!("{CAPTURED}[WARNING] NCA Partition 0 not readable.\n");
        assert_eq!(
            parse(unreadable.as_bytes(), b"").unwrap_err(),
            InspectionErrorCode::ProviderContentUnreadable
        );
        let unsupported = CAPTURED.replace("Enc. Type:   None", "Enc. Type:   AesXts");
        assert_eq!(
            parse(unsupported.as_bytes(), b"").unwrap_err(),
            InspectionErrorCode::UnsupportedInspectionProfile
        );
    }

    #[test]
    fn rejects_stderr_and_spoofed_tree_paths() {
        assert_eq!(
            parse(CAPTURED.as_bytes(), b"detail").unwrap_err(),
            InspectionErrorCode::ProviderOutputMalformed
        );
        let spoofed = CAPTURED.replace(" program:/", " root:/");
        assert_eq!(
            parse(spoofed.as_bytes(), b"").unwrap_err(),
            InspectionErrorCode::ProviderInconsistent
        );
    }

    #[test]
    fn accepts_four_partitions_and_many_files() {
        let mut text = CAPTURED.replace("    0:\n      Offset:      0xc00\n      Size:        0x200\n      Format Type: PartitionFs\n      Hash Type:   None\n      Enc. Type:   None\n", "");
        let header_end = text.find("  Partitions:\n").unwrap() + "  Partitions:\n".len();
        let mut partitions = String::new();
        let mut tree = String::from("\n program:/\n");
        for index in 0..4_u32 {
            partitions.push_str(&format!(
                "    {index}:\n      Offset:      0x{:x}\n      Size:        0x200\n      Format Type: PartitionFs\n      Hash Type:   None\n      Enc. Type:   None\n",
                0xc00 + u64::from(index) * 0x200
            ));
            tree.push_str(&format!("  {index}/\n"));
            for file in 0..500 {
                tree.push_str(&format!("   part{index}_{file:03}.bin\n"));
            }
        }
        text.replace_range(header_end..header_end, &partitions);
        let tree_start =
            text.find("[ContentArchive/Tree]\n").unwrap() + "[ContentArchive/Tree]\n".len();
        text.replace_range(tree_start.., &tree);
        let facts = parse(text.as_bytes(), b"").unwrap();
        assert_eq!(facts.partitions.len(), 4);
        assert_eq!(facts.tree_files.len(), 2_000);
    }

    #[test]
    fn tree_name_byte_budget_accepts_exact_limit_and_rejects_one_byte_over() {
        let mut lines = Vec::with_capacity(4_098);
        lines.push(" PFS0:/".to_owned());
        for index in 0..4_095_u32 {
            let suffix = format!("{index:04x}");
            lines.push(format!("  {}{suffix}", "a".repeat(4_096 - suffix.len())));
        }
        let suffix = "0fff";
        lines.push(format!("  {}{suffix}", "b".repeat(4_090 - suffix.len())));
        assert_eq!(
            lines
                .iter()
                .skip(1)
                .map(|line| line.len() - 2)
                .sum::<usize>()
                + "PFS0:/".len(),
            MAX_TREE_NAME_BYTES
        );

        let references = lines.iter().map(String::as_str).collect::<Vec<_>>();
        let (_, _, files) = parse_tree(references.iter().copied()).unwrap();
        assert_eq!(files.len(), 4_096);

        lines.push("  z".to_owned());
        let references = lines.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(matches!(
            parse_tree(references.iter().copied()),
            Err(InspectionErrorCode::ProviderOutputExceeded)
        ));
    }

    #[test]
    fn expanded_tree_paths_are_bounded_independently_of_input_name_bytes() {
        let mut lines = vec![" program:/".to_owned()];
        for depth in 0..16 {
            lines.push(format!(
                "{}{}{}",
                " ".repeat(depth + 2),
                "d".repeat(1024),
                "/"
            ));
        }
        for index in 0..1024 {
            lines.push(format!("{}file-{index}", " ".repeat(18)));
        }
        let raw_name_bytes = lines
            .iter()
            .skip(1)
            .map(|line| line.trim().len())
            .sum::<usize>();
        assert!(raw_name_bytes < MAX_TREE_NAME_BYTES);

        let references = lines.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(matches!(
            parse_tree(references.iter().copied()),
            Err(InspectionErrorCode::ProviderOutputExceeded)
        ));
    }

    #[test]
    fn newline_storm_is_rejected_by_the_bounded_line_count() {
        let text = "\n".repeat(super::MAX_TREE_NODES * 2 + 1);
        assert_eq!(
            parse(text.as_bytes(), b"").unwrap_err(),
            InspectionErrorCode::ProviderOutputExceeded
        );
    }

    #[test]
    #[ignore = "manual standalone check; requires checksum-verified pinned NSTool in NSCB_STANDALONE_NSTOOL"]
    fn standalone_pinned_nstool_accepts_zero_header_key_and_reports_differential_generations() {
        use crate::nca::synthetic_nca_with_header_fields_and_key;
        use crate::sha256::Sha256Digest;
        use std::fs;
        use std::process::Command;

        let executable = std::env::var_os("NSCB_STANDALONE_NSTOOL")
            .map(std::path::PathBuf::from)
            .expect("set NSCB_STANDALONE_NSTOOL to the pinned macOS arm64 artifact");
        let provider_manifest = manifest().unwrap();
        let target = provider_manifest
            .find("macos", "aarch64")
            .expect("pinned macOS arm64 provider target");
        let metadata = fs::metadata(&executable).expect("NSTool executable metadata");
        assert_eq!(metadata.len(), target.executable_bytes());
        let executable_bytes = fs::read(&executable).expect("read NSTool executable");
        assert_eq!(
            Sha256Digest::digest(&executable_bytes),
            target.executable_sha256()
        );

        let directory = tempfile::tempdir().expect("synthetic qualification directory");
        let input = directory.path().join("differential-fields.nca");
        let key_file = directory.path().join("synthetic.keys");
        fs::write(
            &input,
            synthetic_nca_with_header_fields_and_key(3, 8, 5, 1, &[0; 32]),
        )
        .expect("write synthetic zero-key encrypted NCA");
        fs::write(&key_file, format!("nca_header_key = {}\n", "00".repeat(32)))
            .expect("write synthetic NCA header key");

        let output = Command::new(&executable)
            .args([
                "-k",
                key_file.to_str().unwrap(),
                "-t",
                "nca",
                "-v",
                "--fstree",
                input.to_str().unwrap(),
            ])
            .current_dir(directory.path())
            .env_clear()
            .env("HOME", directory.path())
            .env("TMPDIR", directory.path())
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .output()
            .expect("run pinned NSTool directly for standalone qualification");
        assert!(
            output.status.success(),
            "standalone NSTool exited unsuccessfully (status: {:?})\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let facts = parse(&output.stdout, &output.stderr).unwrap();
        assert_eq!(facts.key_generation, 8);
        assert_eq!(facts.signature_generation, 5);
        assert_eq!(facts.kaek_index, 1);
        assert!(facts.tree_files.contains("0/hello.nca"));
        println!(
            "standalone_nstool=verified; effective_key_generation={}; signature_generation={}; kaek_index={}; files={}",
            facts.key_generation,
            facts.signature_generation,
            facts.kaek_index,
            facts.tree_files.len()
        );
    }
}
