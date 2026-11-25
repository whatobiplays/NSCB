//! Bounded JSON parsing with duplicate-key rejection.
//!
//! The standard serde JSON model accepts duplicate object keys and silently
//! keeps one of the values. Input lists, Split manifests, and local trust
//! receipts all rely on object keys having exactly one meaning, so they use
//! this parser and then project the generic value into their own schema.

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;
use std::mem::size_of;
use unicode_normalization::UnicodeNormalization;

/// A JSON value that preserves object fields in document order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StrictJsonValue {
    /// An object whose keys are known to be unique.
    Object(Vec<(String, StrictJsonValue)>),
    /// An array of values.
    Array(Vec<StrictJsonValue>),
    /// A JSON string.
    String(String),
    /// A JSON number, including floats and negative integers.
    Number(serde_json::Number),
    /// A JSON boolean.
    Bool(bool),
    /// A JSON null.
    Null,
}

/// Resource ceilings applied while a strict JSON value is being parsed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ParseLimits {
    pub(crate) max_depth: usize,
    pub(crate) max_nodes: usize,
    pub(crate) max_collection_items: usize,
    pub(crate) max_string_bytes: usize,
    pub(crate) max_allocation_bytes: usize,
}

/// Additional limits for a standalone Program manifest.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProgramManifestLimits {
    pub(crate) max_files: usize,
    pub(crate) max_directories: usize,
    pub(crate) max_partitions: usize,
    pub(crate) max_file_name_bytes: usize,
    pub(crate) max_total_file_name_bytes: usize,
    pub(crate) max_string_table_bytes: usize,
    pub(crate) max_directory_path_bytes: usize,
}

/// Failure categories for a bounded strict parse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoundedParseError {
    Malformed,
    ResourceLimit,
    AllocationFailed,
}

impl fmt::Display for BoundedParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed JSON",
            Self::ResourceLimit => "JSON resource limit exceeded",
            Self::AllocationFailed => "JSON allocation failed",
        })
    }
}

/// Parses one JSON document and rejects duplicate object keys at every depth.
pub(crate) fn parse(bytes: &[u8]) -> Result<StrictJsonValue, ()> {
    serde_json::from_slice(bytes).map_err(|_| ())
}

/// Parses one strict JSON document while enforcing its budgets during input.
#[cfg(test)]
pub(crate) fn parse_bounded(
    bytes: &[u8],
    limits: ParseLimits,
) -> Result<StrictJsonValue, BoundedParseError> {
    parse_with_limits(bytes, limits, None)
}

/// Parses a manifest while counting its records and PFS0 names as they arrive.
pub(crate) fn parse_program_manifest_bounded(
    bytes: &[u8],
    limits: ParseLimits,
    manifest_limits: ProgramManifestLimits,
) -> Result<StrictJsonValue, BoundedParseError> {
    parse_with_limits(bytes, limits, Some(manifest_limits))
}

fn parse_with_limits(
    bytes: &[u8],
    limits: ParseLimits,
    manifest_limits: Option<ProgramManifestLimits>,
) -> Result<StrictJsonValue, BoundedParseError> {
    let mut budget = ParseBudget {
        limits,
        manifest_limits,
        nodes: 0,
        collection_items: 0,
        string_bytes: 0,
        allocation_bytes: 0,
        files: 0,
        directories: 0,
        partitions: 0,
        file_name_bytes: 0,
        string_table_bytes: 0,
        directory_path_bytes: 0,
        failure: None,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = StrictJsonValueSeed {
        budget: Some(&mut budget),
        depth: 1,
        collection_item: false,
        context: if manifest_limits.is_some() {
            ValueContext::ManifestRoot
        } else {
            ValueContext::Generic
        },
    }
    .deserialize(&mut deserializer);
    match parsed {
        Ok(value) if deserializer.end().is_ok() => Ok(value),
        Ok(_) => Err(BoundedParseError::Malformed),
        Err(_) => Err(budget.failure.unwrap_or(BoundedParseError::Malformed)),
    }
}

/// Returns the first field named `name`, or `None` when it is absent.
pub(crate) fn required_field<'a>(
    fields: &'a [(String, StrictJsonValue)],
    name: &str,
) -> Option<&'a StrictJsonValue> {
    fields
        .iter()
        .find(|(field_name, _)| field_name == name)
        .map(|(_, value)| value)
}

/// Returns the maximum object/array nesting depth of `value`.
pub(crate) fn depth(value: &StrictJsonValue) -> usize {
    match value {
        StrictJsonValue::Object(fields) => {
            1 + fields
                .iter()
                .map(|(_, value)| depth(value))
                .max()
                .unwrap_or(0)
        }
        StrictJsonValue::Array(values) => 1 + values.iter().map(depth).max().unwrap_or(0),
        StrictJsonValue::String(_)
        | StrictJsonValue::Number(_)
        | StrictJsonValue::Bool(_)
        | StrictJsonValue::Null => 1,
    }
}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictJsonValueSeed {
            budget: None,
            depth: 1,
            collection_item: false,
            context: ValueContext::Generic,
        }
        .deserialize(deserializer)
    }
}

struct ParseBudget {
    limits: ParseLimits,
    manifest_limits: Option<ProgramManifestLimits>,
    nodes: usize,
    collection_items: usize,
    string_bytes: usize,
    allocation_bytes: usize,
    files: usize,
    directories: usize,
    partitions: usize,
    file_name_bytes: usize,
    string_table_bytes: usize,
    directory_path_bytes: usize,
    failure: Option<BoundedParseError>,
}

impl ParseBudget {
    fn begin_value<E: de::Error>(
        &mut self,
        depth: usize,
        collection_item: bool,
        context: ValueContext,
    ) -> Result<(), E> {
        if depth > self.limits.max_depth {
            return self.reject(BoundedParseError::ResourceLimit);
        }
        self.nodes = match self.nodes.checked_add(1) {
            Some(nodes) if nodes <= self.limits.max_nodes => nodes,
            _ => return self.reject(BoundedParseError::ResourceLimit),
        };
        if collection_item {
            self.collection_items = match self.collection_items.checked_add(1) {
                Some(items) if items <= self.limits.max_collection_items => items,
                _ => return self.reject(BoundedParseError::ResourceLimit),
            };
        }
        if let Some(limits) = self.manifest_limits {
            let counter = match context {
                ValueContext::ManifestPartition => {
                    Some((&mut self.partitions, limits.max_partitions))
                }
                ValueContext::ManifestFile => Some((&mut self.files, limits.max_files)),
                ValueContext::ManifestDirectory => {
                    Some((&mut self.directories, limits.max_directories))
                }
                _ => None,
            };
            if let Some((counter, maximum)) = counter {
                *counter = match counter.checked_add(1) {
                    Some(count) if count <= maximum => count,
                    _ => return self.reject(BoundedParseError::ResourceLimit),
                };
            }
        }
        self.charge_allocation::<E>(size_of::<StrictJsonValue>())
    }

    fn charge_string<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        self.string_bytes = match self.string_bytes.checked_add(bytes) {
            Some(total) if total <= self.limits.max_string_bytes => total,
            _ => return self.reject(BoundedParseError::ResourceLimit),
        };
        self.charge_allocation(bytes)
    }

    fn charge_allocation<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        self.allocation_bytes = match self.allocation_bytes.checked_add(bytes) {
            Some(total) if total <= self.limits.max_allocation_bytes => total,
            _ => return self.reject(BoundedParseError::ResourceLimit),
        };
        Ok(())
    }

    fn charge_manifest_string<E: de::Error>(
        &mut self,
        context: ValueContext,
        value: &str,
    ) -> Result<(), E> {
        let Some(limits) = self.manifest_limits else {
            return Ok(());
        };
        match context {
            ValueContext::ManifestFilePath => {
                if !(value.starts_with("0/")
                    || value.starts_with("1/")
                    || value.starts_with("2/")
                    || value.starts_with("3/"))
                {
                    return self.reject(BoundedParseError::Malformed);
                }
                let inner_path = &value[2..];
                if inner_path.len() > limits.max_file_name_bytes {
                    return self.reject(BoundedParseError::ResourceLimit);
                }
                self.file_name_bytes = match self.file_name_bytes.checked_add(inner_path.len()) {
                    Some(total) if total <= limits.max_total_file_name_bytes => total,
                    _ => return self.reject(BoundedParseError::ResourceLimit),
                };
                self.string_table_bytes = match self
                    .string_table_bytes
                    .checked_add(inner_path.len())
                    .and_then(|total| total.checked_add(1))
                {
                    Some(total) if total <= limits.max_string_table_bytes => total,
                    _ => return self.reject(BoundedParseError::ResourceLimit),
                };
            }
            ValueContext::ManifestDirectory => {
                self.directory_path_bytes = match self.directory_path_bytes.checked_add(value.len())
                {
                    Some(total) if total <= limits.max_directory_path_bytes => total,
                    _ => return self.reject(BoundedParseError::ResourceLimit),
                };
            }
            _ => {}
        }
        Ok(())
    }

    fn reject<T, E: de::Error>(&mut self, failure: BoundedParseError) -> Result<T, E> {
        self.failure = Some(failure);
        Err(E::custom(failure))
    }
}

struct StrictJsonValueSeed<'a> {
    budget: Option<&'a mut ParseBudget>,
    depth: usize,
    collection_item: bool,
    context: ValueContext,
}

#[derive(Clone, Copy)]
enum ValueContext {
    Generic,
    ManifestRoot,
    ManifestSource,
    ManifestPartitions,
    ManifestPartition,
    ManifestFiles,
    ManifestFile,
    ManifestFilePath,
    ManifestDirectories,
    ManifestDirectory,
}

impl<'de> DeserializeSeed<'de> for StrictJsonValueSeed<'_> {
    type Value = StrictJsonValue;

    fn deserialize<D>(mut self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if let Some(budget) = self.budget.as_deref_mut() {
            budget.begin_value(self.depth, self.collection_item, self.context)?;
        }
        deserializer.deserialize_any(StrictJsonValueVisitor {
            budget: self.budget,
            depth: self.depth,
            context: self.context,
        })
    }
}

struct StrictJsonValueVisitor<'a> {
    budget: Option<&'a mut ParseBudget>,
    depth: usize,
    context: ValueContext,
}

impl<'de> Visitor<'de> for StrictJsonValueVisitor<'_> {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(StrictJsonValue::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(mut self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Some(budget) = self.budget.as_deref_mut() {
            budget.charge_manifest_string(self.context, value)?;
            budget.charge_string(value.len())?;
        }
        let mut copy = String::new();
        copy.try_reserve_exact(value.len()).map_err(|_| {
            if let Some(budget) = self.budget.as_deref_mut() {
                budget.failure = Some(BoundedParseError::AllocationFailed);
            }
            E::custom(BoundedParseError::AllocationFailed)
        })?;
        copy.push_str(value);
        Ok(StrictJsonValue::String(copy))
    }

    fn visit_string<E>(mut self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Some(budget) = self.budget.as_deref_mut() {
            budget.charge_manifest_string(self.context, &value)?;
            budget.charge_string(value.len())?;
        }
        Ok(StrictJsonValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Null)
    }

    fn visit_seq<A>(mut self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        loop {
            let depth = self.depth.checked_add(1).ok_or_else(|| {
                if let Some(budget) = self.budget.as_deref_mut() {
                    budget.failure = Some(BoundedParseError::ResourceLimit);
                }
                A::Error::custom(BoundedParseError::ResourceLimit)
            })?;
            let budget = self.budget.as_deref_mut();
            let value = sequence.next_element_seed(StrictJsonValueSeed {
                budget,
                depth,
                collection_item: true,
                context: sequence_item_context(self.context),
            })?;
            let Some(value) = value else {
                break;
            };
            if let Some(budget) = self.budget.as_deref_mut() {
                budget.charge_allocation::<A::Error>(size_of::<StrictJsonValue>() * 2)?;
            }
            values.try_reserve(1).map_err(|_| {
                if let Some(budget) = self.budget.as_deref_mut() {
                    budget.failure = Some(BoundedParseError::AllocationFailed);
                }
                A::Error::custom(BoundedParseError::AllocationFailed)
            })?;
            values.push(value);
        }
        Ok(StrictJsonValue::Array(values))
    }

    fn visit_map<A>(mut self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = Vec::new();
        let mut keys = HashSet::new();
        loop {
            if let Some(budget) = self.budget.as_deref_mut() {
                budget.charge_allocation::<A::Error>(
                    (size_of::<(String, StrictJsonValue)>() + size_of::<String>()) * 2,
                )?;
            }
            fields.try_reserve(1).map_err(|_| {
                if let Some(budget) = self.budget.as_deref_mut() {
                    budget.failure = Some(BoundedParseError::AllocationFailed);
                }
                A::Error::custom(BoundedParseError::AllocationFailed)
            })?;
            keys.try_reserve(1).map_err(|_| {
                if let Some(budget) = self.budget.as_deref_mut() {
                    budget.failure = Some(BoundedParseError::AllocationFailed);
                }
                A::Error::custom(BoundedParseError::AllocationFailed)
            })?;
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            if let Some(budget) = self.budget.as_deref_mut() {
                budget.charge_string(key.len())?;
            }
            let normalized = match self.budget.as_deref_mut() {
                Some(budget) => normalized_key::<A::Error>(budget, &key)?,
                None => key.nfc().collect::<String>(),
            };
            if !keys.insert(normalized) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let depth = self.depth.checked_add(1).ok_or_else(|| {
                if let Some(budget) = self.budget.as_deref_mut() {
                    budget.failure = Some(BoundedParseError::ResourceLimit);
                }
                A::Error::custom(BoundedParseError::ResourceLimit)
            })?;
            let budget = self.budget.as_deref_mut();
            let value = map.next_value_seed(StrictJsonValueSeed {
                budget,
                depth,
                collection_item: true,
                context: field_value_context(self.context, &key),
            })?;
            fields.push((key, value));
        }
        Ok(StrictJsonValue::Object(fields))
    }
}

fn sequence_item_context(context: ValueContext) -> ValueContext {
    match context {
        ValueContext::ManifestPartitions => ValueContext::ManifestPartition,
        ValueContext::ManifestFiles => ValueContext::ManifestFile,
        ValueContext::ManifestDirectories => ValueContext::ManifestDirectory,
        _ => ValueContext::Generic,
    }
}

fn field_value_context(context: ValueContext, field: &str) -> ValueContext {
    match (context, field) {
        (ValueContext::ManifestRoot, "source") => ValueContext::ManifestSource,
        (ValueContext::ManifestRoot, "partitions") => ValueContext::ManifestPartitions,
        (ValueContext::ManifestPartition, "files") => ValueContext::ManifestFiles,
        (ValueContext::ManifestPartition, "directories") => ValueContext::ManifestDirectories,
        (ValueContext::ManifestFile, "path") => ValueContext::ManifestFilePath,
        _ => ValueContext::Generic,
    }
}

fn normalized_key<E: de::Error>(budget: &mut ParseBudget, key: &str) -> Result<String, E> {
    let capacity = key
        .nfc()
        .try_fold(0_usize, |total, character| {
            total.checked_add(character.len_utf8())
        })
        .ok_or_else(|| {
            budget.failure = Some(BoundedParseError::ResourceLimit);
            E::custom(BoundedParseError::ResourceLimit)
        })?;
    budget.charge_allocation(capacity)?;
    let mut normalized = String::new();
    normalized.try_reserve_exact(capacity).map_err(|_| {
        budget.failure = Some(BoundedParseError::AllocationFailed);
        E::custom(BoundedParseError::AllocationFailed)
    })?;
    normalized.extend(key.nfc());
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedParseError, ParseLimits, StrictJsonValue, depth, parse, parse_bounded,
        required_field,
    };
    use std::mem::size_of;

    #[test]
    fn rejects_duplicate_keys_at_every_depth() {
        for document in [
            br#"{"x":1,"x":2}"#.as_slice(),
            br#"{"x":{"y":1,"y":2}}"#.as_slice(),
            br#"{"x":[{"y":1,"y":2}]}"#.as_slice(),
            br#"{"\u00e9":1,"e\u0301":2}"#.as_slice(),
        ] {
            assert!(parse(document).is_err());
        }
    }

    #[test]
    fn preserves_fields_and_computes_depth() {
        let value = parse(br#"{"a":[1,{"b":null}],"c":true,"d":false}"#).unwrap();
        let StrictJsonValue::Object(fields) = &value else {
            panic!("object");
        };
        assert!(required_field(fields, "a").is_some());
        assert!(required_field(fields, "missing").is_none());
        assert_eq!(
            required_field(fields, "c"),
            Some(&StrictJsonValue::Bool(true))
        );
        assert_eq!(
            required_field(fields, "d"),
            Some(&StrictJsonValue::Bool(false))
        );
        assert_eq!(depth(&value), 4);
    }

    #[test]
    fn rejects_malformed_utf8_and_trailing_documents() {
        assert!(parse(&[0xff]).is_err());
        assert!(parse(br#"{} {}"#).is_err());
    }

    #[test]
    fn bounded_parser_enforces_depth_collection_string_and_allocation_limits() {
        let generous = ParseLimits {
            max_depth: 2,
            max_nodes: 2,
            max_collection_items: 1,
            max_string_bytes: 1,
            max_allocation_bytes: 4096,
        };
        assert!(parse_bounded(br#"{"x":1}"#, generous).is_ok());

        let too_shallow = ParseLimits {
            max_depth: 1,
            ..generous
        };
        assert_eq!(
            parse_bounded(br#"{"x":1}"#, too_shallow),
            Err(BoundedParseError::ResourceLimit)
        );

        let too_many_items = ParseLimits {
            max_collection_items: 0,
            ..generous
        };
        assert_eq!(
            parse_bounded(br#"{"x":1}"#, too_many_items),
            Err(BoundedParseError::ResourceLimit)
        );

        let too_many_string_bytes = ParseLimits {
            max_string_bytes: 0,
            ..generous
        };
        assert_eq!(
            parse_bounded(br#"{"x":1}"#, too_many_string_bytes),
            Err(BoundedParseError::ResourceLimit)
        );

        let exact_scalar_allocation = ParseLimits {
            max_depth: 1,
            max_nodes: 1,
            max_collection_items: 0,
            max_string_bytes: 0,
            max_allocation_bytes: size_of::<StrictJsonValue>(),
        };
        assert!(parse_bounded(b"1", exact_scalar_allocation).is_ok());
        assert_eq!(
            parse_bounded(
                b"1",
                ParseLimits {
                    max_allocation_bytes: size_of::<StrictJsonValue>() - 1,
                    ..exact_scalar_allocation
                }
            ),
            Err(BoundedParseError::ResourceLimit)
        );
    }
}
