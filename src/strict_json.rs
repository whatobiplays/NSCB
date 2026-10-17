//! Bounded JSON parsing with duplicate-key rejection.
//!
//! The standard serde JSON model accepts duplicate object keys and silently
//! keeps one of the values. Input lists, Split manifests, and local trust
//! receipts all rely on object keys having exactly one meaning, so they use
//! this parser and then project the generic value into their own schema.

use serde::Deserialize;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;
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

/// Parses one JSON document and rejects duplicate object keys at every depth.
pub(crate) fn parse(bytes: &[u8]) -> Result<StrictJsonValue, ()> {
    serde_json::from_slice(bytes).map_err(|_| ())
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
        deserializer.deserialize_any(StrictJsonValueVisitor)
    }
}

struct StrictJsonValueVisitor;

impl<'de> Visitor<'de> for StrictJsonValueVisitor {
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

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJsonValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = Vec::new();
        let mut keys = HashSet::new();
        while let Some((key, value)) = map.next_entry::<String, StrictJsonValue>()? {
            let normalized = key.nfc().collect::<String>();
            if !keys.insert(normalized) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            fields.push((key, value));
        }
        Ok(StrictJsonValue::Object(fields))
    }
}

#[cfg(test)]
mod tests {
    use super::{StrictJsonValue, depth, parse, required_field};

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
}
