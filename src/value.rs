//! The deterministic `tag ‖ len ‖ bytes` slot-value encoding.
//!
//! Slot values are encoded by hand (NOT serde/CBOR) so a Rust, a JS, and a wasm writer produce the
//! exact same bytes for the same value — which is what makes leaf hashes, roots, and proofs
//! reproducible across implementations. The encoding is three fields:
//!
//! ```text
//! ┌─────────┬──────────────────┬───────────────┐
//! │ tag: u8 │ len: u32 (be)    │ payload: len  │
//! └─────────┴──────────────────┴───────────────┘
//! ```
//!
//! The `tag` names the value's type, `len` is the big-endian byte length of `payload`, and
//! `payload` is the raw value. Fixed-width numeric tags additionally pin `len` to their width.

use crate::error::{Error, Result};

/// The size of the fixed header: one tag byte plus a 4-byte big-endian length.
const HEADER_LEN: usize = 1 + 4;

/// The type tag that leads every encoded value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ValueTag {
    /// UTF-8 text.
    Utf8 = 0x01,
    /// Opaque byte string (e.g. a 32-byte public key or peer id).
    Bytes = 0x02,
    /// Unsigned 16-bit big-endian integer (payload width 2).
    U16 = 0x03,
    /// Unsigned 32-bit big-endian integer (payload width 4).
    U32 = 0x04,
    /// Unsigned 64-bit big-endian integer (payload width 8).
    U64 = 0x05,
}

impl ValueTag {
    /// Parses a tag byte, rejecting bytes this version does not define.
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(ValueTag::Utf8),
            0x02 => Ok(ValueTag::Bytes),
            0x03 => Ok(ValueTag::U16),
            0x04 => Ok(ValueTag::U32),
            0x05 => Ok(ValueTag::U64),
            other => Err(Error::UnknownTag(other)),
        }
    }

    /// The mandatory payload width for a fixed-width numeric tag, or `None` for variable-length tags.
    fn fixed_width(self) -> Option<usize> {
        match self {
            ValueTag::U16 => Some(2),
            ValueTag::U32 => Some(4),
            ValueTag::U64 => Some(8),
            ValueTag::Utf8 | ValueTag::Bytes => None,
        }
    }
}

/// A decoded slot value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// UTF-8 text.
    Utf8(String),
    /// Opaque bytes.
    Bytes(Vec<u8>),
    /// A `u16`.
    U16(u16),
    /// A `u32`.
    U32(u32),
    /// A `u64`.
    U64(u64),
}

impl Value {
    /// Encodes the value into its canonical `tag ‖ len ‖ bytes` form.
    pub fn encode(&self) -> Vec<u8> {
        let (tag, payload): (ValueTag, Vec<u8>) = match self {
            Value::Utf8(s) => (ValueTag::Utf8, s.as_bytes().to_vec()),
            Value::Bytes(b) => (ValueTag::Bytes, b.clone()),
            Value::U16(n) => (ValueTag::U16, n.to_be_bytes().to_vec()),
            Value::U32(n) => (ValueTag::U32, n.to_be_bytes().to_vec()),
            Value::U64(n) => (ValueTag::U64, n.to_be_bytes().to_vec()),
        };
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.push(tag as u8);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Decodes a canonical value blob, validating the tag, the length prefix, and any fixed width.
    pub fn decode(blob: &[u8]) -> Result<Self> {
        if blob.len() < HEADER_LEN {
            return Err(Error::TruncatedValue("header shorter than 5 bytes"));
        }
        let tag = ValueTag::from_byte(blob[0])?;
        let declared = u32::from_be_bytes([blob[1], blob[2], blob[3], blob[4]]) as usize;
        let payload = &blob[HEADER_LEN..];
        if payload.len() != declared {
            return Err(Error::LengthMismatch {
                declared,
                actual: payload.len(),
            });
        }
        if let Some(width) = tag.fixed_width() {
            if payload.len() != width {
                return Err(Error::WrongWidth {
                    tag: blob[0],
                    expected: width,
                    actual: payload.len(),
                });
            }
        }
        Ok(match tag {
            ValueTag::Utf8 => Value::Utf8(
                String::from_utf8(payload.to_vec())
                    .map_err(|_| Error::TruncatedValue("utf8 payload is not valid UTF-8"))?,
            ),
            ValueTag::Bytes => Value::Bytes(payload.to_vec()),
            ValueTag::U16 => Value::U16(u16::from_be_bytes([payload[0], payload[1]])),
            ValueTag::U32 => Value::U32(u32::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ])),
            ValueTag::U64 => Value::U64(u64::from_be_bytes(payload.try_into().expect("width 8"))),
        })
    }
}
