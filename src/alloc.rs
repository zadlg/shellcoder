//! Implementation of [`crate::Shellcoder`] using a dynamic buffer.

use core::borrow::Borrow;

use crate::prelude::*;

/// A shellcoder backed by a dynamic buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Shellcoder {
    /// Buffer containing the shellcode.
    stream: Vec<u8>,

    /// A maximum length in bytes.
    max_len: Option<usize>,
}

impl Shellcoder {
    /// Instantiates a new shellcode.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Instantiates a new shellcode with a maximum length in bytes.
    #[inline]
    #[must_use]
    pub fn new_with_max_len(max_len: usize) -> Self {
        Self {
            max_len: Some(max_len),
            ..Self::default()
        }
    }

    /// Consumes the [`Shellcoder`] by returning the underlying buffer.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.stream.as_ref()
    }
}

impl crate::Shellcoder for Shellcoder {
    #[inline]
    fn add<O>(&mut self, op: impl Borrow<O>) -> Result<&mut Self>
    where
        O: Op,
    {
        op.borrow()
            .write_to_io(&mut self.stream)
            .map_err(Error::from)
            .and_then(|_| {
                if self.max_len.map(|max_len| max_len < self.stream.len()) == Some(true) {
                    Err(Error::buffer_too_small(self.stream.len()))
                } else {
                    Ok(self)
                }
            })
    }
}
