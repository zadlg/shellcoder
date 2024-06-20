//! Implementation of [`crate::Shellcoder`] using I/O.

use core::borrow::Borrow;
use core::fmt;
use std::io;

use crate::prelude::*;

/// A shellcoder backed by an IO object.
pub struct Shellcoder<'io>(&'io mut dyn io::Write);

impl fmt::Debug for Shellcoder<'_> {
    #[inline]
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "io::Shellcoder")
    }
}

impl<'io> Shellcoder<'io> {
    /// Instantiates a new I/O backed shellcoder.
    #[inline]
    #[must_use]
    pub fn new(stream: &'io mut impl io::Write) -> Self {
        Self(stream)
    }
}

impl crate::Shellcoder for Shellcoder<'_> {
    /// Pushes an operation.
    #[inline]
    fn add<O>(&mut self, op: impl Borrow<O>) -> Result<&mut Self>
    where
        O: Op,
    {
        op.borrow()
            .write_to_io(self.0)
            .map_err(Error::from)
            .map(|_| self)
    }
}
