//! Implementation of [`crate::Shellcoder`] using a static buffer.

use core::borrow::Borrow;
use core::mem;

use crate::prelude::*;

/// A shellcoder backed by a static buffer.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Shellcoder<'buf>(&'buf mut [u8], usize);

impl<'buf> Shellcoder<'buf> {
    /// Instantiates a new shellcoder.
    #[inline]
    #[must_use]
    pub fn new(buffer: &'buf mut [u8]) -> Self {
        Self(buffer, 0)
    }

    /// Returns the shellcode.
    #[inline]
    #[must_use]
    pub fn get(&self) -> &'buf [u8] {
        // SAFETY:
        //
        // We are sure that [`self.1`] is not going to overflow the buffer,
        // cause we test it in [`Shellcoder::add`].
        let effective = unsafe { self.0.get_unchecked(..self.1) };

        // SAFETY:
        //
        // [`std::slice::get`] and [`std::slice::get_mut`] does not propagate
        // the right lifetime.
        // In this bit of code, we are sure that lifetimes match.
        unsafe { mem::transmute(effective) }
    }
}

impl crate::Shellcoder for Shellcoder<'_> {
    #[inline]
    fn add<O>(&mut self, op: impl Borrow<O>) -> Result<&mut Self>
    where
        O: Op,
    {
        let n = op.borrow().write_to(&mut self.0)?;
        self.0 =
        // SAFETY:
        //
        // [`std::slice::get`] and [`std::slice::get_mut`] does not propagate
        // the right lifetime.
        // In this bit of code, we are sure that lifetimes match.
            unsafe { mem::transmute(self.0.get_mut(n..).ok_or_else(|| Error::buffer_too_small(n))?) };
        self.1 = self.1.checked_add(n).ok_or(Error::IntegerOverflow)?;
        Ok(self)
    }
}
