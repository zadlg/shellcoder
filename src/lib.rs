//! Shellcoder is a thin library for writing shellcode payloads.

#![cfg_attr(not(feature = "std"), no_std)]

use core::borrow::Borrow;
use core::fmt;
use core::result::Result as CoreResult;
#[cfg(feature = "std")]
use std::io as std_io;

#[allow(unused_imports)]
use prelude::*;

/// A specialized [`core::result::Result`] type for this crate.
pub type Result<T> = CoreResult<T, Error>;

#[cfg(feature = "std")]
pub mod alloc;
pub mod error;
#[cfg(feature = "std")]
pub mod io;
pub mod ops;
mod prelude;
pub mod r#static;

/// Generic interface for operations.
///
/// This trait describes a generic interface for operations.
/// An operation is a function that outputs some data for building a payload.
///
/// Popular operations are implemented in this crates, such as [`ops::Fill`],
/// [`ops::WriteInteger`] or [`ops::WriteBuffer`].
pub trait Op: fmt::Debug {
    #[cfg(feature = "std")]
    /// Writes the operation to the stream.
    ///
    /// # Errors
    ///
    /// [`error::Error::Io`]: an I/O error occurred.
    ///
    /// # Examples
    ///
    /// Writes an operation to a [`File`](std::fs::File).
    ///
    /// ```rust
    /// use std::fs::File;
    ///
    /// use shellcoder::ops::Advance;
    /// # use shellcoder::Result;
    /// use shellcoder::Op as _;
    ///
    /// # pub fn main() -> Result<()> {
    /// let mut file = File::options()
    ///     .write(true)
    ///     .truncate(true)
    ///     .create(true)
    ///     .open("op.bin")?;
    ///
    /// Advance::new(42)
    ///     .write_to_io(&mut file)?;
    /// # Ok(())
    /// }
    /// ```
    ///
    /// Writes an operation to a vector.
    ///
    /// ```rust
    /// use shellcoder::ops::Fill;
    /// # use shellcoder::Result;
    /// use shellcoder::Op as _;
    ///
    /// # pub fn main() -> Result<()> {
    /// let mut buffer = vec![];
    /// Fill::new(42, b'A')
    ///     .write_to_io(&mut buffer)?;
    /// # Ok(())
    /// }
    /// ```
    ///
    ///
    fn write_to_io(&self, stream: &mut dyn std_io::Write) -> Result<usize>;

    /// Writes the operation to a buffer.
    ///
    /// # Errors
    ///
    /// [`error::Error::OutputBufferTooSmall`]: the provided output buffer is too small
    /// to contain the result of the operation.
    ///
    /// # Examples
    ///
    /// Writes an operation to a buffer.
    ///
    /// ```rust
    /// use shellcoder::ops::Fill;
    /// # use shellcoder::Result;
    /// use shellcoder::Op as _;
    ///
    /// # pub fn main() -> Result<()> {
    /// let mut buffer = [0u8; 10];
    /// Fill::new(10, b'A')
    ///     .write_to(&mut buffer)?;
    /// assert_eq!(&buffer, b"AAAAAAAAAA");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Writes to a buffer that is too small to contain the output of the
    /// operation.
    ///
    /// ```rust
    /// use shellcoder::ops::WriteInteger;
    /// # use shellcoder::Result;
    /// # use shellcoder::error::Error;
    /// use shellcoder::Op as _;
    ///
    /// # pub fn main() -> Result<()> {
    /// let mut buffer = [0u8; 3];
    /// let error = WriteInteger::new_be(0xdeadbeefu32)
    ///     .write_to(&mut buffer)
    ///     .unwrap_err();
    /// assert!(matches!(error, Error::OutputBufferTooSmall(4)));
    /// # Ok(())
    /// # }
    /// ```
    fn write_to(&self, out: impl AsMut<[u8]>) -> Result<usize>;
}

/// Generic interface for shellcoders.
///
/// This is the generic interface for writing shellcodes.
///
/// # Examples
///
/// Writes a simple shellcode that exposes two addresses 8 bytes apart:
///
/// ```ignore
/// use shellcoder::{Op as _, Shellcoder as _};
/// # #[cfg(feature = "std")]
/// use shellcoder::alloc::Shellcoder;
///
/// use shellcoder::ops;
///
/// # use shellcoder::Result;
/// # #[cfg(feature = "std")]
/// # pub fn main() -> Result<()> {
/// let mut shellcoder = Shellcoder::new();
/// let shellcode = shellcoder
///     .int_le(0x100000fbau64)?
///     .advance(8)?
///     .int_le(0x10000fcdeu64)?
///     .as_bytes();
/// assert_eq!(shellcode, &[
///         0xba, 0x0f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
///         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///         0xde, 0xfc, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
/// # Ok(())
/// # }
/// ```
///
/// Writes a shellcode that copies another buffer, with doing no dynamic
/// allocation.
///
/// ```ignore
/// use shellcoder::{Op as _, Shellcoder as _};
/// # #[cfg(feature = "std")]
/// use shellcoder::r#static::Shellcoder;
///
/// use shellcoder::ops;
///
/// fn get_buffer() -> &'static [u8] {
///     b"pwnd"
/// }
///
/// # use shellcoder::Result;
/// # #[cfg(feature = "std")]
/// # pub fn main() -> Result<()> {
/// let some_payload: &[u8] = get_buffer();
///
/// let mut scratch_buffer = [0u8; 42];
///
/// let shellcode = Shellcoder::new(&mut scratch_buffer)
///     .push_buffer(some_payload)?
///     .get();
/// assert_eq!(&shellcode[..4], b"pwnd");
/// # Ok(())
/// # }
/// ```
pub trait Shellcoder: fmt::Debug {
    /// Pushes an operation, and returns the number of bytes that have been
    /// written.
    ///
    /// # Errors
    ///
    ///  - [`error::Error::OutputBufferTooSmall`]: the provided output buffer is too small
    ///    to contain the result of the operation.
    ///  - [`Error:Io`]: an I/O error occurred.
    fn add<O>(&mut self, op: impl Borrow<O>) -> Result<&mut Self>
    where
        O: Op;

    /// Advances the cursor by n bytes, filling gaps with zeroes.
    ///
    /// # Errors
    ///
    ///  - [`error::Error::OutputBufferTooSmall`]: the provided output buffer is too small
    ///    to contain the result of the operation.
    ///  - [`Error:Io`]: an I/O error occurred.
    #[inline]
    fn advance(&mut self, n: usize) -> Result<&mut Self> {
        self.add(ops::Advance::new(n))
    }

    /// Fills with a certain number of bytes.
    ///
    /// # Errors
    ///
    ///  - [`error::Error::OutputBufferTooSmall`]: the provided output buffer is too small
    ///    to contain the result of the operation.
    ///  - [`Error:Io`]: an I/O error occurred.
    #[inline]
    fn fill(&mut self, len: usize, chr: u8) -> Result<&mut Self> {
        self.add(ops::Fill::new(len, chr))
    }

    /// Pushes an integer in big endian.
    ///
    /// # Errors
    ///
    ///  - [`error::Error::OutputBufferTooSmall`]: the provided output buffer is too small
    ///    to contain the result of the operation.
    ///  - [`Error:Io`]: an I/O error occurred.
    #[inline]
    fn int_be<I>(&mut self, i: I) -> Result<&mut Self>
    where
        I: ops::EncodableInteger,
    {
        self.add(ops::WriteInteger::<I>::new_be(i))
    }

    /// Pushes an integer in little endian.
    ///
    /// # Errors
    ///
    ///  - [`error::Error::OutputBufferTooSmall`]: the provided output buffer is too small
    ///    to contain the result of the operation.
    ///  - [`Error:Io`]: an I/O error occurred.
    #[inline]
    fn int_le<I>(&mut self, i: I) -> Result<&mut Self>
    where
        I: ops::EncodableInteger,
    {
        self.add(ops::WriteInteger::<I>::new_le(i))
    }

    /// Pushes a buffer.
    ///
    /// # Errors
    ///
    ///  - [`error::Error::OutputBufferTooSmall`]: the provided output buffer is too small
    ///    to contain the result of the operation.
    ///  - [`error::Error:Io`]: an I/O error occurred.
    #[inline]
    fn push_buffer(&mut self, buffer: impl AsRef<[u8]>) -> Result<&mut Self> {
        self.add(ops::WriteBuffer::new(&buffer))
    }
}
