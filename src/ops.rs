//! All operations available for writing shellcodes.

use core::fmt;
#[cfg(feature = "std")]
use std::io;

use crate::prelude::*;

#[cfg(feature = "serde")]
pub trait WithOrWithoutSerde: Serialize + for<'de> Deserialize<'de> {}
#[cfg(feature = "serde")]
impl<T> WithOrWithoutSerde for T where T: Serialize + for<'de> Deserialize<'de> {}

#[cfg(not(feature = "serde"))]
pub trait WithOrWithoutSerde {}
#[cfg(not(feature = "serde"))]
impl<T> WithOrWithoutSerde for T {}

/// An operation that moves the cursor ahead by n bytes.
/// The gap will be filled by zeroes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Advance(usize);

impl Advance {
    /// Instantiates a new [`Advance`] to move the cursor ahead by n bytes.
    #[inline]
    #[must_use]
    pub const fn new(n: usize) -> Self {
        Self(n)
    }
}

impl Op for Advance {
    #[cfg(feature = "std")]
    #[inline]
    fn write_to_io(&self, stream: &mut dyn io::Write) -> Result<usize> {
        Fill::new(self.0, 0).write_to_io(stream)
    }

    #[inline]
    fn write_to(&self, out: impl AsMut<[u8]>) -> Result<usize> {
        Fill::new(self.0, 0).write_to(out)
    }
}

/// An operation that fills with a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Fill(usize, u8);

impl Fill {
    /// Instantiates a new [`Fill`].
    #[inline]
    #[must_use]
    pub const fn new(len: usize, chr: u8) -> Self {
        Self(len, chr)
    }
}

impl Op for Fill {
    #[cfg(feature = "std")]
    #[inline]
    fn write_to_io(&self, stream: &mut dyn io::Write) -> Result<usize> {
        use core::slice;
        let rchr = slice::from_ref(&self.1);
        for _ in 0..self.0 {
            stream.write_all(rchr)?;
        }
        Ok(self.0)
    }

    #[inline]
    fn write_to(&self, mut out: impl AsMut<[u8]>) -> Result<usize> {
        out.as_mut()
            .get_mut(..self.0)
            .ok_or_else(|| Error::buffer_too_small(self.0))?
            .fill(self.1);
        Ok(self.0)
    }
}

/// An integer that is encodable.
pub trait EncodableInteger:
    Copy + Clone + Sized + fmt::Debug + PartialEq + Eq + Send + Sync + WithOrWithoutSerde
{
    /// Returns the number of bytes needed to encode the integer.
    fn n(self) -> usize;

    /// Writes in big endian.
    ///
    /// # Errors
    ///
    /// An I/O error may be raised here.
    #[cfg(feature = "std")]
    fn write_be_io(self, stream: &mut dyn io::Write) -> Result<()>;

    /// Writes in little endian.
    ///
    /// # Errors
    ///
    /// An I/O error may be raised here.
    #[cfg(feature = "std")]
    fn write_le_io(self, stream: &mut dyn io::Write) -> Result<()>;

    /// Writes in big endian.
    ///
    /// # Errors
    ///
    /// [`Error::OutputBufferTooSmall`] is raised if `out` cannot contain the encoded
    /// integer.
    fn write_be(self, out: impl AsMut<[u8]>) -> Result<()>;

    /// Writes in little endian.
    ///
    /// # Errors
    ///
    /// [`Error::OutputBufferTooSmall`] is raised if `out` cannot contain the encoded
    /// integer.
    fn write_le(self, out: impl AsMut<[u8]>) -> Result<()>;
}

/// Implements [`EncodableInteger`] for a given type.
macro_rules! impl_encodable_integer_for {
    ($i:ident) => {
        impl EncodableInteger for $i {
            #[inline]
            #[must_use]
            fn n(self) -> usize {
                ($i::BITS >> 3).try_into().expect("unreachable")
            }

            #[cfg(feature = "std")]
            #[inline]
            fn write_be_io(self, stream: &mut dyn io::Write) -> Result<()> {
                stream.write_all(&self.to_be_bytes()).map_err(Error::from)
            }

            #[cfg(feature = "std")]
            #[inline]
            fn write_le_io(self, stream: &mut dyn io::Write) -> Result<()> {
                stream.write_all(&self.to_le_bytes()).map_err(Error::from)
            }

            #[inline]
            fn write_be(self, mut out: impl AsMut<[u8]>) -> Result<()> {
                let n = self.n();
                let out = out
                    .as_mut()
                    .get_mut(..n)
                    .ok_or(Error::buffer_too_small(n))?;
                // SAFETY:
                //
                // Length of `out` has been checked previously.
                unsafe {
                    out.as_mut_ptr().copy_from(self.to_be_bytes().as_ptr(), n);
                }
                Ok(())
            }

            #[inline]
            fn write_le(self, mut out: impl AsMut<[u8]>) -> Result<()> {
                let n = self.n();
                let out = out
                    .as_mut()
                    .get_mut(..n)
                    .ok_or(Error::buffer_too_small(n))?;
                // SAFETY:
                //
                // Length of `out` has been checked previously.
                unsafe {
                    out.as_mut_ptr().copy_from(self.to_le_bytes().as_ptr(), n);
                }
                Ok(())
            }
        }
    };
}

impl_encodable_integer_for!(u8);
impl_encodable_integer_for!(u16);
impl_encodable_integer_for!(u32);
impl_encodable_integer_for!(u64);

/// An operation that writes an integer.
/// The cursor will be moved ahead by n bytes, n depending on the integer's
/// encoded size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteInteger<I>
where
    I: EncodableInteger + WithOrWithoutSerde,
{
    /// The integer's value, to encode in big-endian.
    BigEndian(I),

    /// The integer's value, to encode in little-endian.
    LittleEndian(I),
}

impl<I> WriteInteger<I>
where
    I: EncodableInteger,
{
    /// Instantiates a new [`WriteInteger`] to write a big-endian encoded integer.
    #[inline]
    #[must_use]
    pub const fn new_be(value: I) -> Self {
        Self::BigEndian(value)
    }

    /// Instantiates a new [`WriteInteger`] to write a little-endian encoded integer.
    #[inline]
    #[must_use]
    pub const fn new_le(value: I) -> Self {
        Self::LittleEndian(value)
    }
}

impl<I> Op for WriteInteger<I>
where
    I: EncodableInteger,
{
    #[cfg(feature = "std")]
    #[inline]
    fn write_to_io(&self, stream: &mut dyn io::Write) -> Result<usize> {
        match self {
            Self::BigEndian(n) => n.write_be_io(stream).map(|()| n.n()),
            Self::LittleEndian(n) => n.write_le_io(stream).map(|()| n.n()),
        }
    }

    #[inline]
    fn write_to(&self, out: impl AsMut<[u8]>) -> Result<usize> {
        match self {
            Self::BigEndian(n) => n.write_be(out).map(|()| n.n()),
            Self::LittleEndian(n) => n.write_le(out).map(|()| n.n()),
        }
    }
}

/// An operation that writes a buffer.
/// The cursor will be moved ahead by the length in bytes of the given buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WriteBuffer<'buf>(&'buf [u8]);

impl<'buf> WriteBuffer<'buf> {
    /// Instantiates a new [`WriteBuffer`].
    #[inline]
    #[must_use]
    pub fn new(buffer: &'buf (impl AsRef<[u8]> + 'buf)) -> Self {
        Self(buffer.as_ref())
    }
}

impl Op for WriteBuffer<'_> {
    #[cfg(feature = "std")]
    #[inline]
    fn write_to_io(&self, stream: &mut dyn io::Write) -> Result<usize> {
        stream
            .write_all(self.0)
            .map(|()| self.0.len())
            .map_err(Error::from)
    }

    #[inline]
    fn write_to(&self, mut out: impl AsMut<[u8]>) -> Result<usize> {
        let n = self.0.len();
        let out_slice = out
            .as_mut()
            .get_mut(..n)
            .ok_or_else(|| Error::buffer_too_small(n))?;
        // SAFETY:
        //
        // Length of `out` has been checked previously.
        unsafe {
            out_slice.as_mut_ptr().copy_from(self.0.as_ptr(), n);
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    mod advance {
        use crate::ops::Advance;

        use crate::prelude::*;

        #[cfg(feature = "std")]
        #[test]
        fn test_io() -> Result<()> {
            {
                let mut stream = Vec::new();
                let advance = Advance::new(0);
                assert_eq!(advance.write_to_io(&mut stream).unwrap(), 0);
                assert!(stream.is_empty());
            }
            {
                let mut stream = Vec::new();
                let advance = Advance::new(42);
                assert_eq!(advance.write_to_io(&mut stream).unwrap(), 42);
                assert_eq!(stream.len(), 42);
                assert_eq!(
                    stream.as_slice(),
                    &[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]
                );
            }
            {
                let mut stream = vec![42u8; 2];
                let advance = Advance::new(42);
                assert_eq!(advance.write_to_io(&mut stream).unwrap(), 42);
                assert_eq!(stream.len(), 44);
                assert_eq!(
                    stream.as_slice(),
                    &[
                        42, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]
                );
            }
            Ok(())
        }

        #[cfg(feature = "std")]
        #[test]
        fn test() -> Result<()> {
            {
                let mut stream = vec![0u8; 10];
                let advance = Advance::new(10);
                assert_eq!(advance.write_to(&mut stream).unwrap(), 10);
                assert_eq!(stream.len(), 10);
                assert_eq!(stream.as_slice(), &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0,]);
            }
            {
                let mut stream = vec![0u8; 9];
                let advance = Advance::new(10);
                let err = advance.write_to(&mut stream).unwrap_err();
                let io_err = err.io().unwrap();
                assert_eq!(io_err.kind(), std::io::ErrorKind::WriteZero);
                assert_eq!(stream.len(), 9);
                assert_eq!(stream.as_slice(), &[0, 0, 0, 0, 0, 0, 0, 0, 0,]);
            }
            Ok(())
        }
    }

    mod fill {
        use crate::ops::Fill;

        use crate::prelude::*;

        #[cfg(feature = "std")]
        #[test]
        fn test_io() -> Result<()> {
            {
                let mut stream = Vec::new();
                let fill = Fill::new(0, 0x41);
                assert_eq!(fill.write_to_io(&mut stream).unwrap(), 0);
                assert_eq!(stream.len(), 0);
            }
            {
                let mut stream = Vec::new();
                let fill = Fill::new(42, 0x41);
                assert_eq!(fill.write_to_io(&mut stream).unwrap(), 42);
                assert_eq!(stream.len(), 42);
                assert_eq!(
                    String::from_utf8(stream).as_deref(),
                    Ok("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                );
            }
            {
                let mut stream = vec![0x42u8; 4];
                let fill = Fill::new(42, 0x41);
                assert_eq!(fill.write_to_io(&mut stream).unwrap(), 42);
                assert_eq!(stream.len(), 46);
                assert_eq!(
                    String::from_utf8(stream).as_deref(),
                    Ok("BBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                );
            }
            Ok(())
        }

        #[cfg(feature = "std")]
        #[test]
        fn test() -> Result<()> {
            {
                let mut stream = vec![0u8; 10];
                let fill = Fill::new(10, 0x41);
                assert_eq!(fill.write_to(&mut stream).unwrap(), 10);
                assert_eq!(stream.len(), 10);
                assert_eq!(String::from_utf8(stream).as_deref(), Ok("AAAAAAAAAA"));
            }

            {
                let mut stream = vec![0u8; 9];
                let fill = Fill::new(10, 0x41);
                let err = fill.write_to(&mut stream).unwrap_err();
                let io_err = err.io().unwrap();
                assert_eq!(io_err.kind(), std::io::ErrorKind::WriteZero);
                assert_eq!(stream.len(), 9);
                assert_eq!(
                    stream.as_slice(),
                    &[0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,]
                );
            }
            Ok(())
        }
    }

    mod integers {
        use crate::ops::{EncodableInteger, WriteInteger};

        use crate::prelude::*;

        #[test]
        fn test_constructors() -> Result<()> {
            assert_eq!(WriteInteger::new_be(1u8), WriteInteger::BigEndian(1u8));
            assert_eq!(<_ as EncodableInteger>::n(1u8), 1);
            assert_eq!(WriteInteger::new_le(1u8), WriteInteger::LittleEndian(1u8));
            assert_eq!(WriteInteger::new_be(1u16), WriteInteger::BigEndian(1u16));
            assert_eq!(<_ as EncodableInteger>::n(1u16), 2);
            assert_eq!(WriteInteger::new_le(1u16), WriteInteger::LittleEndian(1u16));
            assert_eq!(WriteInteger::new_be(1u32), WriteInteger::BigEndian(1u32));
            assert_eq!(<_ as EncodableInteger>::n(1u32), 4);
            assert_eq!(WriteInteger::new_le(1u32), WriteInteger::LittleEndian(1u32));
            assert_eq!(WriteInteger::new_be(1u64), WriteInteger::BigEndian(1u64));
            assert_eq!(<_ as EncodableInteger>::n(1u64), 8);
            assert_eq!(WriteInteger::new_le(1u64), WriteInteger::LittleEndian(1u64));
            Ok(())
        }

        #[cfg(feature = "std")]
        #[test]
        fn test_encodable_integer_io() -> Result<()> {
            {
                let mut stream = Vec::new();
                assert_eq!(
                    WriteInteger::new_be(1u8).write_to_io(&mut stream).unwrap(),
                    1
                );
                assert_eq!(stream.len(), 1);
                assert_eq!(
                    WriteInteger::new_le(2u8).write_to_io(&mut stream).unwrap(),
                    1
                );
                assert_eq!(stream.len(), 2);
                assert_eq!(stream.as_slice(), &[1, 2]);
            }

            {
                let mut stream = vec![2u8; 1];
                assert_eq!(
                    WriteInteger::new_be(1u8).write_to_io(&mut stream).unwrap(),
                    1
                );
                assert_eq!(stream.len(), 2);
                assert_eq!(stream.as_slice(), &[2u8, 1u8]);
            }

            {
                let mut stream = Vec::new();
                assert_eq!(
                    WriteInteger::new_be(0xdeadu16)
                        .write_to_io(&mut stream)
                        .unwrap(),
                    2
                );
                assert_eq!(stream.len(), 2);
                assert_eq!(stream.as_slice(), &[0xde, 0xad]);
            }

            {
                let mut stream = Vec::new();
                assert_eq!(
                    WriteInteger::new_le(0xdeadu16)
                        .write_to_io(&mut stream)
                        .unwrap(),
                    2
                );
                assert_eq!(stream.len(), 2);
                assert_eq!(stream.as_slice(), &[0xad, 0xde]);
            }

            {
                let mut stream = Vec::new();
                assert_eq!(
                    WriteInteger::new_be(0xdeadbeefu32)
                        .write_to_io(&mut stream)
                        .unwrap(),
                    4
                );
                assert_eq!(stream.len(), 4);
                assert_eq!(stream.as_slice(), &[0xde, 0xad, 0xbe, 0xef]);
            }

            {
                let mut stream = Vec::new();
                assert_eq!(
                    WriteInteger::new_le(0xdeadbeefu32)
                        .write_to_io(&mut stream)
                        .unwrap(),
                    4
                );
                assert_eq!(stream.len(), 4);
                assert_eq!(stream.as_slice(), &[0xef, 0xbe, 0xad, 0xde]);
            }

            {
                let mut stream = Vec::new();
                assert_eq!(
                    WriteInteger::new_be(0xdeadbeefcafebabeu64)
                        .write_to_io(&mut stream)
                        .unwrap(),
                    8
                );
                assert_eq!(stream.len(), 8);
                assert_eq!(
                    stream.as_slice(),
                    &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]
                );
            }

            {
                let mut stream = Vec::new();
                assert_eq!(
                    WriteInteger::new_le(0xdeadbeefcafebabeu64)
                        .write_to_io(&mut stream)
                        .unwrap(),
                    8
                );
                assert_eq!(stream.len(), 8);
                assert_eq!(
                    stream.as_slice(),
                    &[0xbe, 0xba, 0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde]
                );
            }
            Ok(())
        }
    }
}
