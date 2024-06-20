//! Errors that may happen in this crate.

use core::fmt;
#[cfg(feature = "std")]
use std::io;

/// Errors that may happen in this crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// I/O error.
    #[cfg(feature = "std")]
    Io(io::Error),

    /// Output buffer is too small.
    /// Value corresponds to the minimum size it is expected.
    OutputBufferTooSmall(usize),

    /// Integer overflow.
    IntegerOverflow,
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Self::Io(error) => write!(fmt, "I/O error: {error}"),
            Self::OutputBufferTooSmall(len) => write!(
                fmt,
                "output buffer error: too small (requires at least {len:#x} byte(s)"
            ),
            Self::IntegerOverflow => write!(fmt, "integer overflow"),
        }
    }
}

#[cfg(feature = "std")]
impl From<io::Error> for Error {
    #[inline]
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Error {
    /// Instantiates an [`Error::OutputBufferTooSmall`] variant.
    pub(super) const fn buffer_too_small(n: usize) -> Self {
        Self::OutputBufferTooSmall(n)
    }

    /// Returns the underlying I/O error if suitable.
    #[cfg(feature = "std")]
    #[must_use]
    #[inline]
    pub const fn io(&self) -> Option<&io::Error> {
        if let Self::Io(err) = self {
            Some(err)
        } else {
            None
        }
    }
}
