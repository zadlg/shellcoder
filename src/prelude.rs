//! Prelude imports for shellcoder.

#![allow(clippy::redundant_pub_crate)]

#[cfg(feature = "serde")]
pub(crate) use serde::{Deserialize, Serialize};

pub(crate) use crate::{error::Error, Op, Result};
