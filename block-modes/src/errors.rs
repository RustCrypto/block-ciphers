use core::fmt;
#[cfg(feature = "std")]
use std::error;

/// Block mode error.
#[derive(Clone, Copy, Debug)]
pub struct BlockModeError;

/// Invalid key or IV length error.
#[derive(Clone, Copy, Debug)]
pub struct InvalidKeyIvLength;

impl fmt::Display for BlockModeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlockModeError")
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockModeError {
    // workaround for failing travis-ci tests with rust v1.22
    // should be removed, once rust v1.22 is no longer supported:
    // https://github.com/rust-lang/rust/blob/4c58535d09d1261d21569df0036b974811544256/
    // src/libstd/error.rs#L69
    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}

impl fmt::Display for InvalidKeyIvLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid key or IV length, during block cipher mode initialization")
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidKeyIvLength {
    // workaround for failing travis-ci tests with rust v1.22
    // should be removed, once rust v1.22 is no longer supported:
    // https://github.com/rust-lang/rust/blob/4c58535d09d1261d21569df0036b974811544256/
    // src/libstd/error.rs#L69
    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}
