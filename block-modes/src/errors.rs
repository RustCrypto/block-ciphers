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
    fn description(&self) -> &str {
        "block mode error"
    }
}

impl fmt::Display for InvalidKeyIvLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InvalidKeyIvLength")
    }
}

#[cfg(feature = "std")]
impl error::Error for InvalidKeyIvLength {
    fn description(&self) -> &str {
        "invalid key or IV length during block cipher mode initialization"
    }
}
