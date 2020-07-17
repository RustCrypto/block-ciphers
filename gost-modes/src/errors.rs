use core::fmt;

/// Error indicating that an invalid value was used for number of block bytes
/// used for message processing.
///
/// The alue should be between greater than 0 and less or equal to cipher block size.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct InvalidS;

impl fmt::Display for InvalidS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("InvalidS")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidS {}
