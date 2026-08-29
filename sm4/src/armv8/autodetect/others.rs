//! On targets other than Linux/Android the SM4 crypto extensions cannot be
//! detected at runtime, so the NEON backend is used unconditionally.
pub use crate::armv8::neon::Sm4;
