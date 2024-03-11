use super::{RoundKey, RoundKeys};

pub(super) mod aes128;
// NOTE: AES-192 is only implemented if scalar-crypto is enabled.
#[cfg(all(
    target_arch = "riscv64",
    target_feature = "zknd",
    target_feature = "zkne"
))]
pub(super) mod aes192;
pub(super) mod aes256;
