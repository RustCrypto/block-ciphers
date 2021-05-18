//! AES block ciphers implementation using AES-NI instruction set.
//!
//! Ciphers functionality is accessed using `BlockCipher` trait from the
//! [`cipher`](https://docs.rs/cipher) crate.
//!
//! # CTR mode
//! In addition to core block cipher functionality this crate provides optimized
//! CTR mode implementation. This functionality requires additional `ssse3`
//! target feature and feature-gated behind `ctr` feature flag, which is enabled
//! by default.
//!
//! # Vulnerability
//! Lazy FP state restory vulnerability can allow local process to leak content
//! of the FPU register, in which round keys are stored. This vulnerability
//! can be mitigated at the operating system level by installing relevant
//! patches. (i.e. keep your OS updated!) More info:
//! - [Intel advisory](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00145.html)
//! - [Wikipedia](https://en.wikipedia.org/wiki/Lazy_FP_state_restore)
//!
//! # Related documents
//! - [Intel AES-NI whitepaper](https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf)
//! - [Use of the AES Instruction Set](https://www.cosic.esat.kuleuven.be/ecrypt/AESday/slides/Use_of_the_AES_Instruction_Set.pdf)

#[macro_use]
mod utils;

mod aes128;
mod aes192;
mod aes256;

#[cfg(feature = "ctr")]
mod ctr;

#[cfg(feature = "hazmat")]
pub(crate) mod hazmat;

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

pub use self::{aes128::Aes128, aes192::Aes192, aes256::Aes256};

#[cfg(feature = "ctr")]
pub use self::ctr::{Aes128Ctr, Aes192Ctr, Aes256Ctr};
