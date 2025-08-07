//! AES block ciphers implementation using AES-NI instruction set.
//!
//! Ciphers functionality is accessed using `BlockCipher` trait from the
//! [`cipher`](https://docs.rs/cipher) crate.
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

pub(super) mod encdec;
pub(super) mod expand;
#[cfg(test)]
mod test_expand;

#[cfg(feature = "hazmat")]
pub(crate) mod hazmat;
