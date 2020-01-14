
mod sm4;
mod consts;

use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array;

pub use crate::sm4::Sm4;