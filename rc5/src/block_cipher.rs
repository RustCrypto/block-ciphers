use cipher::consts::{U12, U16};

use crate::core::{BlockSize, ExpandedKeyTable, RC5};
use cipher::{impl_simple_block_encdec, AlgorithmName, KeyInit};
use cipher::{inout::InOut, Block, BlockCipher, KeySizeUser};

macro_rules! impl_rc5 {
    (cipher: $cipher:ident, name: $name:expr, word: $word:ident, rounds: $rounds:ident, key_bytes: $key_bytes:ident) => {
        pub struct $cipher {
            key_table: ExpandedKeyTable<$word, $rounds>,
        }

        impl RC5<$word, $rounds, $key_bytes> for $cipher {}

        impl $cipher {
            fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
                Self::encrypt(block, &self.key_table);
            }

            fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
                Self::decrypt(block, &self.key_table);
            }
        }

        impl BlockCipher for $cipher {}

        impl KeySizeUser for $cipher {
            type KeySize = $key_bytes;
        }

        impl KeyInit for $cipher {
            fn new(key: &cipher::Key<Self>) -> Self {
                Self {
                    key_table: Self::substitute_key(key),
                }
            }
        }

        impl AlgorithmName for $cipher {
            fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl_simple_block_encdec!(
            $cipher, BlockSize<$word>, cipher, block,
            encrypt: {
                cipher.encrypt_block(block);
            }
            decrypt: {
                cipher.decrypt_block(block);
            }
        );

        #[cfg(feature = "zeroize")]
        impl cipher::zeroize::ZeroizeOnDrop for $cipher {}

        #[cfg(feature = "zeroize")]
        impl Drop for $cipher {
            fn drop(&mut self) {
                cipher::zeroize::Zeroize::zeroize(&mut *self.key_table)
            }
        }
    };
}

impl_rc5!(cipher: RC5_32_12_16, name: "RC5 - 32/12/16", word: u32, rounds: U12, key_bytes: U16);
impl_rc5!(cipher: RC5_32_16_16, name: "RC5 - 32/16/16", word: u32, rounds: U16, key_bytes: U16);
