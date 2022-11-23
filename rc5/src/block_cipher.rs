use cipher::consts::{U16, U20, U8};

use crate::core::{ExpandedKeyTable, RC5};
use cipher::{impl_simple_block_encdec, AlgorithmName, KeyInit};
use cipher::{inout::InOut, Block, BlockCipher, KeySizeUser};

pub struct RC5_32_20_16 {
    key_table: ExpandedKeyTable<u32, U20>,
}

impl RC5<u32, U20, U16> for RC5_32_20_16 {}

impl RC5_32_20_16 {
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        Self::encrypt(block, &self.key_table);
    }

    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        Self::decrypt(block, &self.key_table);
    }
}

impl BlockCipher for RC5_32_20_16 {}

impl KeySizeUser for RC5_32_20_16 {
    type KeySize = U16;
}

impl KeyInit for RC5_32_20_16 {
    fn new(key: &cipher::Key<Self>) -> Self {
        Self {
            key_table: Self::substitute_key(key),
        }
    }
}

impl AlgorithmName for RC5_32_20_16 {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RC5-32/12/16")
    }
}

impl_simple_block_encdec!(
    RC5_32_20_16, U8, cipher, block,
    encrypt: {
        cipher.encrypt_block(block);
    }
    decrypt: {
        cipher.decrypt_block(block);
    }
);

#[cfg(feature = "zeroize")]
use cipher::zeroize::Zeroize;

#[cfg(feature = "zeroize")]
impl cipher::zeroize::ZeroizeOnDrop for RC5_32_20_16 {}

#[cfg(feature = "zeroize")]
impl Drop for RC5_32_20_16 {
    fn drop(&mut self) {
        self.key_table.zeroize()
    }
}
