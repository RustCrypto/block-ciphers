//! Triple DES (3DES) block ciphers.

use crate::{utils::gen_keys, Des};
use cipher::{
    consts::{U1, U16, U24, U8},
    crypto_common::WeakKeyError,
    typenum::Unsigned,
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut, Key,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{ZeroizeOnDrop, Zeroizing};

#[inline]
fn weak_key_test<const SIZE: usize, U: KeyInit>(key: &Key<U>) -> Result<(), WeakKeyError> {
    #[cfg(feature = "zeroize")]
    let mut tmp = Zeroizing::new(Key::<U>::default());
    #[cfg(not(feature = "zeroize"))]
    let mut tmp = Key::<U>::default();

    for i in 0..<U as KeySizeUser>::KeySize::USIZE {
        // count number of set bits in byte, excluding the low-order bit - SWAR method
        let mut c = key[i] & 0xFE;

        c = (c & 0x55) + ((c >> 1) & 0x55);
        c = (c & 0x33) + ((c >> 2) & 0x33);
        c = (c & 0x0F) + ((c >> 4) & 0x0F);

        // if count is even, set low key bit to 1, otherwise 0
        tmp[i] = (key[i] & 0xFE) | u8::from(c & 0x01 != 0x01);
    }

    let mut des_key = Key::<Des>::default();
    for i in 0..SIZE {
        des_key.copy_from_slice(
            &tmp.as_slice()[i * <Des as KeySizeUser>::KeySize::USIZE
                ..(i + 1) * <Des as KeySizeUser>::KeySize::USIZE],
        );
        Des::weak_key_test(&des_key)?;
    }
    Ok(())
}

/// Triple DES (3DES) block cipher.
#[derive(Clone)]
pub struct TdesEde3 {
    d1: Des,
    d2: Des,
    d3: Des,
}

impl KeySizeUser for TdesEde3 {
    type KeySize = U24;
}

impl KeyInit for TdesEde3 {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let k3 = u64::from_be_bytes(key[16..24].try_into().unwrap());
        let d1 = Des { keys: gen_keys(k1) };
        let d2 = Des { keys: gen_keys(k2) };
        let d3 = Des { keys: gen_keys(k3) };
        Self { d1, d2, d3 }
    }

    #[inline]
    fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
        weak_key_test::<3, Self>(key)
    }
}

impl BlockSizeUser for TdesEde3 {
    type BlockSize = U8;
}

impl ParBlocksSizeUser for TdesEde3 {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for TdesEde3 {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for TdesEde3 {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.clone_in().into());
        data = self.d1.encrypt(data);
        data = self.d2.decrypt(data);
        data = self.d3.encrypt(data);
        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl BlockCipherDecrypt for TdesEde3 {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for TdesEde3 {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.clone_in().into());
        data = self.d3.decrypt(data);
        data = self.d2.encrypt(data);
        data = self.d1.decrypt(data);
        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl fmt::Debug for TdesEde3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEee3 { ... }")
    }
}

impl AlgorithmName for TdesEde3 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEde3")
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for TdesEde3 {}

/// Triple DES (3DES) block cipher.
#[derive(Clone)]
pub struct TdesEee3 {
    d1: Des,
    d2: Des,
    d3: Des,
}

impl KeySizeUser for TdesEee3 {
    type KeySize = U24;
}

impl KeyInit for TdesEee3 {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let k3 = u64::from_be_bytes(key[16..24].try_into().unwrap());
        let d1 = Des { keys: gen_keys(k1) };
        let d2 = Des { keys: gen_keys(k2) };
        let d3 = Des { keys: gen_keys(k3) };
        Self { d1, d2, d3 }
    }

    #[inline]
    fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
        weak_key_test::<3, Self>(key)
    }
}

impl BlockSizeUser for TdesEee3 {
    type BlockSize = U8;
}

impl ParBlocksSizeUser for TdesEee3 {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for TdesEee3 {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for TdesEee3 {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.clone_in().into());
        data = self.d1.encrypt(data);
        data = self.d2.encrypt(data);
        data = self.d3.encrypt(data);
        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl BlockCipherDecrypt for TdesEee3 {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for TdesEee3 {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.clone_in().into());
        data = self.d3.decrypt(data);
        data = self.d2.decrypt(data);
        data = self.d1.decrypt(data);
        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl fmt::Debug for TdesEee3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEee3 { ... }")
    }
}

impl AlgorithmName for TdesEee3 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEee3")
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for TdesEee3 {}

/// Triple DES (3DES) block cipher.
#[derive(Clone)]
pub struct TdesEde2 {
    d1: Des,
    d2: Des,
}

impl KeySizeUser for TdesEde2 {
    type KeySize = U16;
}

impl KeyInit for TdesEde2 {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let d1 = Des { keys: gen_keys(k1) };
        let d2 = Des { keys: gen_keys(k2) };
        Self { d1, d2 }
    }

    #[inline]
    fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
        weak_key_test::<2, Self>(key)
    }
}

impl BlockSizeUser for TdesEde2 {
    type BlockSize = U8;
}

impl ParBlocksSizeUser for TdesEde2 {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for TdesEde2 {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for TdesEde2 {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.clone_in().into());
        data = self.d1.encrypt(data);
        data = self.d2.decrypt(data);
        data = self.d1.encrypt(data);
        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl BlockCipherDecrypt for TdesEde2 {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for TdesEde2 {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.clone_in().into());
        data = self.d1.decrypt(data);
        data = self.d2.encrypt(data);
        data = self.d1.decrypt(data);
        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl fmt::Debug for TdesEde2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEde2 { ... }")
    }
}

impl AlgorithmName for TdesEde2 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEde2")
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for TdesEde2 {}

/// Triple DES (3DES) block cipher.
#[derive(Clone)]
pub struct TdesEee2 {
    d1: Des,
    d2: Des,
}

impl KeySizeUser for TdesEee2 {
    type KeySize = U16;
}

impl KeyInit for TdesEee2 {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let k1 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k2 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let d1 = Des { keys: gen_keys(k1) };
        let d2 = Des { keys: gen_keys(k2) };
        Self { d1, d2 }
    }

    #[inline]
    fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
        weak_key_test::<2, Self>(key)
    }
}

impl BlockSizeUser for TdesEee2 {
    type BlockSize = U8;
}

impl ParBlocksSizeUser for TdesEee2 {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for TdesEee2 {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for TdesEee2 {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.clone_in().into());
        data = self.d1.encrypt(data);
        data = self.d2.encrypt(data);
        data = self.d1.encrypt(data);
        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl BlockCipherDecrypt for TdesEee2 {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for TdesEee2 {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut data = u64::from_be_bytes(block.clone_in().into());
        data = self.d1.decrypt(data);
        data = self.d2.decrypt(data);
        data = self.d1.decrypt(data);
        block.get_out().copy_from_slice(&data.to_be_bytes());
    }
}

impl fmt::Debug for TdesEee2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEee2 { ... }")
    }
}

impl AlgorithmName for TdesEee2 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TdesEee2")
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for TdesEee2 {}
