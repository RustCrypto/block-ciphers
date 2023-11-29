#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};
use cipher::{
    consts::U16, inout::InOut, AlgorithmName, Block, BlockCipher, BlockSizeUser, Key, KeyInit,
    KeySizeUser,
};
use core::{convert::TryInto, fmt};

use crate::consts::{CK, FK, SBOX};

#[inline]
fn tau(a: u32) -> u32 {
    let mut buf = a.to_be_bytes();
    buf[0] = SBOX[buf[0] as usize];
    buf[1] = SBOX[buf[1] as usize];
    buf[2] = SBOX[buf[2] as usize];
    buf[3] = SBOX[buf[3] as usize];
    u32::from_be_bytes(buf)
}

/// L: linear transformation
#[inline]
fn el(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

#[inline]
fn el_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

#[inline]
fn t(val: u32) -> u32 {
    el(tau(val))
}

#[inline]
fn t_prime(val: u32) -> u32 {
    el_prime(tau(val))
}

#[inline]
pub(crate) fn sm4_init_key<T: KeySizeUser>(key: &Key<T>) -> [u32; 32] {
    let mk = [
        u32::from_be_bytes(key[0..4].try_into().unwrap()),
        u32::from_be_bytes(key[4..8].try_into().unwrap()),
        u32::from_be_bytes(key[8..12].try_into().unwrap()),
        u32::from_be_bytes(key[12..16].try_into().unwrap()),
    ];
    let mut rk = [0u32; 32];
    let mut k = [mk[0] ^ FK[0], mk[1] ^ FK[1], mk[2] ^ FK[2], mk[3] ^ FK[3]];

    for i in 0..8 {
        k[0] ^= t_prime(k[1] ^ k[2] ^ k[3] ^ CK[i * 4]);
        k[1] ^= t_prime(k[2] ^ k[3] ^ k[0] ^ CK[i * 4 + 1]);
        k[2] ^= t_prime(k[3] ^ k[0] ^ k[1] ^ CK[i * 4 + 2]);
        k[3] ^= t_prime(k[0] ^ k[1] ^ k[2] ^ CK[i * 4 + 3]);

        rk[i * 4] = k[0];
        rk[i * 4 + 1] = k[1];
        rk[i * 4 + 2] = k[2];
        rk[i * 4 + 3] = k[3];
    }

    rk
}

#[inline]
#[allow(unused)]
pub(super) fn sm4_encrypt<T: BlockSizeUser>(mut block: InOut<'_, '_, Block<T>>, rk: &[u32; 32]) {
    let b = block.get_in();
    let mut x = [
        u32::from_be_bytes(b[0..4].try_into().unwrap()),
        u32::from_be_bytes(b[4..8].try_into().unwrap()),
        u32::from_be_bytes(b[8..12].try_into().unwrap()),
        u32::from_be_bytes(b[12..16].try_into().unwrap()),
    ];

    for i in 0..8 {
        x[0] ^= t(x[1] ^ x[2] ^ x[3] ^ rk[i * 4]);
        x[1] ^= t(x[2] ^ x[3] ^ x[0] ^ rk[i * 4 + 1]);
        x[2] ^= t(x[3] ^ x[0] ^ x[1] ^ rk[i * 4 + 2]);
        x[3] ^= t(x[0] ^ x[1] ^ x[2] ^ rk[i * 4 + 3]);
    }

    let block = block.get_out();
    block[0..4].copy_from_slice(&x[3].to_be_bytes());
    block[4..8].copy_from_slice(&x[2].to_be_bytes());
    block[8..12].copy_from_slice(&x[1].to_be_bytes());
    block[12..16].copy_from_slice(&x[0].to_be_bytes());
}

#[inline]
#[allow(unused)]
pub(super) fn sm4_decrypt<T: BlockSizeUser>(mut block: InOut<'_, '_, Block<T>>, rk: &[u32; 32]) {
    let b = block.get_in();
    let mut x = [
        u32::from_be_bytes(b[0..4].try_into().unwrap()),
        u32::from_be_bytes(b[4..8].try_into().unwrap()),
        u32::from_be_bytes(b[8..12].try_into().unwrap()),
        u32::from_be_bytes(b[12..16].try_into().unwrap()),
    ];

    for i in 0..8 {
        x[0] ^= t(x[1] ^ x[2] ^ x[3] ^ rk[31 - i * 4]);
        x[1] ^= t(x[2] ^ x[3] ^ x[0] ^ rk[31 - (i * 4 + 1)]);
        x[2] ^= t(x[3] ^ x[0] ^ x[1] ^ rk[31 - (i * 4 + 2)]);
        x[3] ^= t(x[0] ^ x[1] ^ x[2] ^ rk[31 - (i * 4 + 3)]);
    }

    let block = block.get_out();
    block[0..4].copy_from_slice(&x[3].to_be_bytes());
    block[4..8].copy_from_slice(&x[2].to_be_bytes());
    block[8..12].copy_from_slice(&x[1].to_be_bytes());
    block[12..16].copy_from_slice(&x[0].to_be_bytes());
}

/// SM4 block cipher.
#[derive(Clone)]
pub struct Sm4 {
    rk: [u32; 32],
}

impl BlockCipher for Sm4 {}

impl KeySizeUser for Sm4 {
    type KeySize = U16;
}

impl KeyInit for Sm4 {
    fn new(key: &Key<Self>) -> Self {
        Sm4 {
            rk: sm4_init_key::<Self>(key),
        }
    }
}

impl fmt::Debug for Sm4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm4 { ... }")
    }
}

impl AlgorithmName for Sm4 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm4")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for Sm4 {
    fn drop(&mut self) {
        self.rk.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for Sm4 {}

cipher::impl_simple_block_encdec!(
    Sm4, U16, cipher, block,
    encrypt: {
        sm4_encrypt::<Self>(block, &cipher.rk);
    }
    decrypt: {
        sm4_decrypt::<Self>(block, &cipher.rk);
    }
);
