use crate::{belt_block_raw, g13, g21, g5, key_idx};
use cipher::consts::{U16, U32};
use cipher::{inout::InOut, AlgorithmName, Block, BlockCipher, Key, KeyInit, KeySizeUser};
use core::{fmt, mem::swap, num::Wrapping};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// BelT block cipher.
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "cipher")))]
pub struct BeltBlock {
    key: [u32; 8],
}

impl BeltBlock {
    /// Encryption as described in section 6.1.3
    #[inline]
    fn encrypt(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let block_in = block.get_in();
        // Steps 1 and 4
        let x = [
            get_u32(block_in, 0),
            get_u32(block_in, 1),
            get_u32(block_in, 2),
            get_u32(block_in, 3),
        ];

        let y = belt_block_raw(x, &self.key);

        let block_out = block.get_out();
        // 6) Y ← b ‖ d ‖ a ‖ c
        for i in 0..4 {
            set_u32(block_out, &y, i);
        }
    }

    /// Decryption as described in section 6.1.4
    #[inline]
    fn decrypt(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let key = &self.key;
        let block_in = block.get_in();
        // Steps 1 and 4
        let mut a = Wrapping(get_u32(block_in, 0));
        let mut b = Wrapping(get_u32(block_in, 1));
        let mut c = Wrapping(get_u32(block_in, 2));
        let mut d = Wrapping(get_u32(block_in, 3));

        // Step 5
        for i in (1..9).rev() {
            // 5.1) b ← b ⊕ G₅(a ⊞ 𝑘[7i])
            b ^= g5(a + key_idx(key, i, 0));
            // 5.2) c ← c ⊕ G₂₁(d ⊞ 𝑘[7i-1])
            c ^= g21(d + key_idx(key, i, 1));
            // 5.3) a ← a ⊟ G₁₃(b ⊞ 𝑘[7i-2])
            a -= g13(b + key_idx(key, i, 2));
            // 5.4) e ← G₂₁(b ⊞ c ⊞ 𝑘[7i-3]) ⊕ ⟨i⟩₃₂
            let e = g21(b + c + key_idx(key, i, 3)) ^ Wrapping(i as u32);
            // 5.5) b ← b ⊞ e
            b += e;
            // 5.6) c ← c ⊟ e
            c -= e;
            // 5.7) d ← d ⊞ G₁₃(c ⊞ 𝑘[7i-4])
            d += g13(c + key_idx(key, i, 4));
            // 5.8) b ← b ⊕ G₂₁(a ⊞ 𝑘[7i-5])
            b ^= g21(a + key_idx(key, i, 5));
            // 5.9) c ← c ⊕ G₅(d ⊞ 𝑘[7i-6])
            c ^= g5(d + key_idx(key, i, 6));
            // 5.10) a ↔ b
            swap(&mut a, &mut b);
            // 5.11) c ↔ d
            swap(&mut c, &mut d);
            // 5.12) a ↔ d
            swap(&mut a, &mut d);
        }

        let block_out = block.get_out();
        // 6) 𝑋 ← c ‖ a ‖ d ‖ b
        let x = [c.0, a.0, d.0, b.0];
        for i in 0..4 {
            set_u32(block_out, &x, i);
        }
    }
}

impl BlockCipher for BeltBlock {}

impl KeySizeUser for BeltBlock {
    type KeySize = U32;
}

impl KeyInit for BeltBlock {
    fn new(key: &Key<Self>) -> Self {
        Self {
            key: [
                get_u32(key, 0),
                get_u32(key, 1),
                get_u32(key, 2),
                get_u32(key, 3),
                get_u32(key, 4),
                get_u32(key, 5),
                get_u32(key, 6),
                get_u32(key, 7),
            ],
        }
    }
}

impl AlgorithmName for BeltBlock {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltBlock")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for BeltBlock {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for BeltBlock {}

cipher::impl_simple_block_encdec!(
    BeltBlock, U16, cipher, block,
    encrypt: {
        cipher.encrypt(block);
    }
    decrypt: {
        cipher.decrypt(block);
    }
);

#[inline(always)]
fn get_u32(block: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(block[4 * i..][..4].try_into().unwrap())
}

#[inline(always)]
fn set_u32(block: &mut [u8], val: &[u32; 4], i: usize) {
    block[4 * i..][..4].copy_from_slice(&val[i].to_le_bytes());
}
