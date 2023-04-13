use crate::{belt_block_raw, g13, g21, g5, key_idx};
use cipher::consts::{U16, U32};
use cipher::{
    inout::InOut, AlgorithmName, Block, BlockCipher, BlockEncrypt, Key, KeyInit, KeySizeUser,
};
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

    /// Wide block encryption as described in section 6.2.3.
    #[inline]
    pub fn wblock_enc(&self, data: &mut [u8]) {
        let len = data.len();
        let n = (len + 15) / 16;
        // For i = 1,2,...,2n execute:
        for i in 1..=2 * n {
            let mut block: Block<BeltBlock> = Default::default();
            block.copy_from_slice(&data[..16]);

            // 𝑠←𝑟1 ⊕𝑟2 ⊕...⊕𝑟𝑛−1
            for i in (16..len - 16).step_by(16) {
                xor_set(&mut block, &data[i..i + 16]);
            }

            // 𝑟←ShLo128(𝑟)
            data.copy_from_slice(&[&data[16..len], &block[..]].concat());
            // 𝑟* ← 𝑟* ⊕ belt-block(𝑠, 𝐾) ⊕ ⟨𝑖⟩128
            data[len - 16..].copy_from_slice(&block);
            self.encrypt_block(&mut block);
            xor_set(&mut block, &i.to_le_bytes());
            // 𝑟* ← 𝑠.
            xor_set(&mut data[len - 32..], &block);
        }
    }

    /// Wide block decryption as described in section 6.2.4.
    #[inline]
    pub fn wblock_dec(&self, data: &mut [u8]) {
        let len = data.len();
        let n = (len + 15) / 16;
        // For i = 2n,2n−1,...,1 execute:
        for i in (1..=2 * n).rev() {
            // block <- r*
            let mut block: Block<BeltBlock> = Default::default();
            block.copy_from_slice(&data[len - 16..]);

            // r <- ShHi^128(r)
            // r1 <- block
            data.copy_from_slice(&[&block[..], &data[..len - 16]].concat());

            self.encrypt_block(&mut block);
            xor_set(&mut block, &i.to_le_bytes());
            xor_set(&mut data[len - 16..], &block);

            let mut t: Block<BeltBlock> = Default::default();
            t.copy_from_slice(&data[..16]);
            // 𝑠←𝑟1 ⊕𝑟2 ⊕...⊕𝑟𝑛−1
            for i in (16..len - 16).step_by(16) {
                xor_set(&mut t, &data[i..i + 16]);
            }
            data[..16].copy_from_slice(&t);
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

#[inline(always)]
fn xor_set(block: &mut [u8], val: &[u8]) {
    block.iter_mut().zip(val.iter()).for_each(|(a, b)| *a ^= b);
}

#[cfg(test)]
mod tests {
    use cipher::KeyInit;
    use hex_literal::hex;

    #[test]
    fn stb_34_101_31_a6() {
        let k = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
        let mut x1 = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B");
        let y1 = hex!("49A38EE1 08D6C742 E52B774F 00A6EF98 B106CBD1 3EA4FB06 80323051 BC04DF76 E487B055 C69BCF54 1176169F 1DC9F6C8");

        let mut x2 = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B89");
        let y2 = hex!("F08EF22D CAA06C81 FB127219 74221CA7 AB82C628 56FCF2F9 FCA006E0 19A28F16 E5821A51 F5735946 25DBAB8F 6A5C94");

        let belt = super::BeltBlock::new_from_slice(&k).unwrap();

        let x_bkp = x1;

        belt.wblock_enc(&mut x1);
        assert_eq!(x1, y1);
        belt.wblock_dec(&mut x1);
        assert_eq!(x1, x_bkp);

        let x_bkp = x2;
        belt.wblock_enc(&mut x2);
        assert_eq!(x2, y2);
        belt.wblock_dec(&mut x2);
        assert_eq!(x2, x_bkp);
    }

    #[test]
    fn stb_34_101_31_a7() {
        let k = hex!("92BD9B1C E5D14101 5445FBC9 5E4D0EF2 682080AA 227D642F 2687F934 90405511");
        let mut y1 = hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638 9FE678CA F7C6F860 D5BB9C4F F33C657B 637C306A DD4EA779 9EB23D31");
        let x1 = hex!("92632EE0 C21AD9E0 9A39343E 5C07DAA4 889B03F2 E6847EB1 52EC99F7 A4D9F154 B5EF68D8 E4A39E56 7153DE13 D72254EE");

        let mut y2 = hex!(
            "E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638 9FE678CA F7C6F860 D5BB9C4F F33C657B"
        );
        let x2 = hex!(
            "DF3F8822 30BAAFFC 92F05660 32117231 0E3CB218 2681EF43 102E6717 5E177BD7 5E93E4E8"
        );

        let belt = super::BeltBlock::new_from_slice(&k).unwrap();

        let y_bkp = y1;

        belt.wblock_dec(&mut y1);
        assert_eq!(y1, x1);
        belt.wblock_enc(&mut y1);
        assert_eq!(y1, y_bkp);

        let y_bkp = y2;
        belt.wblock_dec(&mut y2);
        assert_eq!(y2, x2);
        belt.wblock_enc(&mut y2);
        assert_eq!(y2, y_bkp);
    }
}
