#![no_std]
extern crate block_cipher_trait;
extern crate byteorder;
extern crate generic_array;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;
use core::ops::BitXor;

mod consts;
use consts::{C240, P_1024, P_256, P_512, R_1024, R_256, R_512};

use byteorder::{ByteOrder, LE};
pub use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U1, U128, U32, U64};

fn mix(r: u32, x: (u64, u64)) -> (u64, u64) {
    let y0 = x.0.wrapping_add(x.1);
    let y1 = x.1.rotate_left(r) ^ y0;
    (y0, y1)
}

fn inv_mix(r: u32, y: (u64, u64)) -> (u64, u64) {
    let x1 = (y.0 ^ y.1).rotate_right(r);
    let x0 = y.0.wrapping_sub(x1);
    (x0, x1)
}

fn read_u64v_le(ns: &mut [u64], buf: &[u8]) {
    for (c, n) in buf.chunks(8).zip(ns) {
        *n = LE::read_u64(c);
    }
}

fn write_u64v_le(buf: &mut [u8], ns: &[u64]) {
    for (c, n) in buf.chunks_mut(8).zip(ns) {
        LE::write_u64(c, *n);
    }
}

macro_rules! impl_threefish(
    (
        $name:ident, $rounds:expr, $n_w:expr, $block_size:ty,
        $rot:expr, $perm:expr
    ) => (

        #[derive(Clone, Copy)]
        pub struct $name {
            sk: [[u64; $n_w]; $rounds / 4 + 1]
        }

        impl $name {
            pub fn with_tweak(key: &GenericArray<u8, $block_size>, tweak0: u64, tweak1: u64) -> $name {
                let mut k = [0u64; $n_w + 1];
                read_u64v_le(&mut k[..$n_w], key);
                k[$n_w] = k[..$n_w].iter().fold(C240, BitXor::bitxor);

                let t = [tweak0, tweak1, tweak0 ^ tweak1];
                let mut sk = [[0u64; $n_w]; $rounds / 4 + 1];
                for s in 0..($rounds / 4 + 1) {
                    for i in 0..$n_w {
                        sk[s][i] = k[(s + i) % ($n_w + 1)];
                        if i == $n_w - 3 {
                            sk[s][i] = sk[s][i].wrapping_add(t[s % 3]);
                        } else if i == $n_w - 2 {
                            sk[s][i] = sk[s][i].wrapping_add(t[(s + 1) % 3]);
                        } else if i == $n_w - 1 {
                            sk[s][i] = sk[s][i].wrapping_add(s as u64);
                        }
                    }
                }

                $name { sk: sk }
            }
        }

        impl BlockCipher for $name {
            type BlockSize = $block_size;
            type KeySize = $block_size;
            type ParBlocks = U1;

            fn new(key: &GenericArray<u8, $block_size>) -> $name {
                Self::with_tweak(key, 0, 0)
            }

            fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>)
            {
                let mut v = [0u64; $n_w];
                read_u64v_le(&mut v, block);

                for d in 0..$rounds {
                    let v_tmp = v.clone();
                    for j in 0..($n_w / 2) {
                        let (v0, v1) = (v_tmp[2 * j], v_tmp[2 * j + 1]);
                        let (e0, e1) =
                            if d % 4 == 0 {
                                (v0.wrapping_add(self.sk[d / 4][2 * j]),
                                 v1.wrapping_add(self.sk[d / 4][2 * j + 1]))
                            } else {
                                (v0, v1)
                            };
                        let r = $rot[d % 8][j];
                        let (f0, f1) = mix(r, (e0, e1));
                        let (pi0, pi1) =
                            ($perm[2 * j], $perm[2 * j + 1]);
                        v[pi0] = f0;
                        v[pi1] = f1;
                    }
                }

                for i in 0..$n_w {
                    v[i] = v[i].wrapping_add(self.sk[$rounds / 4][i]);
                }

                write_u64v_le(block, &v[..]);
            }

            fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>)
            {
                let mut v = [0u64; $n_w];
                read_u64v_le(&mut v, &block[..]);

                for i in 0..$n_w {
                    v[i] = v[i].wrapping_sub(self.sk[$rounds / 4][i]);
                }

                for d in (0..$rounds).rev() {
                    let v_tmp = v.clone();
                    for j in 0..($n_w / 2) {
                        let (inv_pi0, inv_pi1) =
                            ($perm[2 * j], $perm[2 * j + 1]);
                        let (f0, f1) = (v_tmp[inv_pi0], v_tmp[inv_pi1]);
                        let r = $rot[d % 8][j];
                        let (e0, e1) = inv_mix(r, (f0, f1));
                        let (v0, v1) =
                            if d % 4 == 0 {
                                (e0.wrapping_sub(self.sk[d / 4][2 * j]),
                                 e1.wrapping_sub(self.sk[d / 4][2 * j + 1]))
                             } else {
                                 (e0, e1)
                             };
                        v[2 * j] = v0;
                        v[2 * j + 1] = v1;
                    }
                }

                write_u64v_le(block, &v[..]);
            }
        }
    )
);

impl_threefish!(Threefish256, 72, 4, U32, R_256, P_256);
impl_threefish!(Threefish512, 72, 8, U64, R_512, P_512);
impl_threefish!(Threefish1024, 80, 16, U128, R_1024, P_1024);

#[cfg(test)]
mod test {
    //! tests from NIST submission

    use super::{Threefish256, Threefish512, Threefish1024};
    use block_cipher_trait::generic_array::GenericArray;
    use block_cipher_trait::BlockCipher;

    #[test]
    fn test_256() {
        let fish = Threefish256::new(&GenericArray::default());
        let mut block = GenericArray::default();
        fish.encrypt_block(&mut block);
        let expected = hex!("84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8");
        assert_eq!(&block[..], &expected[..]);

        let key = hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").into();
        let fish = Threefish256::with_tweak(&key, 0x0706050403020100, 0x0f0e0d0c0b0a0908);
        let mut block = hex!("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0").into();
        fish.encrypt_block(&mut block);
        let expected = hex!("e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df");
        assert_eq!(&block[..], &expected[..]);
    }

    #[test]
    fn test_512() {
        let fish = Threefish512::new(&GenericArray::default());
        let mut block = GenericArray::default();
        fish.encrypt_block(&mut block);
        let expected = hex!("
            b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b
            7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe");
        assert_eq!(&block[..], &expected[..]);

        let mut key = GenericArray::default();
        key.copy_from_slice(&hex!("
            101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
            303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"));
        let fish = Threefish512::with_tweak(&key, 0x0706050403020100, 0x0f0e0d0c0b0a0908);
        let mut block = GenericArray::default();
        block.copy_from_slice(&hex!("
            fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0
            dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0"));
        fish.encrypt_block(&mut block);
        let expected = hex!("
            e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779
            272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d");
        assert_eq!(&block[..], &expected[..]);
    }

    #[test]
    fn test_1024() {
        let fish = Threefish1024::new(&GenericArray::default());
        let mut block = GenericArray::default();
        fish.encrypt_block(&mut block);
        let expected = hex!("
            f05c3d0a3d05b304f785ddc7d1e036015c8aa76e2f217b06c6e1544c0bc1a90d
            f0accb9473c24e0fd54fea68057f43329cb454761d6df5cf7b2e9b3614fbd5a2
            0b2e4760b40603540d82eabc5482c171c832afbe68406bc39500367a592943fa
            9a5b4a43286ca3c4cf46104b443143d560a4b230488311df4feef7e1dfe8391e");
        assert_eq!(&block[..], &expected[..]);

        let mut key = GenericArray::default();
        key.copy_from_slice(&hex!("
            101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
            303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
            505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f
            707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"));
        let fish = Threefish1024::with_tweak(&key, 0x0706050403020100, 0x0f0e0d0c0b0a0908);
        let mut block = GenericArray::default();
        block.copy_from_slice(&hex!("
            fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0
            dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0
            bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0
            9f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180"));
        fish.encrypt_block(&mut block);
        let expected = hex!("
            a6654ddbd73cc3b05dd777105aa849bce49372eaaffc5568d254771bab85531c
            94f780e7ffaae430d5d8af8c70eebbe1760f3b42b737a89cb363490d670314bd
            8aa41ee63c2e1f45fbd477922f8360b388d6125ea6c7af0ad7056d01796e90c8
            3313f4150a5716b30ed5f569288ae974ce2b4347926fce57de44512177dd7cde");
        assert_eq!(&block[..], &expected[..]);
    }
}
