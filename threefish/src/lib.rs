#![no_std]
extern crate block_cipher_trait;
extern crate byteorder;
extern crate generic_array;
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
                for w in v.iter_mut() { *w = w.to_le(); }

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

                for w in v.iter_mut() { *w = w.to_le(); }
                write_u64v_le(block, &v[..]);
            }

            fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>)
            {
                let mut v = [0u64; $n_w];
                read_u64v_le(&mut v, &block[..]);
                for w in v.iter_mut() { *w = w.to_le(); }

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

                for w in v.iter_mut() { *w = w.to_le(); }
                write_u64v_le(block, &mut v[..]);
            }
        }
    )
);

impl_threefish!(Threefish256, 72, 4, U32, R_256, P_256);
impl_threefish!(Threefish512, 72, 8, U64, R_512, P_512);
impl_threefish!(Threefish1024, 80, 16, U128, R_1024, P_1024);
