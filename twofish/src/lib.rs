#![no_std]
extern crate block_cipher_trait;
extern crate byte_tools;
extern crate generic_array;

use block_cipher_trait::{Block, BlockCipher, BlockCipherVarKey};
use generic_array::typenum::U16;
use byte_tools::{read_u32_le, read_u32v_le, write_u32_le, write_u32v_le};

pub struct Twofish {
    s: [u8; 16], // S-box key
    k: [u32; 40], // Subkeys
    start: usize,
}

const QORD: [[usize; 5]; 4] = [[1, 1, 0, 0, 1],
                               [0, 1, 1, 0, 0],
                               [0, 0, 0, 1, 1],
                               [1, 0, 1, 1, 0]];

const QBOX: [[[u8; 16]; 4]; 2] =
    [[[0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4],
      [0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD],
      [0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1],
      [0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA]],
     [[0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5],
      [0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8],
      [0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF],
      [0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA]]];

const RS: [[u8; 8]; 4] = [[0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e],
                          [0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5],
                          [0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19],
                          [0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03]];

const MDS_POLY: u8 = 0x69; // 0x169 (x⁸ + x⁶ + x⁵ + x³ + 1)
const RS_POLY: u8 = 0x4d; // 0x14d (x⁸ + x⁶ + x³ + x² + 1)

fn gf_mult(mut a: u8, mut b: u8, p: u8) -> u8 {
    let mut result = 0;
    while a > 0 {
        if a & 1 == 1 {
            result ^= b;
        }
        a >>= 1;
        if b & 0x80 == 0x80 {
            b = (b << 1) ^ p;
        } else {
            b = b << 1;
        }
    }
    result
}

// q_i sbox
fn sbox(i: usize, x: u8) -> u8 {
    let (a0, b0) = (x >> 4 & 15, x & 15);
    let a1 = a0 ^ b0;
    let b1 = (a0 ^ ((b0 << 3) | (b0 >> 1)) ^ (a0 << 3)) & 15;
    let (a2, b2) = (QBOX[i][0][a1 as usize], QBOX[i][1][b1 as usize]);
    let a3 = a2 ^ b2;
    let b3 = (a2 ^ ((b2 << 3) | (b2 >> 1)) ^ (a2 << 3)) & 15;
    let (a4, b4) = (QBOX[i][2][a3 as usize], QBOX[i][3][b3 as usize]);
    (b4 << 4) + a4
}

fn mds_column_mult(x: u8, column: usize) -> u32 {
    let x5b = gf_mult(x, 0x5b, MDS_POLY);
    let xef = gf_mult(x, 0xef, MDS_POLY);

    let (a, b, c, d) = match column {
        0 => (x, x5b, xef, xef),
        1 => (xef, xef, x5b, x),
        2 => (x5b, xef, x, xef),
        3 => (x5b, x, xef, x5b),
        _ => panic!("Wrong MDS column"),
    };
    (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}

fn mds_mult(y: [u8; 4]) -> u32 {
    let mut z = 0;
    for i in 0..4 {
        z ^= mds_column_mult(y[i], i);
    }
    z
}

fn rs_mult(m: &[u8], out: &mut [u8]) {
    for i in 0..4 {
        out[i] = 0;
        for j in 0..8 {
            out[i] ^= gf_mult(m[j], RS[i][j], RS_POLY);
        }
    }
}

fn h(x: u32, m: &[u8], k: usize, offset: usize) -> u32 {
    let mut y: [u8; 4] = [(x >> 24) as u8, (x >> 16) as u8, (x >> 8) as u8, x as u8];

    if k == 4 {
        y[0] = sbox(1, y[0]) ^ m[4 * (6 + offset) + 0];
        y[1] = sbox(0, y[1]) ^ m[4 * (6 + offset) + 1];
        y[2] = sbox(0, y[2]) ^ m[4 * (6 + offset) + 2];
        y[3] = sbox(1, y[3]) ^ m[4 * (6 + offset) + 3];
    }

    if k >= 3 {
        y[0] = sbox(1, y[0]) ^ m[4 * (4 + offset) + 0];
        y[1] = sbox(1, y[1]) ^ m[4 * (4 + offset) + 1];
        y[2] = sbox(0, y[2]) ^ m[4 * (4 + offset) + 2];
        y[3] = sbox(0, y[3]) ^ m[4 * (4 + offset) + 3];
    }

    y[0] = sbox(1,
                sbox(0, sbox(0, y[0]) ^ m[4 * (2 + offset) + 0]) ^ m[4 * offset + 0]);
    y[1] = sbox(0,
                sbox(0, sbox(1, y[1]) ^ m[4 * (2 + offset) + 1]) ^ m[4 * offset + 1]);
    y[2] = sbox(1,
                sbox(1, sbox(0, y[2]) ^ m[4 * (2 + offset) + 2]) ^ m[4 * offset + 2]);
    y[3] = sbox(0,
                sbox(1, sbox(1, y[3]) ^ m[4 * (2 + offset) + 3]) ^ m[4 * offset + 3]);

    mds_mult(y)
}

impl Twofish {
    fn g_func(&self, x: u32) -> u32 {
        let mut result: u32 = 0;
        for y in 0..4 {
            let mut g = sbox(QORD[y][self.start], (x >> (8 * y)) as u8);

            for z in self.start + 1..5 {
                g ^= self.s[4 * (z - self.start - 1) + y];
                g = sbox(QORD[y][z], g);
            }

            result ^= mds_column_mult(g, y);
        }
        result
    }

    fn key_schedule(&mut self, key: &[u8]) {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            panic!("Invalid key size: {}", key.len());
        }
        let k = key.len() / 8;

        let rho: u32 = 0x1010101;

        for x in 0..20 {
            let a = h(rho * (2 * x), key, k, 0);
            let b = h(rho * (2 * x + 1), key, k, 1).rotate_left(8);
            self.k[(2 * x) as usize] = a.wrapping_add(b);
            self.k[(2 * x + 1) as usize] = (a.wrapping_add(b).wrapping_add(b)).rotate_left(9);
        }
        self.start = match k {
            4 => 0,
            3 => 1,
            _ => 2,
        };

        // Compute S_i.
        for i in 0..k {
            rs_mult(&key[i * 8..i * 8 + 8], &mut self.s[i * 4..(i + 1) * 4]);
        }
    }
}

impl BlockCipher for Twofish {
    type BlockSize = U16;

    fn encrypt_block(&self, input: &Block<U16>, output: &mut Block<U16>) {
        let mut p = [0u32; 4];
        read_u32v_le(&mut p, input);

        // Input whitening
        for i in 0..4 {
            p[i] ^= self.k[i];
        }

        for r in 0..8 {
            let k = 4 * r + 8;

            let t1 = self.g_func(p[1].rotate_left(8));
            let t0 = self.g_func(p[0]).wrapping_add(t1);
            p[2] = (p[2] ^ (t0.wrapping_add(self.k[k]))).rotate_right(1);
            p[3] = p[3].rotate_left(1) ^ (t1.wrapping_add(t0).wrapping_add(self.k[k + 1]));

            let t1 = self.g_func(p[3].rotate_left(8));
            let t0 = self.g_func(p[2]).wrapping_add(t1);
            p[0] = (p[0] ^ (t0.wrapping_add(self.k[k + 2]))).rotate_right(1);
            p[1] = (p[1].rotate_left(1)) ^ (t1.wrapping_add(t0).wrapping_add(self.k[k + 3]));
        }

        // Undo last swap and output whitening
        write_u32_le(&mut output[0..4], p[2] ^ self.k[4]);
        write_u32_le(&mut output[4..8], p[3] ^ self.k[5]);
        write_u32_le(&mut output[8..12], p[0] ^ self.k[6]);
        write_u32_le(&mut output[12..16], p[1] ^ self.k[7]);
    }

    fn decrypt_block(&self, input: &Block<U16>, output: &mut Block<U16>) {
        let mut c = [0u32; 4];

        c[0] = read_u32_le(&input[8..12]) ^ self.k[6];
        c[1] = read_u32_le(&input[12..16]) ^ self.k[7];
        c[2] = read_u32_le(&input[0..4]) ^ self.k[4];
        c[3] = read_u32_le(&input[4..8]) ^ self.k[5];

        for r in (0..8).rev() {
            let k = 4 * r + 8;

            let t1 = self.g_func(c[3].rotate_left(8));
            let t0 = self.g_func(c[2]).wrapping_add(t1);
            c[0] = c[0].rotate_left(1) ^ (t0.wrapping_add(self.k[k + 2]));
            c[1] = (c[1] ^ (t1.wrapping_add(t0).wrapping_add(self.k[k + 3]))).rotate_right(1);

            let t1 = self.g_func(c[1].rotate_left(8));
            let t0 = self.g_func(c[0]).wrapping_add(t1);
            c[2] = c[2].rotate_left(1) ^ (t0.wrapping_add(self.k[k]));
            c[3] = (c[3] ^ (t1.wrapping_add(t0).wrapping_add(self.k[k + 1]))).rotate_right(1);
        }

        for i in 0..4 {
            c[i] ^= self.k[i];
        }
        write_u32v_le(output, &c[..]);
    }
}

impl BlockCipherVarKey for Twofish {
    fn new(key: &[u8]) -> Twofish {
        let mut twofish = Twofish {
            s: [0u8; 16],
            k: [0u32; 40],
            start: 0,
        };
        twofish.key_schedule(key);
        twofish
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intermediate128() {
        let key = [0u8; 16];
        let twofish = Twofish::new(&key);
        let subkeys: [u32; 40] =
            [0x52C54DDE, 0x11F0626D, 0x7CAC9D4A, 0x4D1B4AAA, 0xB7B83A10, 0x1E7D0BEB, 0xEE9C341F,
             0xCFE14BE4, 0xF98FFEF9, 0x9C5B3C17, 0x15A48310, 0x342A4D81, 0x424D89FE, 0xC14724A7,
             0x311B834C, 0xFDE87320, 0x3302778F, 0x26CD67B4, 0x7A6C6362, 0xC2BAF60E, 0x3411B994,
             0xD972C87F, 0x84ADB1EA, 0xA7DEE434, 0x54D2960F, 0xA2F7CAA8, 0xA6B8FF8C, 0x8014C425,
             0x6A748D1C, 0xEDBAF720, 0x928EF78C, 0x0338EE13, 0x9949D6BE, 0xC8314176, 0x07C07D68,
             0xECAE7EA7, 0x1FE71844, 0x85C05C89, 0xF298311E, 0x696EA672];
        assert_eq!(&twofish.k[..], &subkeys[..]);
    }

    #[test]
    fn intermediate192() {
        let key: [u8; 24] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA,
                             0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                             0x66, 0x77];
        let twofish = Twofish::new(&key);
        let sboxkey: [u8; 12] = [0xf2, 0xf6, 0x9f, 0xb8, 0x4b, 0xbc, 0x55, 0xb2, 0x61, 0x10, 0x66,
                                 0x45];
        let subkeys: [u32; 40] =
            [0x38394A24, 0xC36D1175, 0xE802528F, 0x219BFEB4, 0xB9141AB4, 0xBD3E70CD, 0xAF609383,
             0xFD36908A, 0x03EFB931, 0x1D2EE7EC, 0xA7489D55, 0x6E44B6E8, 0x714AD667, 0x653AD51F,
             0xB6315B66, 0xB27C05AF, 0xA06C8140, 0x9853D419, 0x4016E346, 0x8D1C0DD4, 0xF05480BE,
             0xB6AF816F, 0x2D7DC789, 0x45B7BD3A, 0x57F8A163, 0x2BEFDA69, 0x26AE7271, 0xC2900D79,
             0xED323794, 0x3D3FFD80, 0x5DE68E49, 0x9C3D2478, 0xDF326FE3, 0x5911F70D, 0xC229F13B,
             0xB1364772, 0x4235364D, 0x0CEC363A, 0x57C8DD1F, 0x6A1AD61E];
        assert_eq!(&twofish.s[..12], &sboxkey[..]);
        assert_eq!(&twofish.k[..], &subkeys[..]);
    }

    #[test]
    fn intermediate256() {
        let key: [u8; 32] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA,
                             0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                             0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let twofish = Twofish::new(&key);
        let sboxkey: [u8; 16] = [0xf2, 0xf6, 0x9f, 0xb8, 0x4b, 0xbc, 0x55, 0xb2, 0x61, 0x10, 0x66,
                                 0x45, 0xf7, 0x47, 0x44, 0x8e];
        let subkeys: [u32; 40] =
            [0x5EC769BF, 0x44D13C60, 0x76CD39B1, 0x16750474, 0x349C294B, 0xEC21F6D6, 0x4FBD10B4,
             0x578DA0ED, 0xC3479695, 0x9B6958FB, 0x6A7FBC4E, 0x0BF1830B, 0x61B5E0FB, 0xD78D9730,
             0x7C6CF0C4, 0x2F9109C8, 0xE69EA8D1, 0xED99BDFF, 0x35DC0BBD, 0xA03E5018, 0xFB18EA0B,
             0x38BD43D3, 0x76191781, 0x37A9A0D3, 0x72427BEA, 0x911CC0B8, 0xF1689449, 0x71009CA9,
             0xB6363E89, 0x494D9855, 0x590BBC63, 0xF95A28B5, 0xFB72B4E1, 0x2A43505C, 0xBFD34176,
             0x5C133D12, 0x3A9247F7, 0x9A3331DD, 0xEE7515E6, 0xF0D54DCD];
        assert_eq!(&twofish.s[..], &sboxkey[..]);
        assert_eq!(&twofish.k[..], &subkeys[..]);
    }
}
