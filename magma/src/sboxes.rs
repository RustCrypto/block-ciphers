//! Expanded S-boxes generated using `gen_exp_sbox` function

type ExpSbox = [[u8; 256]; 4];
type SmallSbox = [[u8; 16]; 8];

const fn gen_exp_sbox(sbox: &SmallSbox) -> ExpSbox {
    let mut out = [[0u8; 256]; 4];
    let mut i = 0;
    while i < 4 {
        let mut j = 0;
        while j < 16 {
            let mut k = 0;
            while k < 16 {
                let v: u8 = sbox[2 * i][j] + (sbox[2 * i + 1][k] << 4);
                let c: usize = j + (k << 4);
                out[i][c] = v;
                k += 1;
            }
            j += 1;
        }
        i += 1;
    }
    out
}

/// Trait for GOST 28147-89 cipher S-boxes
pub trait Sbox {
    /// S-Box name
    const NAME: &'static str;
    /// Unexpanded S-box
    const SBOX: SmallSbox;
}

/// Extension of the `Sbox` trait which provides expanded S-Box
/// and helper methods
pub(crate) trait SboxExt: Sbox {
    /// Expanded S-box
    const EXP_SBOX: ExpSbox = gen_exp_sbox(&Self::SBOX);

    /// Apply S-box and return result
    fn apply_sbox(a: u32) -> u32 {
        let mut v = 0;
        for i in 0..4 {
            let shift = 8 * i;
            let k = ((a & (0xffu32 << shift)) >> shift) as usize;
            v += (Self::EXP_SBOX[i][k] as u32) << shift;
        }
        v
    }

    /// Function `g` based on the S-box
    fn g(a: u32, k: u32) -> u32 {
        Self::apply_sbox(a.wrapping_add(k)).rotate_left(11)
    }
}

impl<T: Sbox> SboxExt for T {}

pub enum Tc26 {}

impl Sbox for Tc26 {
    const NAME: &'static str = "Tc26";
    const SBOX: SmallSbox = [
        [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
        [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
        [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
        [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
        [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
        [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
        [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
        [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
    ];
}

pub enum TestSbox {}

impl Sbox for TestSbox {
    const NAME: &'static str = "TestSbox";
    const SBOX: SmallSbox = [
        [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
    ];
}

pub enum CryptoProA {}

impl Sbox for CryptoProA {
    const NAME: &'static str = "CryptoProA";
    const SBOX: SmallSbox = [
        [9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5],
        [3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1],
        [14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9],
        [14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6],
        [11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6],
        [3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6],
        [1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14],
        [11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4],
    ];
}

pub enum CryptoProB {}

impl Sbox for CryptoProB {
    const NAME: &'static str = "CryptoProB";
    const SBOX: SmallSbox = [
        [8, 4, 11, 1, 3, 5, 0, 9, 2, 14, 10, 12, 13, 6, 7, 15],
        [0, 1, 2, 10, 4, 13, 5, 12, 9, 7, 3, 15, 11, 8, 6, 14],
        [14, 12, 0, 10, 9, 2, 13, 11, 7, 5, 8, 15, 3, 6, 1, 4],
        [7, 5, 0, 13, 11, 6, 1, 2, 3, 10, 12, 15, 4, 14, 9, 8],
        [2, 7, 12, 15, 9, 5, 10, 11, 1, 4, 0, 13, 6, 8, 14, 3],
        [8, 3, 2, 6, 4, 13, 14, 11, 12, 1, 7, 15, 10, 0, 9, 5],
        [5, 2, 10, 11, 9, 1, 12, 3, 7, 4, 13, 0, 6, 15, 8, 14],
        [0, 4, 11, 14, 8, 3, 7, 1, 10, 2, 9, 6, 15, 13, 5, 12],
    ];
}

pub enum CryptoProC {}

impl Sbox for CryptoProC {
    const NAME: &'static str = "CryptoProC";
    const SBOX: SmallSbox = [
        [1, 11, 12, 2, 9, 13, 0, 15, 4, 5, 8, 14, 10, 7, 6, 3],
        [0, 1, 7, 13, 11, 4, 5, 2, 8, 14, 15, 12, 9, 10, 6, 3],
        [8, 2, 5, 0, 4, 9, 15, 10, 3, 7, 12, 13, 6, 14, 1, 11],
        [3, 6, 0, 1, 5, 13, 10, 8, 11, 2, 9, 7, 14, 15, 12, 4],
        [8, 13, 11, 0, 4, 5, 1, 2, 9, 3, 12, 14, 6, 15, 10, 7],
        [12, 9, 11, 1, 8, 14, 2, 4, 7, 3, 6, 5, 10, 0, 15, 13],
        [10, 9, 6, 8, 13, 14, 2, 0, 15, 3, 5, 11, 4, 1, 12, 7],
        [7, 4, 0, 5, 10, 2, 15, 14, 12, 6, 1, 11, 13, 9, 3, 8],
    ];
}

pub enum CryptoProD {}

impl Sbox for CryptoProD {
    const NAME: &'static str = "CryptoProD";
    const SBOX: SmallSbox = [
        [10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15],
        [5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8],
        [7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13],
        [4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3],
        [7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5],
        [7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3],
        [13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11],
        [1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12],
    ];
}
