#[cfg(test)]
use core::mem;
#[cfg(test)]
use coresimd::vendor::__m128i;

use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U8, U16};

pub type Block128 = GenericArray<u8, U16>;
pub type Block128x8 = GenericArray<GenericArray<u8, U16>, U8>;

#[cfg(test)]
pub(crate) fn check(a: &[__m128i], b: &[[u64; 2]]) {
    for (v1, v2) in a.iter().zip(b) {
        let t1: [u64; 2] = unsafe { mem::transmute(*v1) };
        let t2 = [v2[0].to_be(), v2[1].to_be()];
        assert_eq!(t1, t2);
    }
}
