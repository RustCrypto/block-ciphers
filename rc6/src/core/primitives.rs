use cipher::{
    generic_array::{ArrayLength, GenericArray},
    zeroize::DefaultIsZeroes,
};
use core::ops::Add;

pub trait Word: Default + Copy + From<u8> + Add<Output = Self> + DefaultIsZeroes + Default {
    type Bytes: ArrayLength<u8>;

    const ZERO: Self;
    const THREE: Self;
    const EIGHT: Self;

    const P: Self;
    const Q: Self;

    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;
    fn wrapping_mul(self, rhs: Self) -> Self;

    fn rotate_left(self, n: Self) -> Self;
    fn rotate_right(self, n: Self) -> Self;

    fn from_le_bytes(bytes: &GenericArray<u8, Self::Bytes>) -> Self;
    fn to_le_bytes(self) -> GenericArray<u8, Self::Bytes>;

    fn bitxor(self, other: Self) -> Self;
}
