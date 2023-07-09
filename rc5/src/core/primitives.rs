use core::ops::{Add, BitXor};

use cipher::{
    generic_array::{ArrayLength, GenericArray},
    typenum::{Diff, Prod, Quot, Sum, U1, U2, U4, U8},
    zeroize::DefaultIsZeroes,
};

pub type BlockSize<W> = Prod<<W as Word>::Bytes, U2>;
pub type Block<W> = GenericArray<u8, BlockSize<W>>;

pub type Key<B> = GenericArray<u8, B>;

pub type ExpandedKeyTable<W, R> = GenericArray<W, ExpandedKeyTableSize<R>>;
pub type ExpandedKeyTableSize<R> = Prod<Sum<R, U1>, U2>;

pub type KeyAsWords<W, B> = GenericArray<W, KeyAsWordsSize<W, B>>;
pub type KeyAsWordsSize<W, B> = Quot<Diff<Sum<B, <W as Word>::Bytes>, U1>, <W as Word>::Bytes>;

pub trait Word:
    Default + Copy + From<u8> + Add<Output = Self> + DefaultIsZeroes + private::Sealed
{
    type Bytes: ArrayLength<u8>;

    const ZERO: Self;
    const THREE: Self;
    const EIGHT: Self;

    const P: Self;
    const Q: Self;

    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;

    fn rotate_left(self, n: Self) -> Self;
    fn rotate_right(self, n: Self) -> Self;

    fn from_le_bytes(bytes: &GenericArray<u8, Self::Bytes>) -> Self;
    fn to_le_bytes(self) -> GenericArray<u8, Self::Bytes>;

    fn bitxor(self, other: Self) -> Self;
}

mod private {
    pub trait Sealed {}

    impl Sealed for u32 {}
    impl Sealed for u16 {}
    impl Sealed for u64 {}
}

impl Word for u32 {
    type Bytes = U4;

    const ZERO: Self = 0;
    const THREE: Self = 3;
    const EIGHT: Self = 8;

    const P: Self = 0xb7e15163;
    const Q: Self = 0x9e3779b9;

    #[inline(always)]
    fn wrapping_add(self, rhs: Self) -> Self {
        u32::wrapping_add(self, rhs)
    }
    #[inline(always)]
    fn wrapping_sub(self, rhs: Self) -> Self {
        u32::wrapping_sub(self, rhs)
    }

    #[inline(always)]
    fn rotate_left(self, n: Self) -> Self {
        u32::rotate_left(self, n)
    }

    #[inline(always)]
    fn rotate_right(self, n: Self) -> Self {
        u32::rotate_right(self, n)
    }

    #[inline(always)]
    fn from_le_bytes(bytes: &GenericArray<u8, Self::Bytes>) -> Self {
        u32::from_le_bytes(bytes.as_slice().try_into().unwrap())
    }

    #[inline(always)]
    fn to_le_bytes(self) -> GenericArray<u8, Self::Bytes> {
        u32::to_le_bytes(self).into()
    }

    #[inline(always)]
    fn bitxor(self, other: Self) -> Self {
        <u32 as BitXor>::bitxor(self, other)
    }
}

impl Word for u16 {
    type Bytes = U2;

    const ZERO: Self = 0;
    const THREE: Self = 3;
    const EIGHT: Self = 8;

    const P: Self = 0xb7e1;
    const Q: Self = 0x9e37;

    #[inline(always)]
    fn wrapping_add(self, rhs: Self) -> Self {
        u16::wrapping_add(self, rhs)
    }
    #[inline(always)]
    fn wrapping_sub(self, rhs: Self) -> Self {
        u16::wrapping_sub(self, rhs)
    }

    #[inline(always)]
    fn rotate_left(self, n: Self) -> Self {
        u16::rotate_left(self, n as u32)
    }

    #[inline(always)]
    fn rotate_right(self, n: Self) -> Self {
        u16::rotate_right(self, n as u32)
    }

    #[inline(always)]
    fn from_le_bytes(bytes: &GenericArray<u8, Self::Bytes>) -> Self {
        u16::from_le_bytes(bytes.as_slice().try_into().unwrap())
    }

    #[inline(always)]
    fn to_le_bytes(self) -> GenericArray<u8, Self::Bytes> {
        u16::to_le_bytes(self).into()
    }

    #[inline(always)]
    fn bitxor(self, other: Self) -> Self {
        <u16 as BitXor>::bitxor(self, other)
    }
}

impl Word for u64 {
    type Bytes = U8;

    const ZERO: Self = 0;
    const THREE: Self = 3;
    const EIGHT: Self = 8;

    const P: Self = 0xb7e151628aed2a6b;
    const Q: Self = 0x9e3779b97f4a7c15;

    #[inline(always)]
    fn wrapping_add(self, rhs: Self) -> Self {
        u64::wrapping_add(self, rhs)
    }
    #[inline(always)]
    fn wrapping_sub(self, rhs: Self) -> Self {
        u64::wrapping_sub(self, rhs)
    }

    #[inline(always)]
    fn rotate_left(self, n: Self) -> Self {
        let size = Self::BITS;
        u64::rotate_left(self, (n % size as u64) as u32)
    }

    #[inline(always)]
    fn rotate_right(self, n: Self) -> Self {
        let size = Self::BITS;
        u64::rotate_right(self, (n % size as u64) as u32)
    }

    #[inline(always)]
    fn from_le_bytes(bytes: &GenericArray<u8, Self::Bytes>) -> Self {
        u64::from_le_bytes(bytes.as_slice().try_into().unwrap())
    }

    #[inline(always)]
    fn to_le_bytes(self) -> GenericArray<u8, Self::Bytes> {
        u64::to_le_bytes(self).into()
    }

    #[inline(always)]
    fn bitxor(self, other: Self) -> Self {
        <u64 as BitXor>::bitxor(self, other)
    }
}
