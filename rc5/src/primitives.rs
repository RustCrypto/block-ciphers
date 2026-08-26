use core::ops::{Add, BitXor, Mul};

use cipher::{
    array::{Array, ArraySize},
    typenum::{Diff, Prod, Quot, Sum, U1, U2, U4, U8, U16},
};

pub type BlockSize<W> = Prod<<W as Word>::Bytes, U2>;
pub type Block<W> = Array<u8, BlockSize<W>>;

pub type Key<B> = Array<u8, B>;

pub type ExpandedKeyTable<W, R> = Array<W, ExpandedKeyTableSize<R>>;
pub type ExpandedKeyTableSize<R> = Prod<Sum<R, U1>, U2>;

pub type KeyAsWords<W, B> = Array<W, KeyAsWordsSize<W, B>>;
pub type KeyAsWordsSize<W, B> = Quot<Diff<Sum<B, <W as Word>::Bytes>, U1>, <W as Word>::Bytes>;

pub trait Word
where
    Self: Default + Copy + From<u8> + Add<Output = Self> + Default + private::Sealed,
    BlockSize<Self>: ArraySize,
{
    type Bytes: ArraySize + Mul<U2>;

    const ZERO: Self;
    const THREE: Self;
    const EIGHT: Self;

    const P: Self;
    const Q: Self;

    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;

    fn rotate_left(self, n: Self) -> Self;
    fn rotate_right(self, n: Self) -> Self;

    fn from_le_bytes(bytes: &Array<u8, Self::Bytes>) -> Self;
    fn to_le_bytes(self) -> Array<u8, Self::Bytes>;

    fn bitxor(self, other: Self) -> Self;
}

mod private {
    #[cfg(feature = "zeroize")]
    pub trait Sealed: cipher::zeroize::DefaultIsZeroes {}
    #[cfg(not(feature = "zeroize"))]
    pub trait Sealed {}

    impl Sealed for u8 {}
    impl Sealed for u16 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
    impl Sealed for u128 {}
}

impl Word for u8 {
    type Bytes = U1;

    const ZERO: Self = 0;
    const THREE: Self = 3;
    const EIGHT: Self = 8;

    const P: Self = 0xb7;
    const Q: Self = 0x9f;

    #[inline(always)]
    fn wrapping_add(self, rhs: Self) -> Self {
        u8::wrapping_add(self, rhs)
    }
    #[inline(always)]
    fn wrapping_sub(self, rhs: Self) -> Self {
        u8::wrapping_sub(self, rhs)
    }

    #[inline(always)]
    fn rotate_left(self, n: Self) -> Self {
        u8::rotate_left(self, n as u32)
    }

    #[inline(always)]
    fn rotate_right(self, n: Self) -> Self {
        u8::rotate_right(self, n as u32)
    }

    #[inline(always)]
    fn from_le_bytes(bytes: &Array<u8, Self::Bytes>) -> Self {
        u8::from_le_bytes(bytes.as_slice().try_into().unwrap())
    }

    #[inline(always)]
    fn to_le_bytes(self) -> Array<u8, Self::Bytes> {
        u8::to_le_bytes(self).into()
    }

    #[inline(always)]
    fn bitxor(self, other: Self) -> Self {
        <u8 as BitXor>::bitxor(self, other)
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
    fn from_le_bytes(bytes: &Array<u8, Self::Bytes>) -> Self {
        u16::from_le_bytes(bytes.as_slice().try_into().unwrap())
    }

    #[inline(always)]
    fn to_le_bytes(self) -> Array<u8, Self::Bytes> {
        u16::to_le_bytes(self).into()
    }

    #[inline(always)]
    fn bitxor(self, other: Self) -> Self {
        <u16 as BitXor>::bitxor(self, other)
    }
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
    fn from_le_bytes(bytes: &Array<u8, Self::Bytes>) -> Self {
        u32::from_le_bytes(bytes.as_slice().try_into().unwrap())
    }

    #[inline(always)]
    fn to_le_bytes(self) -> Array<u8, Self::Bytes> {
        u32::to_le_bytes(self).into()
    }

    #[inline(always)]
    fn bitxor(self, other: Self) -> Self {
        <u32 as BitXor>::bitxor(self, other)
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
    fn from_le_bytes(bytes: &Array<u8, Self::Bytes>) -> Self {
        u64::from_le_bytes(bytes.as_slice().try_into().unwrap())
    }

    #[inline(always)]
    fn to_le_bytes(self) -> Array<u8, Self::Bytes> {
        u64::to_le_bytes(self).into()
    }

    #[inline(always)]
    fn bitxor(self, other: Self) -> Self {
        <u64 as BitXor>::bitxor(self, other)
    }
}

impl Word for u128 {
    type Bytes = U16;

    const ZERO: Self = 0;
    const THREE: Self = 3;
    const EIGHT: Self = 8;

    const P: Self = 0xb7e151628aed2a6abf7158809cf4f3c7;
    const Q: Self = 0x9e3779b97f4a7c15f39cc0605cedc835;

    #[inline(always)]
    fn wrapping_add(self, rhs: Self) -> Self {
        u128::wrapping_add(self, rhs)
    }
    #[inline(always)]
    fn wrapping_sub(self, rhs: Self) -> Self {
        u128::wrapping_sub(self, rhs)
    }

    #[inline(always)]
    fn rotate_left(self, n: Self) -> Self {
        let size = Self::BITS;
        u128::rotate_left(self, (n % size as u128) as u32)
    }

    #[inline(always)]
    fn rotate_right(self, n: Self) -> Self {
        let size = Self::BITS;
        u128::rotate_right(self, (n % size as u128) as u32)
    }

    #[inline(always)]
    fn from_le_bytes(bytes: &Array<u8, Self::Bytes>) -> Self {
        u128::from_le_bytes(bytes.as_slice().try_into().unwrap())
    }

    #[inline(always)]
    fn to_le_bytes(self) -> Array<u8, Self::Bytes> {
        u128::to_le_bytes(self).into()
    }

    #[inline(always)]
    fn bitxor(self, other: Self) -> Self {
        <u128 as BitXor>::bitxor(self, other)
    }
}
