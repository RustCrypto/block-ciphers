use core::ops::{BitAnd, BitOr, BitXor, Shl, Shr};

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct u32x4(pub u32, pub u32, pub u32, pub u32);

impl BitXor for u32x4 {
    type Output = u32x4;

    #[inline(always)]
    fn bitxor(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0 ^ rhs.0,
            self.1 ^ rhs.1,
            self.2 ^ rhs.2,
            self.3 ^ rhs.3,
        )
    }
}

impl BitAnd for u32x4 {
    type Output = u32x4;

    #[inline(always)]
    fn bitand(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0 & rhs.0,
            self.1 & rhs.1,
            self.2 & rhs.2,
            self.3 & rhs.3,
        )
    }
}

impl BitOr for u32x4 {
    type Output = u32x4;

    #[inline(always)]
    fn bitor(self, rhs: u32x4) -> u32x4 {
        u32x4(
            self.0 | rhs.0,
            self.1 | rhs.1,
            self.2 | rhs.2,
            self.3 | rhs.3,
        )
    }
}

impl Shl<u32> for u32x4 {
    type Output = u32x4;

    #[inline(always)]
    fn shl(self, shift: u32) -> u32x4 {
        u32x4(
            self.0 << shift,
            self.1 << shift,
            self.2 << shift,
            self.3 << shift,
        )
    }
}

impl Shr<u32> for u32x4 {
    type Output = u32x4;

    #[inline(always)]
    fn shr(self, shift: u32) -> u32x4 {
        u32x4(
            self.0 >> shift,
            self.1 >> shift,
            self.2 >> shift,
            self.3 >> shift,
        )
    }
}
