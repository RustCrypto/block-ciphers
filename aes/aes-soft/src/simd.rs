use core::ops::{BitAnd, BitOr, BitXor};

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
