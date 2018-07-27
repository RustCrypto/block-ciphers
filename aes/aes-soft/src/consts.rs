use simd::u32x4;

pub const U32X4_0: u32x4 = u32x4(0, 0, 0, 0);
pub const U32X4_1: u32x4 =
    u32x4(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff);

// This array is not accessed in any key-dependant way, so there are no timing problems inherent in
// using it.
pub static RCON: [u32; 10] =
    [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
