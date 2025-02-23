#[inline]
pub fn f0(x: u8) -> u8 {
    x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(7)
}

#[inline]
pub fn f1(x: u8) -> u8 {
    x.rotate_left(3) ^ x.rotate_left(4) ^ x.rotate_left(6)
}
