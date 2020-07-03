#[inline(always)]
pub(crate) fn xor(buf: &mut [u8], key: &[u8]) {
    debug_assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) {
        *a ^= *b;
    }
}

#[inline(always)]
pub(crate) fn xor2(buf1: &mut [u8], buf2: &mut [u8]) {
    debug_assert_eq!(buf1.len(), buf2.len());
    for (a, b) in buf1.iter_mut().zip(buf2.iter_mut()) {
        let t = *a ^ *b;
        *a = t;
        *b = t;
    }
}
