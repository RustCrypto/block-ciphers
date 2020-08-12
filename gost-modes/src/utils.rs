#[inline(always)]
pub(crate) fn xor(buf1: &mut [u8], buf2: &[u8]) {
    debug_assert_eq!(buf1.len(), buf2.len());
    for (a, b) in buf1.iter_mut().zip(buf2) {
        *a ^= *b;
    }
}

#[inline(always)]
pub(crate) fn xor_set1(buf1: &mut [u8], buf2: &mut [u8]) {
    debug_assert_eq!(buf1.len(), buf2.len());
    for (a, b) in buf1.iter_mut().zip(buf2) {
        let t = *a ^ *b;
        *a = t;
        *b = t;
    }
}

#[inline(always)]
pub(crate) fn xor_set2(buf1: &mut [u8], buf2: &mut [u8]) {
    debug_assert_eq!(buf1.len(), buf2.len());
    for (a, b) in buf1.iter_mut().zip(buf2) {
        let t = *a;
        *a ^= *b;
        *b = t;
    }
}
