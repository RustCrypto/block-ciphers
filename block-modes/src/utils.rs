use block_cipher_trait::generic_array::GenericArray;

pub(crate) type ParBlocks<B, P> = GenericArray<GenericArray<u8, B>, P>;

#[inline(always)]
pub fn xor(buf: &mut [u8], key: &[u8]) {
    assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) {
        *a ^= *b;
    }
}
