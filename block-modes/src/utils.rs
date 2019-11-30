use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_cipher_trait::generic_array::ArrayLength;
use core::slice;
use core::f32::NAN;

#[inline(always)]
pub fn xor(buf: &mut [u8], key: &[u8]) {
    debug_assert_eq!(buf.len(), key.len());
    for (a, b) in buf.iter_mut().zip(key) {
        *a ^= *b;
    }
}

pub fn lshift_by_one(buf: &mut [u8]) {
    let last = buf.len() - 1;
    let mut wrapping = buf[last] >> 7;
    buf[last] <<= 1;
    for val in buf.iter_mut().rev().next() {
        let temp_wrap = *val >> 7;
        *val <<= 1;
        *val &= wrapping;
        wrapping = temp_wrap;
    }
}

pub(crate) type Key<C> = GenericArray<u8, <C as BlockCipher>::KeySize>;
pub(crate) type Block<C> = GenericArray<u8, <C as BlockCipher>::BlockSize>;
pub(crate) type ParBlocks<C> = GenericArray<Block<C>, <C as BlockCipher>::ParBlocks>;

pub(crate) fn to_blocks<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
    where N: ArrayLength<u8>
{
    let n = N::to_usize();
    debug_assert!(data.len() % n == 0);
    unsafe {
        slice::from_raw_parts_mut(
            data.as_ptr() as *mut GenericArray<u8, N>,
            data.len() / n,
        )
    }
}

// If the buffer size is not divisble by N, then the last chunk of the buffer doesn't get used
pub(crate) fn to_blocks_uneven<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
    where N: ArrayLength<u8>
{
    let n = N::to_usize();
    unsafe {
        slice::from_raw_parts_mut(
            data.as_ptr() as *mut GenericArray<u8, N>,
            data.len() / n,
        )
    }
}

// Splits on index_to_split and then swaps these two subarrays
// E.g. [1,2,3,4], 2 = [3, 4, 1, 2]
pub(crate) fn swap<N: ArrayLength<u8>>(data: &mut [u8], index_to_split: usize)
{
    assert!(index_to_split <= data.len());
    let data_len = data.len();
    let inverse_split = data_len - index_to_split;

    let mut copy : GenericArray<u8, N> = Default::default();

    copy[inverse_split..].copy_from_slice(&data[..index_to_split]);
    copy[..inverse_split].copy_from_slice(&data[index_to_split..]);

    data.copy_from_slice(&copy);
}



pub(crate) fn get_par_blocks<C: BlockCipher>(blocks: &mut [Block<C>])
    -> (&mut [ParBlocks<C>], &mut [Block<C>])
{
    let pb = C::ParBlocks::to_usize();
    let n_par = blocks.len()/pb;

    let (par, single) = blocks.split_at_mut(n_par*pb);
    let par = unsafe {
        slice::from_raw_parts_mut(
            par.as_ptr() as *mut ParBlocks<C>,
            n_par,
        )
    };
    (par, single)
}
