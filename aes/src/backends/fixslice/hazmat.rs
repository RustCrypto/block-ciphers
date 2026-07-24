use super::{BatchBlocks, NativeWord, State, Word, mix_columns::*, sbox::*, utils::*};
use crate::hazmat::{Block, Block8};
use cipher::typenum::Unsigned;

/// XOR the `src` block into the `dst` block in-place.
fn xor_in_place(dst: &mut Block, src: &Block) {
    for (a, b) in dst.iter_mut().zip(src.as_slice()) {
        *a ^= *b;
    }
}

#[inline]
fn inv_bitslice_one<W: Word>(block: &mut Block, state: &State<W>) {
    let out = W::inv_bitslice(state);
    block.copy_from_slice(out[0].as_slice());
}

fn cipher_round_generic<W: Word>(block: &mut Block, round_key: &Block) {
    let mut state = State::<W>::default();
    W::bitslice(&mut state, &broadcast::<W>(block.as_slice()));
    sub_bytes(&mut state);
    sub_bytes_nots(&mut state);
    shift_rows_1(&mut state);
    mix_columns_0(&mut state);
    inv_bitslice_one(block, &state);
    xor_in_place(block, round_key);
}

fn cipher_round_par_generic<W: Word>(blocks: &mut Block8, round_keys: &Block8) {
    let blocks_per_batch = <<W as Word>::Blocks>::USIZE;
    for (chunk, keys) in blocks
        .chunks_exact_mut(blocks_per_batch)
        .zip(round_keys.chunks_exact(blocks_per_batch))
    {
        let mut state = State::<W>::default();
        let mut batch = BatchBlocks::<W>::default();
        for (slot, blk) in batch.iter_mut().zip(chunk.iter()) {
            slot.copy_from_slice(blk.as_slice());
        }
        W::bitslice(&mut state, &batch);
        sub_bytes(&mut state);
        sub_bytes_nots(&mut state);
        shift_rows_1(&mut state);
        mix_columns_0(&mut state);
        let res = W::inv_bitslice(&state);

        for i in 0..blocks_per_batch {
            chunk[i] = res[i];
            xor_in_place(&mut chunk[i], &keys[i]);
        }
    }
}

fn equiv_inv_cipher_round_generic<W: Word>(block: &mut Block, round_key: &Block) {
    let mut state = State::<W>::default();
    W::bitslice(&mut state, &broadcast::<W>(block.as_slice()));
    sub_bytes_nots(&mut state);
    inv_sub_bytes(&mut state);
    inv_shift_rows_1(&mut state);
    inv_mix_columns_0(&mut state);
    inv_bitslice_one(block, &state);
    xor_in_place(block, round_key);
}

fn equiv_inv_cipher_round_par_generic<W: Word>(blocks: &mut Block8, round_keys: &Block8) {
    let blocks_per_batch = <<W as Word>::Blocks>::USIZE;
    for (chunk, keys) in blocks
        .chunks_exact_mut(blocks_per_batch)
        .zip(round_keys.chunks_exact(blocks_per_batch))
    {
        let mut state = State::<W>::default();
        let mut batch = BatchBlocks::<W>::default();
        for (slot, blk) in batch.iter_mut().zip(chunk.iter()) {
            slot.copy_from_slice(blk.as_slice());
        }
        W::bitslice(&mut state, &batch);
        sub_bytes_nots(&mut state);
        inv_sub_bytes(&mut state);
        inv_shift_rows_1(&mut state);
        inv_mix_columns_0(&mut state);
        let res = W::inv_bitslice(&state);

        for i in 0..blocks_per_batch {
            chunk[i] = res[i];
            xor_in_place(&mut chunk[i], &keys[i]);
        }
    }
}

fn mix_columns_generic<W: Word>(block: &mut Block) {
    let mut state = State::<W>::default();
    W::bitslice(&mut state, &broadcast::<W>(block.as_slice()));
    mix_columns_0(&mut state);
    inv_bitslice_one(block, &state);
}

fn inv_mix_columns_generic<W: Word>(block: &mut Block) {
    let mut state = State::<W>::default();
    W::bitslice(&mut state, &broadcast::<W>(block.as_slice()));
    inv_mix_columns_0(&mut state);
    inv_bitslice_one(block, &state);
}

/// AES cipher (encrypt) round function.
#[inline]
pub(crate) fn cipher_round(block: &mut Block, round_key: &Block) {
    cipher_round_generic::<NativeWord>(block, round_key)
}

/// AES cipher (encrypt) round function: parallel version.
#[inline]
pub(crate) fn cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    cipher_round_par_generic::<NativeWord>(blocks, round_keys)
}

/// AES cipher (encrypt) inverse round function.
#[inline]
pub(crate) fn equiv_inv_cipher_round(block: &mut Block, round_key: &Block) {
    equiv_inv_cipher_round_generic::<NativeWord>(block, round_key)
}

/// AES cipher (encrypt) inverse round function: parallel version.
#[inline]
pub(crate) fn equiv_inv_cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    equiv_inv_cipher_round_par_generic::<NativeWord>(blocks, round_keys)
}

/// AES mix columns function.
#[inline]
pub(crate) fn mix_columns(block: &mut Block) {
    mix_columns_generic::<NativeWord>(block)
}

/// AES inverse mix columns function.
#[inline]
pub(crate) fn inv_mix_columns(block: &mut Block) {
    inv_mix_columns_generic::<NativeWord>(block)
}
