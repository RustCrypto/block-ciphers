use crate::{
    Block,
    riscv::rv64::{
        Block8, RoundKeys,
        utils::{AlignedBlock, AlignedParBlock},
    },
};
use cipher::inout::InOut;

#[inline]
#[target_feature(enable = "zkne")]
pub(super) fn encrypt1<const N: usize>(keys: &RoundKeys<N>, mut block1: InOut<'_, '_, Block>) {
    let mut block = AlignedBlock::load(block1.get_in());
    let ([rk_pairs @ .., last_rk_pair], [last_rk]) = keys.as_chunks::<2>() else {
        unreachable!("round keys failed pattern check");
    };
    for rk_pair in rk_pairs {
        block.encrypt(rk_pair);
    }
    block.encrypt_last(last_rk_pair);
    block.xor(last_rk);
    block.save(block1.get_out());
}

#[inline]
#[target_feature(enable = "zkne")]
pub(super) fn encrypt8<const N: usize>(keys: &RoundKeys<N>, mut block8: InOut<'_, '_, Block8>) {
    let mut block = AlignedParBlock::load(block8.get_in());
    let ([rk_pairs @ .., last_rk_pair], [last_rk]) = keys.as_chunks::<2>() else {
        unreachable!("round keys failed pattern check");
    };
    for rk_pair in rk_pairs {
        block.encrypt(rk_pair);
    }
    block.encrypt_last(last_rk_pair);
    block.xor(last_rk);
    block.save(block8.get_out());
}

#[inline]
#[target_feature(enable = "zknd")]
pub(super) fn decrypt1<const N: usize>(keys: &RoundKeys<N>, mut block1: InOut<'_, '_, Block>) {
    let mut block = AlignedBlock::load(block1.get_in());
    let ([last_rk_pair, rk_pairs @ ..], [last_rk]) = keys.as_chunks::<2>() else {
        unreachable!("round keys failed pattern check");
    };
    block.xor(last_rk);
    for rk_pair in rk_pairs.iter().rev() {
        block.decrypt(rk_pair);
    }
    block.decrypt_last(last_rk_pair);
    block.save(block1.get_out());
}

#[inline]
#[target_feature(enable = "zknd")]
pub(super) fn decrypt8<const N: usize>(keys: &RoundKeys<N>, mut block8: InOut<'_, '_, Block8>) {
    let mut block = AlignedParBlock::load(block8.get_in());
    let ([last_rk_pair, rk_pairs @ ..], [last_rk]) = keys.as_chunks::<2>() else {
        unreachable!("round keys failed pattern check");
    };
    block.xor(last_rk);
    for rk_pair in rk_pairs.iter().rev() {
        block.decrypt(rk_pair);
    }
    block.decrypt_last(last_rk_pair);
    block.save(block8.get_out());
}
