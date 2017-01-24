extern crate block_cipher_trait;
extern crate generic_array;

mod consts;

use block_cipher_trait::{Block, BlockCipher, BlockCipherFixKey};
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{Cmp, Compare, Less, Same, U8, U65};

use consts::SBOXES;

#[derive(Copy, Clone)]
struct Des {
}

impl Des {
    /// Applies all eight sboxes to the input
    fn apply_sboxes(&self, input: u64) -> u64 {
        let mut output: u64 = 0;
        for i in 0..8 {
            let sbox = SBOXES[i];
            let val = (input >> (i * 6)) & 0x3F;
            output |= (sbox[val as usize] as u64) << (i * 6);
        }

        output
    }

    /// Applies the given pbox to the input
    fn apply_pbox<N>(&self, input: u64, pbox: GenericArray<u8, N>) -> u64
        where N: ArrayLength<u8> + Cmp<U65>,
              Compare<N, U65>: Same<Less>,
    {
        let len = N::to_usize();
        let mut output = 0;
        for i in 0..len {
            output |= ((1 << pbox[i]) & input) << i;
        }
        output
    }
}

impl BlockCipher for Des {
    type BlockSize = U8;

    fn encrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {

    }

    fn decrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
        unimplemented!()
    }
}

impl BlockCipherFixKey for Des {
    type KeySize = U8;

    fn new(key: &GenericArray<u8, U8>) -> Self {
        unimplemented!()
    }
}
