extern crate block_cipher_trait;
extern crate generic_array;

mod consts;

use block_cipher_trait::{Block, BlockCipher, BlockCipherFixKey};
use generic_array::GenericArray;
use generic_array::typenum::U8;

use consts::SBOXES;

#[derive(Copy, Clone)]
struct Des {
}

impl Des {
    fn apply_sboxes(
        &self,
        input: u64,
    ) -> u64 {
        let mut output: u64 = 0;
        for i in 0..8 {
            let sbox = SBOXES[i];
            let val = (input >> (i * 6)) & 0x3F;
            output |= (sbox[val as usize] as u64) << (i * 6);
        }

        output
    }

    fn apply_pbox(&self) {
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
