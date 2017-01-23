extern crate block_cipher_trait;
extern crate generic_array;

use block_cipher_trait::{Block, BlockCipher, BlockCipherFixKey};
use generic_array::GenericArray;
use generic_array::typenum::U8;

#[derive(Copy, Clone)]
struct Des {
}

impl Des {
}

impl BlockCipher for Des {
    type BlockSize = U8;

    fn encrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
        unimplemented!()
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
