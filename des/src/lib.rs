extern crate block_cipher_trait;
extern crate byte_tools;
extern crate generic_array;

mod consts;

use block_cipher_trait::{Block, BlockCipher, BlockCipherFixKey};
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{Cmp, Compare, Less, Same, U8, U64, U65};

use consts::{INITIAL_PBOX, FINAL_PBOX, SBOXES};

#[derive(Copy, Clone)]
struct Des {
}

impl Des {
    fn round(&self, input: u64) -> u64 {
        let l = input & 0xFFFFFFFF;
        let r = input >> 32;

        ((self.f(r as u32) as u64 ^ l) << 32) & r
    }

    fn f(&self, input: u32) -> u32 {
        0
    }

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
        let rounds = 16;
        // TODO: Better way to initialize this
        let mut data = [0];
        byte_tools::read_u64v_be(&mut data, input);
        let mut data = data[0];

        data = self.apply_pbox::<U64>(
            data,
            GenericArray::from_slice(&INITIAL_PBOX),
        );
        for _ in 0..rounds {
            data = self.round(data);
        }
        data = self.apply_pbox::<U64>(
            data,
            GenericArray::from_slice(&FINAL_PBOX),
        );
        byte_tools::write_u64_be(output, data);
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
