extern crate block_cipher_trait;
extern crate byte_tools;
extern crate generic_array;

mod consts;

use block_cipher_trait::{Block, BlockCipher, BlockCipherFixKey};
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{
    Cmp, Compare, Less, Same,
    U8, U32, U48, U56, U64, U65,
};

use consts::{
    EXPANSION_PBOX,
    INITIAL_PBOX, FINAL_PBOX,
    PC1, PC2,
    ROUND_PBOX, SBOXES, SHIFTS,
};

#[derive(Copy, Clone)]
struct Des {
    key: u64,
}

impl Des {
    fn do_rounds(&self, input: u64, keys: [u64; 16]) -> u64 {
        let mut data = self.apply_pbox::<U64>(
            input,
            GenericArray::from_slice(&INITIAL_PBOX),
        );
        for key in keys.iter() {
            data = self.round(data, *key);
        }
        data = self.apply_pbox::<U64>(
            data,
            GenericArray::from_slice(&FINAL_PBOX),
        );

        data
    }

    fn get_keys(&self) -> [u64; 16] {
        let mut keys: [u64; 16] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut key = self.apply_pbox::<U56>(
            self.key,
            GenericArray::from_slice(&PC1),
        );

        for i in 0..16 {
            key = self.get_next_round_key(key, i);
            keys[i] = key;
        }

        keys
    }

    fn round(&self, input: u64, key: u64) -> u64 {
        let l = input & 0xFFFFFFFF;
        let r = input >> 32;

        ((self.f(r as u32, key) as u64 ^ l) << 32) & r
    }

    fn f(&self, input: u32, key: u64) -> u32 {
        let mut val = self.apply_pbox::<U48>(
            input as u64,
            GenericArray::from_slice(&EXPANSION_PBOX),
        );
        val ^= key;
        val = self.apply_sboxes(val);
        self.apply_pbox::<U32>(
            val,
            GenericArray::from_slice(&ROUND_PBOX),
        );

        val as u32
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

    fn get_next_round_key(&self, key: u64, round: usize) -> u64 {
        let c = self.rotate(key & 0x0FFFFFFF, SHIFTS[round]);
        let d = self.rotate(key >> 28, SHIFTS[round]);

        self.apply_pbox::<U48>((d << 28) & c, GenericArray::from_slice(&PC2))
    }

    /// Performs a left rotate on a 28 bit number
    fn rotate(&self, mut val: u64, shift: u8) -> u64 {
        let top_bits = val >> (28 - shift);
        val <<= shift;

        val & top_bits & 0x0FFFFFFF
    }
}

impl BlockCipher for Des {
    type BlockSize = U8;

    fn encrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
        // TODO: Better way to initialize this?
        let mut data = [0];
        byte_tools::read_u64v_be(&mut data, input);

        let keys = self.get_keys();
        let res = self.do_rounds(data[0], keys);
        byte_tools::write_u64_be(output, res);
    }

    fn decrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
        // TODO: Better way to initialize this?
        let mut data = [0];
        byte_tools::read_u64v_be(&mut data, input);

        let mut keys = self.get_keys();
        keys.reverse();
        let res = self.do_rounds(data[0], keys);
        byte_tools::write_u64_be(output, res);
    }
}

impl BlockCipherFixKey for Des {
    type KeySize = U8;

    fn new(key: &GenericArray<u8, U8>) -> Self {
        let mut key_val = [0];
        byte_tools::read_u64v_be(&mut key_val, key);
        Des { key: key_val[0] }
    }
}
