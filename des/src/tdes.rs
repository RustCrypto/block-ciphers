use super::BlockCipher;
use des::{gen_keys, Des};

use byteorder::{BE, ByteOrder};
use generic_array::GenericArray;
use generic_array::typenum::{U1, U16, U24, U8};

#[derive(Copy, Clone)]
pub struct TdesEde3 {
    d1: Des,
    d2: Des,
    d3: Des,
}

#[derive(Copy, Clone)]
pub struct TdesEee3 {
    d1: Des,
    d2: Des,
    d3: Des,
}

#[derive(Copy, Clone)]
pub struct TdesEde2 {
    d1: Des,
    d2: Des,
}

#[derive(Copy, Clone)]
pub struct TdesEee2 {
    d1: Des,
    d2: Des,
}

impl BlockCipher for TdesEde3 {
    type KeySize = U24;
    type BlockSize = U8;
    type ParBlocks = U1;

    fn new(key: &GenericArray<u8, U24>) -> Self {
        let d1 = Des {
            keys: gen_keys(BE::read_u64(&key[0..8])),
        };
        let d2 = Des {
            keys: gen_keys(BE::read_u64(&key[8..16])),
        };
        let d3 = Des {
            keys: gen_keys(BE::read_u64(&key[16..24])),
        };
        Self { d1, d2, d3 }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut data = BE::read_u64(block);

        data = self.d1.encrypt(data);
        data = self.d2.decrypt(data);
        data = self.d3.encrypt(data);

        BE::write_u64(block, data);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut data = BE::read_u64(block);

        data = self.d3.decrypt(data);
        data = self.d2.encrypt(data);
        data = self.d1.decrypt(data);

        BE::write_u64(block, data);
    }
}

impl BlockCipher for TdesEee3 {
    type KeySize = U24;
    type BlockSize = U8;
    type ParBlocks = U1;

    fn new(key: &GenericArray<u8, U24>) -> Self {
        let d1 = Des {
            keys: gen_keys(BE::read_u64(&key[0..8])),
        };
        let d2 = Des {
            keys: gen_keys(BE::read_u64(&key[8..16])),
        };
        let d3 = Des {
            keys: gen_keys(BE::read_u64(&key[16..24])),
        };
        Self { d1, d2, d3 }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut data = BE::read_u64(block);

        data = self.d1.encrypt(data);
        data = self.d2.encrypt(data);
        data = self.d3.encrypt(data);

        BE::write_u64(block, data);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut data = BE::read_u64(block);

        data = self.d3.decrypt(data);
        data = self.d2.decrypt(data);
        data = self.d1.decrypt(data);

        BE::write_u64(block, data);
    }
}

impl BlockCipher for TdesEde2 {
    type KeySize = U16;
    type BlockSize = U8;
    type ParBlocks = U1;

    fn new(key: &GenericArray<u8, U16>) -> Self {
        let d1 = Des {
            keys: gen_keys(BE::read_u64(&key[0..8])),
        };
        let d2 = Des {
            keys: gen_keys(BE::read_u64(&key[8..16])),
        };
        Self { d1, d2 }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut data = BE::read_u64(block);

        data = self.d1.encrypt(data);
        data = self.d2.decrypt(data);
        data = self.d1.encrypt(data);

        BE::write_u64(block, data);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut data = BE::read_u64(block);

        data = self.d1.decrypt(data);
        data = self.d2.encrypt(data);
        data = self.d1.decrypt(data);

        BE::write_u64(block, data);
    }
}

impl BlockCipher for TdesEee2 {
    type KeySize = U16;
    type BlockSize = U8;
    type ParBlocks = U1;

    fn new(key: &GenericArray<u8, U16>) -> Self {
        let d1 = Des {
            keys: gen_keys(BE::read_u64(&key[0..8])),
        };
        let d2 = Des {
            keys: gen_keys(BE::read_u64(&key[8..16])),
        };
        Self { d1, d2 }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut data = BE::read_u64(block);

        data = self.d1.encrypt(data);
        data = self.d2.encrypt(data);
        data = self.d1.encrypt(data);

        BE::write_u64(block, data);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut data = BE::read_u64(block);

        data = self.d1.decrypt(data);
        data = self.d2.decrypt(data);
        data = self.d1.decrypt(data);

        BE::write_u64(block, data);
    }
}

impl_opaque_debug!(TdesEde3);
impl_opaque_debug!(TdesEee3);
impl_opaque_debug!(TdesEde2);
impl_opaque_debug!(TdesEee2);
