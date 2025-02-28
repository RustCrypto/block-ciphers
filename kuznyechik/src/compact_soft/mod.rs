use crate::{BlockSize, Key};
use cipher::{
    BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncClosure, BlockCipherEncrypt,
};

mod backends;

use backends::{DecBackend, EncBackend, RoundKeys, expand};

#[derive(Clone)]
pub(crate) struct EncDecKeys(RoundKeys);
#[derive(Clone)]
pub(crate) struct EncKeys(RoundKeys);
#[derive(Clone)]
pub(crate) struct DecKeys(RoundKeys);

impl From<EncKeys> for EncDecKeys {
    fn from(enc: EncKeys) -> Self {
        Self(enc.0)
    }
}

impl From<EncKeys> for DecKeys {
    fn from(enc: EncKeys) -> Self {
        Self(enc.0)
    }
}

impl EncKeys {
    pub fn new(key: &Key) -> Self {
        Self(expand(key))
    }
}

impl BlockCipherEncrypt for crate::Kuznyechik {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = BlockSize>) {
        f.call(&mut EncBackend(&self.keys.0));
    }
}

impl BlockCipherDecrypt for crate::Kuznyechik {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = BlockSize>) {
        f.call(&mut DecBackend(&self.keys.0));
    }
}

impl BlockCipherEncrypt for crate::KuznyechikEnc {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = BlockSize>) {
        f.call(&mut EncBackend(&self.keys.0));
    }
}

impl BlockCipherDecrypt for crate::KuznyechikDec {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = BlockSize>) {
        f.call(&mut DecBackend(&self.keys.0));
    }
}
