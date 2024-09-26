use crate::{BlockSize, Key};
use cipher::{
    BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncClosure, BlockCipherEncrypt,
};

mod backends;

use backends::{expand_enc_keys, inv_enc_keys, DecBackend, EncBackend, RoundKeys};

#[derive(Clone)]
pub(crate) struct EncDecKeys {
    enc: RoundKeys,
    dec: RoundKeys,
}
#[derive(Clone)]
pub(crate) struct EncKeys(RoundKeys);
#[derive(Clone)]
pub(crate) struct DecKeys(RoundKeys);

impl EncKeys {
    pub fn new(key: &Key) -> Self {
        Self(expand_enc_keys(key))
    }
}

impl From<EncKeys> for EncDecKeys {
    fn from(enc: EncKeys) -> Self {
        Self {
            dec: inv_enc_keys(&enc.0),
            enc: enc.0,
        }
    }
}

impl From<EncKeys> for DecKeys {
    fn from(enc: EncKeys) -> Self {
        Self(inv_enc_keys(&enc.0))
    }
}

impl BlockCipherEncrypt for crate::Kuznyechik {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = BlockSize>) {
        f.call(&mut EncBackend(&self.keys.enc));
    }
}

impl BlockCipherDecrypt for crate::Kuznyechik {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = BlockSize>) {
        f.call(&mut DecBackend(&self.keys.dec));
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
