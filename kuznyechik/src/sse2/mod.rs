//! SSE2-based implementation based on <https://github.com/aprelev/lg15>

use crate::{BlockSize, Key};
use cipher::{
    BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncClosure, BlockCipherEncrypt,
};

mod backends;

use backends::{DecBackend, EncBackend, RoundKeys, expand_enc_keys, inv_enc_keys};

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
        f.call(&EncBackend(&self.keys.enc));
    }
}

impl BlockCipherDecrypt for crate::Kuznyechik {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = BlockSize>) {
        f.call(&DecBackend(&self.keys.dec));
    }
}

impl BlockCipherEncrypt for crate::KuznyechikEnc {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = BlockSize>) {
        f.call(&EncBackend(&self.keys.0));
    }
}

impl BlockCipherDecrypt for crate::KuznyechikDec {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = BlockSize>) {
        f.call(&DecBackend(&self.keys.0));
    }
}
