use crate::{BlockSize, Key, KeySize};
use cipher::{
    AlgorithmName, BlockCipher, BlockCipherDecrypt, BlockCipherEncrypt, BlockClosure,
    BlockSizeUser, KeyInit, KeySizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod backends;
#[path = "../fused_tables/consts.rs"]
mod consts;

use backends::{expand_enc_keys, inv_enc_keys, DecBackend, EncBackend, RoundKeys};

/// Kuznyechik (GOST R 34.12-2015) block cipher
#[derive(Clone)]
pub struct Kuznyechik {
    enc_keys: RoundKeys,
    dec_keys: RoundKeys,
}

impl BlockCipher for Kuznyechik {}

impl KeySizeUser for Kuznyechik {
    type KeySize = KeySize;
}

impl BlockSizeUser for Kuznyechik {
    type BlockSize = BlockSize;
}

impl KeyInit for Kuznyechik {
    fn new(key: &Key) -> Self {
        let enc_keys = expand_enc_keys(key);
        let dec_keys = inv_enc_keys(&enc_keys);
        Self { dec_keys, enc_keys }
    }
}

impl From<KuznyechikEnc> for Kuznyechik {
    #[inline]
    fn from(enc: KuznyechikEnc) -> Kuznyechik {
        Self {
            dec_keys: inv_enc_keys(&enc.keys),
            enc_keys: enc.keys,
        }
    }
}

impl From<&KuznyechikEnc> for Kuznyechik {
    #[inline]
    fn from(enc: &KuznyechikEnc) -> Kuznyechik {
        Self {
            dec_keys: inv_enc_keys(&enc.keys),
            enc_keys: enc.keys,
        }
    }
}

impl BlockCipherEncrypt for Kuznyechik {
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = BlockSize>) {
        f.call(&mut EncBackend(&self.enc_keys));
    }
}

impl BlockCipherDecrypt for Kuznyechik {
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = BlockSize>) {
        f.call(&mut DecBackend(&self.dec_keys));
    }
}

impl fmt::Debug for Kuznyechik {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Kuznyechik { ... }")
    }
}

impl AlgorithmName for Kuznyechik {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kuznyechik")
    }
}

impl Drop for Kuznyechik {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.enc_keys.zeroize();
            self.dec_keys.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Kuznyechik {}

/// Kuznyechik (GOST R 34.12-2015) block cipher (encrypt-only)
#[derive(Clone)]
pub struct KuznyechikEnc {
    keys: RoundKeys,
}

impl BlockCipher for KuznyechikEnc {}

impl KeySizeUser for KuznyechikEnc {
    type KeySize = KeySize;
}

impl BlockSizeUser for KuznyechikEnc {
    type BlockSize = BlockSize;
}

impl KeyInit for KuznyechikEnc {
    fn new(key: &Key) -> Self {
        let keys = expand_enc_keys(key);
        Self { keys }
    }
}

impl BlockCipherEncrypt for KuznyechikEnc {
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = BlockSize>) {
        f.call(&mut EncBackend(&self.keys));
    }
}

impl fmt::Debug for KuznyechikEnc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KuznyechikEnc { ... }")
    }
}

impl AlgorithmName for KuznyechikEnc {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kuznyechik")
    }
}
impl Drop for KuznyechikEnc {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.keys.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for KuznyechikEnc {}

/// Kuznyechik (GOST R 34.12-2015) block cipher (decrypt-only)
#[derive(Clone)]
pub struct KuznyechikDec {
    keys: RoundKeys,
}

impl BlockCipher for KuznyechikDec {}

impl KeySizeUser for KuznyechikDec {
    type KeySize = KeySize;
}

impl BlockSizeUser for KuznyechikDec {
    type BlockSize = BlockSize;
}

impl KeyInit for KuznyechikDec {
    fn new(key: &Key) -> Self {
        let enc_keys = expand_enc_keys(key);
        let keys = inv_enc_keys(&enc_keys);
        Self { keys }
    }
}

impl From<KuznyechikEnc> for KuznyechikDec {
    #[inline]
    fn from(enc: KuznyechikEnc) -> KuznyechikDec {
        let keys = inv_enc_keys(&enc.keys);
        Self { keys }
    }
}

impl From<&KuznyechikEnc> for KuznyechikDec {
    #[inline]
    fn from(enc: &KuznyechikEnc) -> KuznyechikDec {
        let keys = inv_enc_keys(&enc.keys);
        Self { keys }
    }
}

impl BlockCipherDecrypt for KuznyechikDec {
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = BlockSize>) {
        f.call(&mut DecBackend(&self.keys));
    }
}

impl fmt::Debug for KuznyechikDec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KuznyechikDec { ... }")
    }
}

impl AlgorithmName for KuznyechikDec {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kuznyechik")
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for KuznyechikDec {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.keys.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for KuznyechikDec {}
