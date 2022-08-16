// This implementation is based on the
// 32-bit word oriented C implementation https://github.com/aadomn/gift/tree/master/crypto_bc/gift128/opt32 from https://github.com/aadomn/gift

use cipher::{consts::U16, BlockCipher, Key, KeyInit, KeySizeUser};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    consts::GIFT_RC,
    key_schedule::{
        key_double_update_1, key_double_update_2, key_double_update_3, key_double_update_4,
        key_triple_update_0, key_triple_update_1, key_triple_update_2, key_triple_update_3,
        key_triple_update_4, key_update, rearrange_rkey_0, rearrange_rkey_1, rearrange_rkey_2,
        rearrange_rkey_3,
    },
    primitives::{
        inv_quintuple_round, packing, quintuple_round, swapmovesingle, u32big, unpacking,
    },
};

impl Gift128 {
    #[inline]
    fn precompute_rkeys(key: &[u8]) -> Self {
        let mut rkey = [0u32; 80];
        rkey[0] = u32big(&(key[12..16]));
        rkey[1] = u32big(&(key[4..8]));
        rkey[2] = u32big(&(key[8..12]));
        rkey[3] = u32big(&(key[0..4]));

        for i in (0..16).step_by(2) {
            rkey[i + 4] = rkey[i + 1];
            rkey[i + 5] = key_update(&rkey[i]);
        }

        for i in (0..20).step_by(10) {
            rkey[i] = rearrange_rkey_0(&rkey[i]);
            rkey[i + 1] = rearrange_rkey_0(&rkey[i + 1]);
            rkey[i + 2] = rearrange_rkey_1(&rkey[i + 2]);
            rkey[i + 3] = rearrange_rkey_1(&rkey[i + 3]);
            rkey[i + 4] = rearrange_rkey_2(&rkey[i + 4]);
            rkey[i + 5] = rearrange_rkey_2(&rkey[i + 5]);
            rkey[i + 6] = rearrange_rkey_3(&rkey[i + 6]);
            rkey[i + 7] = rearrange_rkey_3(&rkey[i + 7]);
        }

        for i in (20..80).step_by(10) {
            rkey[i] = rkey[i - 19];
            rkey[i + 1] = key_triple_update_0(&rkey[i - 20]);
            rkey[i + 2] = key_double_update_1(&rkey[i - 17]);
            rkey[i + 3] = key_triple_update_1(&rkey[i - 18]);
            rkey[i + 4] = key_double_update_2(&rkey[i - 15]);
            rkey[i + 5] = key_triple_update_2(&rkey[i - 16]);
            rkey[i + 6] = key_double_update_3(&rkey[i - 13]);
            rkey[i + 7] = key_triple_update_3(&rkey[i - 14]);
            rkey[i + 8] = key_double_update_4(&rkey[i - 11]);
            rkey[i + 9] = key_triple_update_4(&rkey[i - 12]);
            swapmovesingle(&mut rkey[i], 0x00003333, 16);
            swapmovesingle(&mut rkey[i], 0x55554444, 1);
            swapmovesingle(&mut rkey[i + 1], 0x55551100, 1);
        }

        Self { k: rkey }
    }
}

impl KeyInit for Gift128 {
    fn new(key: &Key<Self>) -> Self {
        Self::precompute_rkeys(key[0..16].try_into().unwrap())
    }
}

macro_rules! impl_gift {
    ($name:ident, $subkey_size:literal, $key_size:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            /// Subkeys
            k: [u32; $subkey_size],
        }

        impl BlockCipher for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl Drop for $name {
            fn drop(&mut self) {
                self.k.zeroize();
            }
        }

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl ZeroizeOnDrop for $name {}

        cipher::impl_simple_block_encdec!(
            $name, U16, cipher, block,
            encrypt: {
                let b = block.get_in();
                let mut state = [0u32; 4];
                packing(&mut state, b);
                for i in (0..40).step_by(5) {
                    quintuple_round(&mut state, &cipher.k[i*2..], &GIFT_RC[i..]);
                }
                unpacking(&state, block.get_out());
            }
            decrypt: {
                let b = block.get_in();
                let mut state = [0u32; 4];
                packing(&mut state, b);
                let mut i: usize = 35;
                while i > 0 {
                    inv_quintuple_round(&mut state, &cipher.k[i*2..], &GIFT_RC[i..]);
                    i -= 5;
                }
                inv_quintuple_round(&mut state, &cipher.k[i*2..], &GIFT_RC[i..]);
                unpacking(&state, block.get_out());
            }
        );
    };
}

impl_gift!(Gift128, 80, U16, "Gift-128 block cipher instance.");
