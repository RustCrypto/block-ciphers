//! Pure Rust implementation of the [Simon] block cipher.
//!
//! [Simon]: https://en.wikipedia.org/wiki/Simon_(cipher)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut, Key,
    KeyInit, KeySizeUser, ParBlocksSizeUser, consts::*,
};
use core::{fmt, mem::size_of};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! define_simon_impl {
    (
        $name:ident,
        $block_size:ty,
        $key_size:ty,
        $word_type:ty,
        $n:literal,
        $m:literal,
        $z:literal,
        $mask:literal,
        $rounds:literal,
        $doc:expr $(,)?
    ) => {
        #[doc=$doc]
        #[doc = "block cipher"]
        #[derive(Clone)]
        pub struct $name {
            k: [$word_type; $rounds],
        }

        impl $name {
            #[inline]
            fn from_be_bytes(bytes: &[u8]) -> $word_type {
                let mut tmp = [0u8; size_of::<$word_type>()];
                let offset = size_of::<$word_type>() - $n / 8;
                tmp[offset..].copy_from_slice(bytes);
                <$word_type>::from_be_bytes(tmp)
            }

            #[inline]
            #[allow(clippy::wrong_self_convention)]
            fn to_be_bytes(word: $word_type) -> [u8; $n / 8] {
                let tmp = word.to_be_bytes();
                let offset = size_of::<$word_type>() - $n / 8;
                tmp[offset..].try_into().unwrap()
            }

            #[inline]
            fn rotate_right(x: $word_type, pos: $word_type) -> $word_type {
                // We can't use $word_type.rotate_right here because the word size might be different from the word type.
                (x >> pos) | (x << ($n - pos))
            }

            #[inline]
            fn rotate_left(x: $word_type, pos: $word_type) -> $word_type {
                // We can't use $word_type.rotate_left here because the word size might be different from the word type.
                (x << pos) | (x >> ($n - pos))
            }

            #[inline]
            fn f(x: $word_type) -> $word_type {
                ($name::rotate_left(x, 1) & $name::rotate_left(x, 8)) ^ $name::rotate_left(x, 2)
            }

            #[inline]
            fn round_function(
                k: $word_type,
                mut x: $word_type,
                mut y: $word_type,
            ) -> ($word_type, $word_type) {
                (x, y) = ((y ^ $name::f(x) ^ k) & $mask, x);
                (x, y)
            }

            #[inline]
            fn inverse_round_function(
                k: $word_type,
                mut x: $word_type,
                mut y: $word_type,
            ) -> ($word_type, $word_type) {
                (x, y) = (y, (x ^ $name::f(y) ^ k) & $mask);
                (x, y)
            }
        }

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            fn new(key: &Key<Self>) -> Self {
                let mut k = [0; $rounds];
                for i in 0..$m {
                    k[i] = $name::from_be_bytes(&key[($m - 1 - i) * ($n / 8)..($m - i) * ($n / 8)]);
                }

                for i in $m..$rounds {
                    let mut tmp = $name::rotate_right(k[i - 1], 3);
                    if $m == 4 {
                        tmp ^= k[i - 3];
                        tmp &= $mask;
                    }
                    tmp ^= $name::rotate_right(tmp, 1);
                    let lfsr_bit = <$word_type>::try_from(($z >> ((i - $m) % 62)) & 1).unwrap();
                    k[i] = (!k[i - $m] ^ tmp ^ lfsr_bit ^ 3) & $mask;
                }

                Self { k }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = $block_size;
        }

        impl ParBlocksSizeUser for $name {
            type ParBlocksSize = U1;
        }

        impl BlockCipherEncrypt for $name {
            #[inline]
            fn encrypt_with_backend(
                &self,
                f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(self)
            }
        }

        impl BlockCipherEncBackend for $name {
            #[inline]
            fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
                let b = block.get_in();
                let mut x = $name::from_be_bytes(&b[0..($n / 8)]);
                let mut y = $name::from_be_bytes(&b[($n / 8)..2 * ($n / 8)]);
                for i in 0..$rounds {
                    let res = $name::round_function(self.k[i], x, y);
                    x = res.0;
                    y = res.1;
                }

                let b = block.get_out();
                b[0..($n / 8)].copy_from_slice(&$name::to_be_bytes(x));
                b[($n / 8)..2 * ($n / 8)].copy_from_slice(&$name::to_be_bytes(y));
            }
        }

        impl BlockCipherDecrypt for $name {
            #[inline]
            fn decrypt_with_backend(
                &self,
                f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>,
            ) {
                f.call(self)
            }
        }

        impl BlockCipherDecBackend for $name {
            #[inline]
            fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
                let b = block.get_in();
                let mut x = $name::from_be_bytes(&b[0..($n / 8)]);
                let mut y = $name::from_be_bytes(&b[($n / 8)..2 * ($n / 8)]);
                for i in (0..$rounds).rev() {
                    let res = $name::inverse_round_function(self.k[i], x, y);
                    x = res.0;
                    y = res.1;
                }

                let b = block.get_out();
                b[0..($n / 8)].copy_from_slice(&$name::to_be_bytes(x));
                b[($n / 8)..2 * ($n / 8)].copy_from_slice(&$name::to_be_bytes(y));
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                self.k.zeroize();
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $name {}
    };
}

define_simon_impl!(
    Simon32_64,
    U4,
    U8,
    u16,
    16,
    4,
    0xD9C3522FB386A45Fu64,
    0xFFFF,
    32,
    "Simon32/64"
);
define_simon_impl!(
    Simon48_72,
    U6,
    U9,
    u32,
    24,
    3,
    0xD9C3522FB386A45Fu64,
    0xFFFFFF,
    36,
    "Simon48/72"
);
define_simon_impl!(
    Simon48_96,
    U6,
    U12,
    u32,
    24,
    4,
    0x56864FB8AD0C9F71u64,
    0xFFFFFF,
    36,
    "Simon48/96"
);
define_simon_impl!(
    Simon64_96,
    U8,
    U12,
    u32,
    32,
    3,
    0x7369F885192C0EF5u64,
    0xFFFFFFFF,
    42,
    "Simon64/96"
);
define_simon_impl!(
    Simon64_128,
    U8,
    U16,
    u32,
    32,
    4,
    0xFC2CE51207A635DBu64,
    0xFFFFFFFF,
    44,
    "Simon64/128"
);
define_simon_impl!(
    Simon96_96,
    U12,
    U12,
    u64,
    48,
    2,
    0x7369F885192C0EF5u64,
    0xFFFFFFFFFFFF,
    52,
    "Simon96/96"
);
define_simon_impl!(
    Simon96_144,
    U12,
    U18,
    u64,
    48,
    3,
    0xFC2CE51207A635DBu64,
    0xFFFFFFFFFFFF,
    54,
    "Simon96/144"
);
define_simon_impl!(
    Simon128_128,
    U16,
    U16,
    u64,
    64,
    2,
    0x7369F885192C0EF5u64,
    0xFFFFFFFFFFFFFFFF,
    68,
    "Simon128/128"
);
define_simon_impl!(
    Simon128_192,
    U16,
    U24,
    u64,
    64,
    3,
    0xFC2CE51207A635DBu64,
    0xFFFFFFFFFFFFFFFF,
    69,
    "Simon128/192"
);
define_simon_impl!(
    Simon128_256,
    U16,
    U32,
    u64,
    64,
    4,
    0xFDC94C3A046D678Bu64,
    0xFFFFFFFFFFFFFFFF,
    72,
    "Simon128/256"
);
