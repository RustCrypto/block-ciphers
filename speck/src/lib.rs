//! Pure Rust implementation of the [Speck] block cipher.
//!
//! [Speck]: https://en.wikipedia.org/wiki/Speck_(cipher)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/speck/0.0.1"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    consts::{U12, U16, U18, U24, U32, U4, U6, U8, U9},
    AlgorithmName, BlockCipher, Key, KeyInit, KeySizeUser,
};
use core::fmt;
use core::mem::size_of;

macro_rules! define_speck_impl {
    (
        $name:ident,
        $block_size:ty,
        $key_size:ty,
        $word_type:ty,
        $n:literal,
        $m:literal,
        $alpha:literal,
        $beta:literal,
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
            fn round_function(
                k: $word_type,
                mut x: $word_type,
                mut y: $word_type,
            ) -> ($word_type, $word_type) {
                x = $name::rotate_right(x, $alpha);
                x = <$word_type>::wrapping_add(x, y) & $mask;
                x = (x ^ k) & $mask;
                y = $name::rotate_left(y, $beta);
                y = (y ^ x) & $mask;
                (x, y)
            }

            #[inline]
            fn inverse_round_function(
                k: $word_type,
                mut x: $word_type,
                mut y: $word_type,
            ) -> ($word_type, $word_type) {
                y = (y ^ x) & $mask;
                y = $name::rotate_right(y, $beta);
                x = (x ^ k) & $mask;
                x = <$word_type>::wrapping_sub(x, y) & $mask;
                x = $name::rotate_left(x, $alpha);
                (x, y)
            }
        }

        impl BlockCipher for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            fn new(key: &Key<Self>) -> Self {
                let mut k = [0; $rounds];
                let mut l = [0; $m - 1 + $rounds - 1];
                k[0] = $name::from_be_bytes(&key[($m - 1) * ($n / 8)..($m) * ($n / 8)]);

                for i in 0..$m - 1 {
                    l[i] = $name::from_be_bytes(
                        &key[($m - 2 - i) * ($n / 8)..($m - 1 - i) * ($n / 8)]
                    );
                }

                for i in 0..($rounds - 1) {
                    let res = $name::round_function(i.try_into().unwrap(), l[i], k[i]);
                    l[i + $m - 1] = res.0;
                    k[i + 1] = res.1;
                }

                Self { k }
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

        cipher::impl_simple_block_encdec!($name, $block_size, cipher, block,
            encrypt: {
                let b = block.get_in();
                let mut x = $name::from_be_bytes(&b[0..($n / 8)]);
                let mut y = $name::from_be_bytes(&b[($n / 8)..2 * ($n / 8)]);
                for i in 0..$rounds {
                    let res = $name::round_function(cipher.k[i], x, y);
                    x = res.0;
                    y = res.1;
                }

                let b = block.get_out();
                b[0..($n / 8)].copy_from_slice(&$name::to_be_bytes(x));
                b[($n / 8)..2 * ($n / 8)].copy_from_slice(&$name::to_be_bytes(y));
            }
            decrypt: {
                let b = block.get_in();
                let mut x = $name::from_be_bytes(&b[0..($n / 8)]);
                let mut y = $name::from_be_bytes(&b[($n / 8)..2 * ($n / 8)]);
                for i in (0..$rounds).rev() {
                    let res = $name::inverse_round_function(cipher.k[i], x, y);
                    x = res.0;
                    y = res.1;
                }

                let b = block.get_out();
                b[0..($n / 8)].copy_from_slice(&$name::to_be_bytes(x));
                b[($n / 8)..2 * ($n / 8)].copy_from_slice(&$name::to_be_bytes(y));
            }
        );
    };
}

define_speck_impl!(
    Speck32_64,
    U4,
    U8,
    u16,
    16,
    4,
    7,
    2,
    0xFFFF,
    22,
    "Speck32/64"
);
define_speck_impl!(
    Speck48_72,
    U6,
    U9,
    u32,
    24,
    3,
    8,
    3,
    0xFFFFFF,
    22,
    "Speck48/72"
);
define_speck_impl!(
    Speck48_96,
    U6,
    U12,
    u32,
    24,
    4,
    8,
    3,
    0xFFFFFF,
    23,
    "Speck48/96"
);
define_speck_impl!(
    Speck64_96,
    U8,
    U12,
    u32,
    32,
    3,
    8,
    3,
    0xFFFFFFFF,
    26,
    "Speck64/96"
);
define_speck_impl!(
    Speck64_128,
    U8,
    U16,
    u32,
    32,
    4,
    8,
    3,
    0xFFFFFFFF,
    27,
    "Speck64/128"
);
define_speck_impl!(
    Speck96_96,
    U12,
    U12,
    u64,
    48,
    2,
    8,
    3,
    0xFFFFFFFFFFFF,
    28,
    "Speck96/96"
);
define_speck_impl!(
    Speck96_144,
    U12,
    U18,
    u64,
    48,
    3,
    8,
    3,
    0xFFFFFFFFFFFF,
    29,
    "Speck96/144"
);
define_speck_impl!(
    Speck128_128,
    U16,
    U16,
    u64,
    64,
    2,
    8,
    3,
    0xFFFFFFFFFFFFFFFF,
    32,
    "Speck128/128"
);
define_speck_impl!(
    Speck128_192,
    U16,
    U24,
    u64,
    64,
    3,
    8,
    3,
    0xFFFFFFFFFFFFFFFF,
    33,
    "Speck128/192"
);
define_speck_impl!(
    Speck128_256,
    U16,
    U32,
    u64,
    64,
    4,
    8,
    3,
    0xFFFFFFFFFFFFFFFF,
    34,
    "Speck128/256"
);
