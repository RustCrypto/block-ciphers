//! Pure Rust implementation of the [Advanced Encryption Standard][AES]
//! (AES, a.k.a. Rijndael).
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! # Supported backends
//! This crate provides multiple backends including a portable pure Rust
//! backend as well as ones based on CPU intrinsics.
//!
//! By default, it performs runtime detection of CPU intrinsics and uses them
//! if they are available.
//!
//! ## "soft" portable backend
//! As a baseline implementation, this crate provides a constant-time pure Rust
//! implementation based on [fixslicing], a more advanced form of bitslicing
//! implemented entirely in terms of bitwise arithmetic with no use of any
//! lookup tables or data-dependent branches.
//!
//! Enabling the `aes_compact` configuration flag will reduce the code size of this
//! backend at the cost of decreased performance (using a modified form of
//! the fixslicing technique called "semi-fixslicing").
//!
//! ## ARMv8 intrinsics (Rust 1.61+)
//! On `aarch64` targets including `aarch64-apple-darwin` (Apple M1) and Linux
//! targets such as `aarch64-unknown-linux-gnu` and `aarch64-unknown-linux-musl`,
//! support for using AES intrinsics provided by the ARMv8 Cryptography Extensions.
//!
//! On Linux and macOS, support for ARMv8 AES intrinsics is autodetected at
//! runtime. On other platforms the `aes` target feature must be enabled via
//! RUSTFLAGS.
//!
//! ## `x86`/`x86_64` intrinsics (AES-NI and VAES)
//! By default this crate uses runtime detection on `i686`/`x86_64` targets
//! in order to determine if AES-NI and VAES are available, and if they are
//! not, it will fallback to using a constant-time software implementation.
//!
//! Passing `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3` explicitly at
//! compile-time will override runtime detection and ensure that AES-NI is
//! used or passing `RUSTFLAGS=-Ctarget-feature=+aes,+avx512f,+ssse3,+vaes`
//! will ensure that AESNI and VAES are always used.
//!
//! Note: Enabling VAES256 or VAES512 still requires specifying `--cfg
//! aes_backend = "avx256"` or `--cfg aes_backend = "avx512"` explicitly.
//!
//! Programs built in this manner will crash with an illegal instruction on
//! CPUs which do not have AES-NI and VAES enabled.
//!
//! Note: runtime detection is not possible on SGX targets. Please use the
//! aforementioned `RUSTFLAGS` to leverage AES-NI and VAES on these targets.
//!
//! # Examples
//! ```
//! use aes::Aes128;
//! use aes::cipher::{Array, BlockCipherEncrypt, BlockCipherDecrypt, KeyInit};
//!
//! let key = Array::from([0u8; 16]);
//! let mut block = Array::from([42u8; 16]);
//!
//! // Initialize cipher
//! let cipher = Aes128::new(&key);
//!
//! let block_copy = block;
//!
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//!
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//!
//! // Implementation supports parallel block processing. Number of blocks
//! // processed in parallel depends in general on hardware capabilities.
//! // This is achieved by instruction-level parallelism (ILP) on a single
//! // CPU core, which is different from multi-threaded parallelism.
//! let mut blocks = [block; 100];
//! cipher.encrypt_blocks(&mut blocks);
//!
//! for block in blocks.iter_mut() {
//!     cipher.decrypt_block(block);
//!     assert_eq!(block, &block_copy);
//! }
//!
//! // `decrypt_blocks` also supports parallel block processing.
//! cipher.decrypt_blocks(&mut blocks);
//!
//! for block in blocks.iter_mut() {
//!     cipher.encrypt_block(block);
//!     assert_eq!(block, &block_copy);
//! }
//! ```
//!
//! For implementation of block cipher modes of operation see
//! [`block-modes`] repository.
//!
//! # Configuration Flags
//!
//! You can modify crate using the following configuration flags:
//!
//! - `aes_backend`: explicitly select one of the following backends:
//!   - `soft`: force software backend
//!   - `avx256`: force AVX2 backend
//!   - `avx512`: force AVX-512 backend
//! - `aes_backend_soft`: modify software backend:
//!   - `compact`: use compact implementation (less performant, but results in a smaller binary)
//!
//! It can be enabled using `RUSTFLAGS` environment variable
//! (e.g. `RUSTFLAGS='--cfg aes_backend="soft"'`) or by modifying `.cargo/config`.
//!
//! [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
//! [fixslicing]: https://eprint.iacr.org/2020/1123.pdf
//! [AES-NI]: https://en.wikipedia.org/wiki/AES_instruction_set
//! [`block-modes`]: https://github.com/RustCrypto/block-modes/

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

#[cfg(feature = "hazmat")]
pub mod hazmat;

mod backends;

use cipher::{
    AlgorithmName, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncClosure,
    BlockCipherEncrypt, BlockSizeUser, Key, KeyInit, KeySizeUser,
    array::Array,
    consts::{U16, U24, U32},
};
use core::fmt;
use cpubits::cfg_if;

/// 128-bit AES block
pub type Block = Array<u8, U16>;

// Define token used for target feature detection
cfg_if! {
    if #[cfg(aes_backend = "soft")] {
        type Token = ();
    } else if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
        cpufeatures::new!(features_aes, "aes");
        #[cfg(any(aes_backend = "avx256", aes_backend = "avx512"))]
        cpufeatures::new!(features_vaes256, "vaes");
        #[cfg(aes_backend = "avx512")]
        cpufeatures::new!(features_vaes512, "avx512f", "vaes");

        #[derive(Clone, Copy)]
        struct Token {
            aes: features_aes::InitToken,
            #[cfg(any(aes_backend = "avx256", aes_backend = "avx512"))]
            vaes256: features_vaes256::InitToken,
            #[cfg(aes_backend = "avx512")]
            vaes512: features_vaes512::InitToken,
        }

        impl Default for Token {
            fn default() -> Self {
                Token {
                    aes: features_aes::InitToken::init(),
                    #[cfg(any(aes_backend = "avx256", aes_backend = "avx512"))]
                    vaes256: features_vaes256::InitToken::init(),
                    #[cfg(aes_backend = "avx512")]
                    vaes512: features_vaes512::InitToken::init(),
                }
            }
        }

    } else if #[cfg(target_arch = "aarch64")] {
        cpufeatures::new!(features_aes, "aes");

        #[derive(Clone, Copy)]
        struct Token {
            aes: features_aes::InitToken,
        }

        impl Default for Token {
            fn default() -> Self {
                Token {
                    aes: features_aes::InitToken::init(),
                }
            }
        }
    } else {
        type Token = ();
    }
}

/// Returns `true` if this crate can use AES hardware acceleration on the current machine.
///
/// This is a runtime check performed on the machine where the code is executed.
///
/// ```
/// if aes::hardware_accelerated() {
///     println!("AES hardware acceleration is available");
/// } else {
///     println!("WARNING: using software fallback for AES");
/// }
/// ```
pub fn hardware_accelerated() -> bool {
    cfg_if! {
        if #[cfg(aes_backend = "soft")] {
            false
        } else if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
            features_aes::get()
        } else if #[cfg(target_arch = "aarch64")] {
            features_aes::get()
        } else {
            false
        }
    }
}

macro_rules! impl_key_init {
    ($name:ident, $soft_name:ident, $key_size:ty, $inner:path) => {
        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                type Inner = $inner;
                let token = Token::default();
                let key = &key.0;

                #[cfg(not(aes_backend = "soft"))]
                cfg_if! {
                    if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
                        if token.aes.get() {
                            // SAFETY: we confirmed that the required target features are available
                            let aes = unsafe { backends::x86_aes::$name::new(key) };
                            let inner = Inner { aes };
                            return Self { inner, token };
                        }
                    } else if #[cfg(target_arch = "aarch64")] {
                        if token.aes.get() {
                            // SAFETY: we confirmed that the required target features are available
                            let aes = unsafe { backends::aarch64_aes::$name::new(key) };
                            let inner = Inner { aes };
                            return Self { inner, token };
                        }
                    }
                }

                let soft = backends::soft::$soft_name::new(key);
                let inner = Inner { soft };
                Self { inner, token }
            }
        }
    };
}

macro_rules! impl_encrypt {
    ($ty_name:ident, $name:ident) => {
        impl BlockCipherEncrypt for $ty_name {
            #[inline]
            fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
                #[cfg(not(aes_backend = "soft"))]
                cfg_if! {
                    if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
                        #[cfg(aes_backend = "avx512")]
                        if self.token.vaes512.get() {
                            // SAFETY: we access correct union variant
                            let enc_rk = unsafe { &self.inner.aes.enc_rk };
                            // SAFETY: we confirmed that the required target features are available
                            unsafe { backends::x86_vaes512::$name::encrypt(enc_rk, f) };
                            return;
                        }

                        #[cfg(any(aes_backend = "avx256", aes_backend = "avx512"))]
                        if self.token.vaes256.get() {
                            // SAFETY: we access correct union variant
                            let enc_rk = unsafe { &self.inner.aes.enc_rk };
                            // SAFETY: we confirmed that the required target features are available
                            unsafe { backends::x86_vaes256::$name::encrypt(enc_rk, f) };
                            return;
                        }

                        if self.token.aes.get() {
                            // SAFETY: we access correct union variant
                            let aes = unsafe { &self.inner.aes };
                            // SAFETY: we confirmed that the required target features are available
                            unsafe { aes.encrypt(f) };
                            return;
                        }
                    } else if #[cfg(target_arch = "aarch64")] {
                        if self.token.aes.get() {
                            // SAFETY: we access correct union variant
                            let aes = unsafe { &self.inner.aes };
                            // SAFETY: we confirmed that the required target features are available
                            unsafe { aes.encrypt(f) };
                            return;
                        }
                    }
                }

                // SAFETY: we access correct union variant
                let backend = unsafe { &self.inner.soft };
                f.call(backend);
            }
        }
    };
}

macro_rules! impl_decrypt {
    ($name:ident, $alg_name:ident) => {
        impl BlockCipherDecrypt for $name {
            #[inline]
            fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = U16>) {
                #[cfg(not(aes_backend = "soft"))]
                cfg_if! {
                    if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
                        #[cfg(aes_backend = "avx512")]
                        if self.token.vaes512.get() {
                            // SAFETY: we access correct union variant
                            let dec_rk = unsafe { &self.inner.aes.dec_rk };
                            // SAFETY: we confirmed that the required target features are available
                            unsafe { backends::x86_vaes512::$alg_name::decrypt(dec_rk, f) };
                            return;
                        }

                        #[cfg(any(aes_backend = "avx256", aes_backend = "avx512"))]
                        if self.token.vaes256.get() {
                            // SAFETY: we access correct union variant
                            let dec_rk = unsafe { &self.inner.aes.dec_rk };
                            // SAFETY: we confirmed that the required target features are available
                            unsafe { backends::x86_vaes256::$alg_name::decrypt(dec_rk, f) };
                            return;
                        }

                        if self.token.aes.get() {
                            // SAFETY: we access correct union variant
                            let backend = unsafe { &self.inner.aes };
                            // SAFETY: we confirmed that the required target features are available
                            unsafe { backend.decrypt(f) };
                            return;
                        }
                    } else if #[cfg(target_arch = "aarch64")] {
                        if self.token.aes.get() {
                            // SAFETY: we access correct union variant
                            let backend = unsafe { &self.inner.aes };
                            // SAFETY: we confirmed that the required target features are available
                            unsafe { backend.decrypt(f) };
                            return;
                        }
                    }
                }

                // SAFETY: we access correct union variant
                let backend = unsafe { &self.inner.soft };
                f.call(backend);
            }
        }
    };
}

macro_rules! impl_from_enc {
    ($name:ident, $name_enc:ident, $inner:path, $into_fn:ident) => {
        impl From<&$name_enc> for $name {
            #[inline]
            fn from(enc: &$name_enc) -> $name {
                type Inner = $inner;

                let token = enc.token;

                #[cfg(not(aes_backend = "soft"))]
                cfg_if! {
                    if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
                        if token.aes.get() {
                            // SAFETY: we access correct union variant
                            let aes_enc = unsafe { &enc.inner.aes };
                            // SAFETY: we confirmed that the required target features are available
                            let aes = unsafe { aes_enc.$into_fn() };
                            let inner = Inner { aes };
                            return Self { inner, token };
                        }
                    } else if #[cfg(target_arch = "aarch64")] {
                        if token.aes.get() {
                            // SAFETY: we access correct union variant
                            let aes_enc = unsafe { &enc.inner.aes };
                            // SAFETY: we confirmed that the required target features are available
                            let aes = unsafe { aes_enc.$into_fn() };
                            let inner = Inner { aes };
                            return Self { inner, token };
                        }
                    }
                }

                // SAFETY: we access correct union variant
                let soft = unsafe { enc.inner.soft };
                let inner = Inner { soft };
                Self { inner, token }
            }
        }

        impl From<$name_enc> for $name {
            #[inline]
            fn from(enc: $name_enc) -> $name {
                Self::from(&enc)
            }
        }
    };
}

macro_rules! common_impls {
    ($name:ident) => {
        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl Drop for $name {
            #[inline]
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                unsafe {
                    zeroize::zeroize_flat_type(self);
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name {}
    };
}

macro_rules! define_aes_impl {
    (
        name = $name:ident,
        name_enc = $name_enc:ident,
        name_dec = $name_dec:ident,
        module = $module:tt,
        key_size = $key_size:ident,
        doc = $doc:expr,
    ) => {
        mod $module {
            use crate::backends;

            #[derive(Copy, Clone)]
            pub(super) union Inner {
                #[cfg(all(
                    any(target_arch = "x86_64", target_arch = "x86"),
                    not(aes_backend = "soft"),
                ))]
                pub(super) aes: backends::x86_aes::$name,
                #[cfg(all(target_arch = "aarch64", not(aes_backend = "soft")))]
                pub(super) aes: backends::aarch64_aes::$name,
                pub(super) soft: backends::soft::$name,
            }

            #[derive(Copy, Clone)]
            pub(super) union InnerEnc {
                #[cfg(all(
                    any(target_arch = "x86_64", target_arch = "x86"),
                    not(aes_backend = "soft"),
                ))]
                pub(super) aes: backends::x86_aes::$name_enc,
                #[cfg(all(target_arch = "aarch64", not(aes_backend = "soft")))]
                pub(super) aes: backends::aarch64_aes::$name_enc,
                pub(super) soft: backends::soft::$name,
            }

            #[derive(Copy, Clone)]
            pub(super) union InnerDec {
                #[cfg(all(
                    any(target_arch = "x86_64", target_arch = "x86"),
                    not(aes_backend = "soft"),
                ))]
                pub(super) aes: backends::x86_aes::$name_dec,
                #[cfg(all(target_arch = "aarch64", not(aes_backend = "soft")))]
                pub(super) aes: backends::aarch64_aes::$name_dec,
                pub(super) soft: backends::soft::$name,
            }
        }

        #[doc=$doc]
        #[doc = "block cipher"]
        #[derive(Clone)]
        pub struct $name {
            inner: $module::Inner,
            #[allow(dead_code, reason = "this field is not used on software-only targets")]
            token: Token,
        }

        common_impls!($name);
        impl_key_init!($name, $name, $key_size, $module::Inner);
        impl_encrypt!($name, $name);
        impl_decrypt!($name, $name);
        impl_from_enc!($name, $name_enc, $module::Inner, as_encdec);

        #[doc=$doc]
        #[doc = "block cipher (encrypt-only)"]
        #[derive(Clone)]
        pub struct $name_enc {
            inner: $module::InnerEnc,
            #[allow(dead_code, reason = "this field is not used on software-only targets")]
            token: Token,
        }

        common_impls!($name_enc);
        impl_key_init!($name_enc, $name, $key_size, $module::InnerEnc);
        impl_encrypt!($name_enc, $name);

        #[doc=$doc]
        #[doc = "block cipher (decrypt-only)"]
        #[derive(Clone)]
        pub struct $name_dec {
            inner: $module::InnerDec,
            #[allow(dead_code, reason = "this field is not used on software-only targets")]
            token: Token,
        }

        common_impls!($name_dec);
        impl_key_init!($name_dec, $name, $key_size, $module::InnerDec);
        impl_decrypt!($name_dec, $name);
        impl_from_enc!($name_dec, $name_enc, $module::InnerDec, as_dec);
    };
}

define_aes_impl!(
    name = Aes128,
    name_enc = Aes128Enc,
    name_dec = Aes128Dec,
    module = aes128,
    key_size = U16,
    doc = "AES-128",
);
define_aes_impl!(
    name = Aes192,
    name_enc = Aes192Enc,
    name_dec = Aes192Dec,
    module = aes192,
    key_size = U24,
    doc = "AES-192",
);
define_aes_impl!(
    name = Aes256,
    name_enc = Aes256Enc,
    name_dec = Aes256Dec,
    module = aes256,
    key_size = U32,
    doc = "AES-256",
);
