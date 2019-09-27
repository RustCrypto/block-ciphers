#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! [HCTR](http://delta.cs.cinvestav.mx/~debrup/hctr.pdf): A Variable-Input-Length Enciphering
//! Mode.
//!
//! > HCTR turns an n-bit blockcipher into a tweakable blockcipher that supports arbitrary
//! > variable input length which is no less than n bits. The tweak length of HCTR is fixed and
//! > can be zero.
//!
//! This `Hctr` implementation is generic over the `BlockCipher` and `UniversalHash` functions,
//! such that the `BlockSize` of the `BlockCipher` is equal to the `OutputSize` of the
//! `UniversalHash`, and that the `UniversalHash` meets the additional constraints outlined in
//! the HCTR paper. Additionally, the payload must be at least as large as the `BlockSize` of the
//! provided `BlockCipher`.
//!
//! The tweak length may be variable if the AXU supports it, such as Polyval.
//!
//! ## Unstable
//!
//! There is currently no TweakableBlockCipher trait for HCTR to implement, thus its interface
//! is unstable until one exists.
//!
//! ## Recommendations
//!
//! If the optional, and default, features "aes" and "polyval" are enabled; the recommended
//! HCTR instantiation is available as `Aes128HctrPolyval`.
//!
//! If your target hardware supports accelerating either or both AES and Carryless Multiplication,
//! make sure to enable the respective CPU target features for the best performance on your
//! machine.
//!
//! `RUSTFLAGS="-Ctarget-cpu=native -Ctarget-feature=+aes,+sse2" cargo bench`
//!
//! ```rust
//! # #[cfg(all(feature = "aes", feature = "polyval"))]
//! # {
//! use hctr::Aes128HctrPolyval as Hctr;
//! # let secret_key = Default::default();
//!
//! let hctr = Hctr::new(secret_key);
//! let mut buf = *b"Hello world! This message must be at least `BlockSize` large.";
//! hctr.seal_in_place(&mut buf, b"a variable length byte string as the tweak.");
//! hctr.open_in_place(&mut buf, b"a variable length byte string as the tweak.");
//! assert_eq!(&buf[..], &b"Hello world! This message must be at least `BlockSize` large."[..]);
//! # }
//! ```

use block_cipher_trait::{
    generic_array::{
        typenum::{Sum, Unsigned, U16},
        ArrayLength, GenericArray,
    },
    BlockCipher,
};
use ctr::{stream_cipher::SyncStreamCipher, Ctr128};
use universal_hash::UniversalHash;

#[cfg(feature = "aes")]
use aes::Aes128;
#[cfg(feature = "polyval")]
use polyval::Polyval;

#[derive(Clone)]
/// See crate level documentation.
pub struct Hctr<C, H> {
    cipher: C,
    hasher: H,
}

#[cfg(all(feature = "aes", feature = "polyval"))]
/// HCTR instantiated using `Aes128` and `Polyval`. The recommended instantiation. Requires the
/// default features "aes" and "polyval".
pub type Aes128HctrPolyval = Hctr<Aes128, Polyval>;

fn xor_in_place(a: &mut [u8], b: &[u8]) {
    assert_eq!(a.len(), b.len());

    for (a, b) in a.iter_mut().zip(b) {
        *a ^= *b;
    }
}

/// A wide strong pseudorandom permutation
pub trait WideSPRP {
    /// How large the key must be
    type KeySize: ArrayLength<u8>;

    /// Create a new wide-SPRP instance.
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;
    /// Encrypt a message in-place with a tweak.
    fn seal_in_place(&self, buf: &mut [u8], tweak: &[u8]);
    /// Decrypt a message in-place with a tweak.
    fn open_in_place(&self, buf: &mut [u8], tweak: &[u8]);

    /// Enc/decrypt multiple Wide SPRP layers with independent tweaks. This is especially
    /// useful for onion routers and mixnets.
    fn process_layers(states: &[(&Self, bool, &[u8])], buf: &mut [u8]) {
        for (cipher, inverse, tweak) in states {
            if *inverse {
                cipher.open_in_place(buf, tweak);
            } else {
                cipher.seal_in_place(buf, tweak);
            }
        }
    }
}

impl<C, H> WideSPRP for Hctr<C, H>
where
    C: BlockCipher<BlockSize = U16> + Clone,
    C::ParBlocks: ArrayLength<GenericArray<u8, C::BlockSize>>,
    C::KeySize: core::ops::Add<H::KeySize>,
    Sum<C::KeySize, H::KeySize>: ArrayLength<u8>,
    Ctr128<C>: SyncStreamCipher,
    H: UniversalHash<OutputSize = C::BlockSize>,
{
    type KeySize = Sum<C::KeySize, H::KeySize>;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let (a, b) = key.split_at(C::KeySize::to_usize());
        Hctr {
            cipher: C::new(GenericArray::from_slice(a)),
            hasher: H::new(GenericArray::from_slice(b)),
        }
    }

    fn seal_in_place(&self, buf: &mut [u8], tweak: &[u8]) {
        Self::process_layers(&[(self, false, tweak)], buf);
    }

    fn open_in_place(&self, buf: &mut [u8], tweak: &[u8]) {
        Self::process_layers(&[(self, true, tweak)], buf);
    }

    fn process_layers(states: &[(&Self, bool, &[u8])], buf: &mut [u8]) {
        assert!(
            buf.len() >= C::BlockSize::to_usize(),
            "message must be at least as large as the BlockCipher::BlockSize."
        );
        let mut states = states.into_iter();

        let (l, r) = buf.split_at_mut(C::BlockSize::to_usize());

        let mut curr = states.next();
        let mut next = states.next();

        if let Some((hctr1, _, tweak1)) = curr {
            // phase 1 (curr): L ^= H(R, T)
            let mut hasher1 = hctr1.hasher.clone();
            hasher1.update_padded(r);
            hasher1.update_padded(tweak1);
            xor_in_place(l, &hasher1.result_reset().into_bytes());

            while let Some((hctr1, inverse, tweak1)) = curr.take() {
                // phase 2a (curr): L' = E(L)
                let mut internal_nonce = GenericArray::clone_from_slice(l);

                if *inverse {
                    hctr1.cipher.decrypt_block(GenericArray::from_mut_slice(l));
                } else {
                    hctr1.cipher.encrypt_block(GenericArray::from_mut_slice(l));
                }

                // phase 2b (curr): K = L ^ L'
                xor_in_place(&mut *internal_nonce, l);

                // phase 2c (curr): R = Ctr(K, R)
                Ctr128::from_cipher(hctr1.cipher.clone(), &internal_nonce)
                    .apply_keystream(r);

                // phase 3 (curr): L ^= H(R, T)
                // phase 1 (next): L ^= H(R, T)
                if let Some((hctr2, _, tweak2)) = next {
                    let mut hasher2 = hctr2.hasher.clone();
                    for chunk in r.chunks_mut(
                        C::BlockSize::to_usize() * C::ParBlocks::to_usize(),
                    ) {
                        hasher1.update_padded(chunk);
                        hasher2.update_padded(chunk);
                    }
                    hasher1.update_padded(tweak1);
                    hasher2.update_padded(tweak2);

                    xor_in_place(l, &hasher1.result().into_bytes());
                    xor_in_place(l, &hasher2.result_reset().into_bytes());

                    hasher1 = hasher2;

                    curr = next;
                    next = states.next();
                } else {
                    hasher1.update_padded(r);
                    hasher1.update_padded(tweak1);
                    xor_in_place(l, &hasher1.result_reset().into_bytes());
                }
            }
        }
    }
}

#[test]
#[cfg(all(feature = "aes", feature = "polyval"))]
fn weak_sanity_check() {
    let hctr = Aes128HctrPolyval::new(&Default::default());
    let a = include_bytes!("../LICENSE-MIT");

    let mut b = a.to_vec();
    hctr.seal_in_place(&mut b, &[]);
    assert_ne!(&a[..], &b[..]);

    // no modifications
    let mut c = b.clone();
    hctr.open_in_place(&mut c, &[]);
    assert_eq!(&a[..], &c[..]);

    // corrupt first byte
    let mut c = b.clone();
    c[0] ^= 1;
    hctr.open_in_place(&mut c, &[]);
    assert_ne!(&a[..], &c[..]);

    // corrupt 20th byte
    let mut c = b.clone();
    c[20] ^= 1;
    hctr.open_in_place(&mut c, &[]);
    assert_ne!(&a[..], &c[..]);
}
