#![no_std]
#![forbid(unsafe_code, missing_docs)]

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

fn hash<H: UniversalHash>(
    h: &mut H,
    a: &[u8],
    b: &[u8],
) -> GenericArray<u8, H::OutputSize>
{
    h.update_padded(a);
    h.update_padded(b);

    h.result_reset().into_bytes()
}

impl<C, H> Hctr<C, H>
where
    C: BlockCipher<BlockSize = U16> + Clone,
    C::ParBlocks: ArrayLength<GenericArray<u8, C::BlockSize>>,
    C::KeySize: core::ops::Add<H::KeySize>,
    Sum<C::KeySize, H::KeySize>: ArrayLength<u8>,
    Ctr128<C>: SyncStreamCipher,
    H: UniversalHash<OutputSize = C::BlockSize>,
{
    /// Create a new HCTR instance with key size `C::KeySize + H::KeySize`.
    pub fn new(key: GenericArray<u8, Sum<C::KeySize, H::KeySize>>) -> Self {
        let (a, b) = key.split_at(C::KeySize::to_usize());
        Hctr {
            cipher: C::new(GenericArray::from_slice(a)),
            hasher: H::new(GenericArray::from_slice(b)),
        }
    }

    /// Encrypt a message in-place with a tweak.
    ///
    /// Panics if the message length is not at least as large as the `BlockCipher`'s `BlockSize`.
    pub fn seal_in_place(&self, buf: &mut [u8], tweak: &[u8]) {
        self.internal_prp(false, buf, tweak);
    }

    /// Decrypt a message in-place with a tweak.
    ///
    /// Panics if the message length is not at least as large as the `BlockCipher`'s `BlockSize`.
    pub fn open_in_place(&self, buf: &mut [u8], tweak: &[u8]) {
        self.internal_prp(true, buf, tweak);
    }

    fn internal_prp(&self, inverse: bool, buf: &mut [u8], tweak: &[u8]) {
        assert!(
            buf.len() >= C::BlockSize::to_usize(),
            "message must be at least as large as the BlockCipher::BlockSize."
        );

        let mut hasher = self.hasher.clone();

        let (l, r) = buf.split_at_mut(C::BlockSize::to_usize());

        // phase 1: L ^= H(R, T)
        xor_in_place(l, &hash(&mut hasher, r, tweak));

        // phase 2a: L' = E(L)
        let mut internal_nonce = GenericArray::clone_from_slice(l);

        if inverse {
            self.cipher.decrypt_block(GenericArray::from_mut_slice(l));
        } else {
            self.cipher.encrypt_block(GenericArray::from_mut_slice(l));
        }

        // phase 2b: R = Ctr(L ^ L', R)
        xor_in_place(&mut *internal_nonce, l);

        Ctr128::from_cipher(self.cipher.clone(), &internal_nonce)
            .apply_keystream(r);

        // phase 3: L = L' ^ H(R, T)
        xor_in_place(l, &hash(&mut hasher, r, tweak));
    }
}

#[test]
#[cfg(all(feature = "aes", feature = "polyval"))]
fn weak_sanity_check() {
    let hctr = Aes128HctrPolyval::new(Default::default());
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
