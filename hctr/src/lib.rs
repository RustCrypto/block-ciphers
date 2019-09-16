//! HCTR: http://delta.cs.cinvestav.mx/~debrup/hctr.pdf

use core::convert::TryInto;

use block_cipher_trait::{generic_array::GenericArray, BlockCipher};
use ctr::{stream_cipher::SyncStreamCipher, Ctr128};

use aes::Aes128;
use polyval::Polyval;

#[derive(Clone)]
pub struct Hctr<C, H> {
    cipher: C,
    hasher: H,
}

pub type Aes128HctrPolyval = Hctr<Aes128, Polyval>;

fn xor_in_place(a: &mut [u8], b: &[u8]) {
    assert_eq!(a.len(), b.len());

    for (a, b) in a.iter_mut().zip(b) {
        *a ^= *b;
    }
}

fn hash(mut h: Polyval, a: &[u8], b: &[u8]) -> [u8; 16] {
    h.input_padded(a);
    h.input_padded(b);

    *h.result().as_ref()
}

impl Hctr<Aes128, Polyval> {
    pub fn new(key: [u8; 32]) -> Self {
        let (a, b) = key.split_at(16);
        Hctr {
            cipher: Aes128::new(GenericArray::from_slice(a)),
            hasher: Polyval::new(b.try_into().unwrap()),
        }
    }

    pub fn seal_in_place(&self, buf: &mut [u8], aad: &[u8]) {
        self.internal_prp(false, buf, aad);
    }

    pub fn open_in_place(&self, buf: &mut [u8], aad: &[u8]) {
        self.internal_prp(true, buf, aad);
    }

    fn internal_prp(&self, inverse: bool, buf: &mut [u8], aad: &[u8]) {
        assert!(buf.len() >= 16, "message must be at least 16 bytes");

        let (l, r) = buf.split_at_mut(16);

        // phase 1: L ^= H(R, T)
        xor_in_place(l, &hash(self.hasher.clone(), r, aad));

        // phase 2a: L' = E(L)
        let mut internal_nonce = GenericArray::clone_from_slice(l);

        if inverse {
            self.cipher.decrypt_block(GenericArray::from_mut_slice(l));
        } else {
            self.cipher.encrypt_block(GenericArray::from_mut_slice(l));
        }

        // phase 2b: R = Ctr(L ^ L', R)
        xor_in_place(&mut *internal_nonce, l);

        Ctr128::from_cipher(self.cipher.clone(), &internal_nonce).apply_keystream(r);

        // phase 3: L = L' ^ H(R, T)
        xor_in_place(l, &hash(self.hasher.clone(), r, aad));
    }
}

#[test]
fn weak_sanity_check() {
    let hctr = Hctr::new(Default::default());
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
