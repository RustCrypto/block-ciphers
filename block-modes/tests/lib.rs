//! Test vectors are from NIST "Recommendation for Block Cipher Modes of
//! Operation":
//! http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
extern crate aesni;
extern crate block_modes;
extern crate block_cipher_trait;

use block_cipher_trait::generic_array::GenericArray;
use block_modes::traits::{BlockMode, BlockModeVarKey};
use block_modes::{Ctr128, Ofb, Cfb, Cbc};
use aesni::Aes128;

#[test]
fn ctr_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/ctr-aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/ctr-aes128.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Ctr128::<Aes128>::new(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt);
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Ctr128::<Aes128>::new(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct);
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn ofb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/ofb-aes128.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Ofb::<Aes128>::new(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt);
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Ofb::<Aes128>::new(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct);
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn cfb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cfb-aes128.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Cfb::<Aes128>::new(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt);
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Cfb::<Aes128>::new(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct);
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn cbc_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cbc-aes128.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Cbc::<Aes128>::new(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt);
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Cbc::<Aes128>::new(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct);
    assert_eq!(ct, &plaintext[..]);
}
