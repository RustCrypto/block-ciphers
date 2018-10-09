//! Test vectors generated with OpenSSL
extern crate aes_soft;
extern crate block_cipher_trait;
extern crate block_modes;

use block_cipher_trait::generic_array::GenericArray;
use block_modes::{BlockMode, BlockModeIv};
use block_modes::block_padding::ZeroPadding;
use block_modes::{Cbc, Cfb, Ctr128, Ecb, Ofb, Ige};
use aes_soft::Aes128;

#[test]
fn ecb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/ecb-aes128.ciphertext.bin");

    let mut mode = Ecb::<Aes128, ZeroPadding>::new_varkey(key).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt).unwrap();
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Ecb::<Aes128, ZeroPadding>::new_varkey(key).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn ctr_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/ctr-aes128.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Ctr128::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt).unwrap();
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Ctr128::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn ofb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/ofb-aes128.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Ofb::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt).unwrap();
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Ofb::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn cfb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cfb-aes128.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Cfb::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt).unwrap();
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Cfb::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn cbc_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cbc-aes128.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Cbc::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt).unwrap();
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Cbc::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn ige_aes256_1() {
    let key = include_bytes!("data/ige-aes128-1.key.bin");
    let iv = include_bytes!("data/ige-aes128-1.iv.bin");
    let plaintext = include_bytes!("data/ige-aes128-1.plaintext.bin");
    let ciphertext = include_bytes!("data/ige-aes128-1.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Ige::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt).unwrap();
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Ige::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn ige_aes256_2() {
    let key = include_bytes!("data/ige-aes128-2.key.bin");
    let iv = include_bytes!("data/ige-aes128-2.iv.bin");
    let plaintext = include_bytes!("data/ige-aes128-2.plaintext.bin");
    let ciphertext = include_bytes!("data/ige-aes128-2.ciphertext.bin");

    let iv = GenericArray::from_slice(iv);

    let mut mode = Ige::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    mode.encrypt_nopad(&mut pt).unwrap();
    assert_eq!(pt, &ciphertext[..]);

    let mut mode = Ige::<Aes128, ZeroPadding>::new_varkey(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt_nopad(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}
