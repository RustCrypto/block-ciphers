//! Test vectors generated with OpenSSL
extern crate aes_soft;
extern crate block_cipher_trait;
extern crate block_modes;

use block_modes::BlockMode;
use block_modes::block_padding::ZeroPadding;
use block_modes::{Cbc, Ecb, Xts};
use aes_soft::Aes128;

#[test]
fn ecb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/ecb-aes128.ciphertext.bin");

    // ECB mode ignores IV
    let iv = Default::default();
    let mode = Ecb::<Aes128, ZeroPadding>::new_var(key, iv)
        .unwrap();
    let mut pt = plaintext.to_vec();
    let n = pt.len();
    mode.encrypt(&mut pt, n).unwrap();
    assert_eq!(pt, &ciphertext[..]);

    let mode = Ecb::<Aes128, ZeroPadding>::new_var(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn cbc_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cbc-aes128.ciphertext.bin");

    let mode = Cbc::<Aes128, ZeroPadding>::new_var(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    let n = pt.len();
    mode.encrypt(&mut pt, n).unwrap();
    assert_eq!(pt, &ciphertext[..]);

    let mode = Cbc::<Aes128, ZeroPadding>::new_var(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn xts_aes128() {
    let key = include_bytes!("data/xts-aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/xts-aes128.ciphertext.bin");

    let mode = Xts::<Aes128, ZeroPadding>::new_var(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    let n = pt.len();
    mode.encrypt(&mut pt, n).unwrap();
    assert_eq!(pt.len(), ciphertext.len());
    assert_eq!(pt, &ciphertext[..]);

    let mode = Xts::<Aes128, ZeroPadding>::new_var(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}

#[test]
fn xts_aes128_stealing() {
    let key = include_bytes!("data/xts-aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/xts-aes128-stealing.plaintext.bin");
    let ciphertext = include_bytes!("data/xts-aes128-stealing.ciphertext.bin");

    let mode = Xts::<Aes128, ZeroPadding>::new_var(key, iv).unwrap();
    let mut pt = plaintext.to_vec();
    let n = pt.len();
    mode.encrypt(&mut pt, n).unwrap();
    assert_eq!(pt.len(), ciphertext.len());
    assert_eq!(pt, &ciphertext[..]);

    let mode = Xts::<Aes128, ZeroPadding>::new_var(key, iv).unwrap();
    let mut ct = ciphertext.to_vec();
    mode.decrypt(&mut ct).unwrap();
    assert_eq!(ct, &plaintext[..]);
}
