//! Test vectors from: https://www.ietf.org/archive/id/draft-krovetz-rc6-rc5-vectors-00.txt
use cipher::consts::*;
use cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hex_literal::hex;
use rc5::RC5;

#[test]
fn rc5_8_12_4() {
    let key = hex!("00010203");
    let pt = hex!("0001");
    let ct = hex!("212A");

    let rc5 = <RC5<u8, U12, U4> as KeyInit>::new_from_slice(&key).unwrap();

    let mut block = Array::from(pt);
    rc5.encrypt_block(&mut block);

    assert_eq!(ct, block[..]);

    rc5.decrypt_block(&mut block);
    assert_eq!(pt, block[..]);
}

#[test]
fn rc5_16_16_8() {
    let key = hex!("0001020304050607");
    let pt = hex!("00010203");
    let ct = hex!("23A8D72E");

    let rc5 = <RC5<u16, U16, U8> as KeyInit>::new_from_slice(&key).unwrap();

    let mut block = Array::from(pt);
    rc5.encrypt_block(&mut block);

    assert_eq!(ct, block[..]);

    rc5.decrypt_block(&mut block);
    assert_eq!(pt, block[..]);
}

#[test]
fn rc5_32_12_16() {
    let key = hex!("000102030405060708090A0B0C0D0E0F");
    let pt = hex!("0001020304050607");
    let ct = hex!("C8D3B3C486700CFA");

    let rc5 = <RC5<u32, U12, U16> as KeyInit>::new_from_slice(&key).unwrap();

    let mut block = Array::from(pt);
    rc5.encrypt_block(&mut block);

    assert_eq!(ct, block[..]);

    rc5.decrypt_block(&mut block);
    assert_eq!(pt, block[..]);
}

#[test]
fn rc5_32_16_16() {
    let key = hex!("000102030405060708090A0B0C0D0E0F");
    let pt = hex!("0001020304050607");
    let ct = hex!("3E2E95357027D896");

    let rc5 = <RC5<u32, U16, U16> as KeyInit>::new_from_slice(&key).unwrap();

    let mut block = Array::from(pt);
    rc5.encrypt_block(&mut block);

    assert_eq!(ct, block[..]);

    rc5.decrypt_block(&mut block);
    assert_eq!(pt, block[..]);
}

#[test]
fn rc5_64_24_24() {
    let key = hex!("000102030405060708090A0B0C0D0E0F1011121314151617");
    let pt = hex!("000102030405060708090A0B0C0D0E0F");
    let ct = hex!("A46772820EDBCE0235ABEA32AE7178DA");

    let rc5 = <RC5<u64, U24, U24> as KeyInit>::new_from_slice(&key).unwrap();

    let mut block = Array::from(pt);
    rc5.encrypt_block(&mut block);

    assert_eq!(ct, block[..]);

    rc5.decrypt_block(&mut block);
    assert_eq!(pt, block[..]);
}

#[test]
fn rc5_128_28_32() {
    let key = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let pt = hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let ct = hex!("ECA5910921A4F4CFDD7AD7AD20A1FCBA068EC7A7CD752D68FE914B7FE180B440");

    let rc5 = <RC5<u128, U28, U32> as KeyInit>::new_from_slice(&key).unwrap();

    let mut block = Array::from(pt);
    rc5.encrypt_block(&mut block);

    assert_eq!(ct, block[..]);

    rc5.decrypt_block(&mut block);
    assert_eq!(pt, block[..]);
}
