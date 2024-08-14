use aria::{Aria128, Aria192, Aria256};
use cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hex_literal::hex;

/// Test vector from RFC 5794, Appendix A.1
#[test]
fn test_rfc5794_a1() {
    let key = hex!("000102030405060708090a0b0c0d0e0f");
    let pt = hex!("00112233445566778899aabbccddeeff");
    let ct = hex!("d718fbd6ab644c739da95f3be6451778");

    let c = Aria128::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf, &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf, &pt);
}

/// Test vector from RFC 5794, Appendix A.2
#[test]
fn test_rfc5794_a2() {
    let key = hex!("000102030405060708090a0b0c0d0e0f1011121314151617");
    let pt = hex!("00112233445566778899aabbccddeeff");
    let ct = hex!("26449c1805dbe7aa25a468ce263a9e79");

    let c = Aria192::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf, &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf, &pt);
}

/// Test vector from RFC 5794, Appendix A.3
#[test]
fn test_rfc5794_a3() {
    let key = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let pt = hex!("00112233445566778899aabbccddeeff");
    let ct = hex!("f92bd7c79fb72e2f2b8f80c1972d24fc");

    let c = Aria256::new_from_slice(&key).unwrap();

    let mut buf = Array::from(pt);
    c.encrypt_block(&mut buf);
    assert_eq!(&buf, &ct);
    c.decrypt_block(&mut buf);
    assert_eq!(&buf, &pt);
}
