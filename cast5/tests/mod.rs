use cast5::Cast5;
use cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hex_literal::hex;

/// Test vectors from RFC 2144 Appendix B.1
/// https://tools.ietf.org/html/rfc2144#appendix-B.1
#[test]
fn rfc2144_b1() {
    let key128 = hex!("0123456712345678234567893456789A");
    let key80 = hex!("01234567123456782345");
    let key40 = hex!("0123456712");
    let ct128 = Array::from(hex!("238B4FE5847E44B2"));
    let ct80 = Array::from(hex!("EB6A711A2C02271B"));
    let ct40 = Array::from(hex!("7AC816D16E9B302E"));
    let pt = Array::from(hex!("0123456789ABCDEF"));

    let mut buf = pt;

    let c = Cast5::new_from_slice(&key128).unwrap();
    c.encrypt_block(&mut buf);
    assert_eq!(buf, ct128);
    c.decrypt_block(&mut buf);
    assert_eq!(buf, pt);

    let c = Cast5::new_from_slice(&key80).unwrap();
    c.encrypt_block(&mut buf);
    assert_eq!(buf, ct80);
    c.decrypt_block(&mut buf);
    assert_eq!(buf, pt);

    let c = Cast5::new_from_slice(&key40).unwrap();
    c.encrypt_block(&mut buf);
    assert_eq!(buf, ct40);
    c.decrypt_block(&mut buf);
    assert_eq!(buf, pt);
}

/// Test based on RFC 2144 Appendix B.2
/// https://tools.ietf.org/html/rfc2144#appendix-B.1
#[test]
fn full_maintenance_test() {
    let a = hex!("0123456712345678234567893456789A");
    let b = hex!("0123456712345678234567893456789A");

    let verify_a = hex!("EEA9D0A249FD3BA6B3436FB89D6DCA92");
    let verify_b = hex!("B2C95EB00C31AD7180AC05B8E83D696E");

    let count = 1_000_000;

    let (al, ar) = a.split_at(8);
    let (bl, br) = b.split_at(8);

    let mut al = Array::try_from(al).unwrap();
    let mut ar = Array::try_from(ar).unwrap();

    let mut bl = Array::try_from(bl).unwrap();
    let mut br = Array::try_from(br).unwrap();

    for _ in 0..count {
        let mut k = Array::from([0u8; 16]);
        k[..8].copy_from_slice(&bl);
        k[8..].copy_from_slice(&br);
        let c = Cast5::new(&k);
        c.encrypt_block(&mut al);
        c.encrypt_block(&mut ar);

        k[..8].copy_from_slice(&al);
        k[8..].copy_from_slice(&ar);
        let c = Cast5::new(&k);
        c.encrypt_block(&mut bl);
        c.encrypt_block(&mut br);
    }

    assert_eq!(&al[..], &verify_a[..8]);
    assert_eq!(&ar[..], &verify_a[8..]);

    assert_eq!(&bl[..], &verify_b[..8]);
    assert_eq!(&br[..], &verify_b[8..]);
}

// Test vectors from NESSIE:
// https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/cast-128/Cast-128-128-64.verified.test-vectors
cipher::block_cipher_test!(cast5, cast5::Cast5);
