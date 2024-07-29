use cast6::Cast6;
use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hex_literal::hex;

/// Test vectors from RFC 2612 Appendix A
/// https://tools.ietf.org/html/rfc2612#page-10
#[test]
fn rfc2144_a() {
    let key128 = hex!("2342bb9efa38542c0af75647f29f615d");
    let key192 = hex!("2342bb9efa38542cbed0ac83940ac298bac77a7717942863");
    let key256 = hex!("2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604");
    let ct128 = hex!("c842a08972b43d20836c91d1b7530f6b");
    let ct192 = hex!("1b386c0210dcadcbdd0e41aa08a7a7e8");
    let ct256 = hex!("4f6a2038286897b9c9870136553317fa");
    let pt = Block::<Cast6>::default();

    let mut buf = pt;

    let c = Cast6::new_from_slice(&key128).unwrap();
    c.encrypt_block(&mut buf);
    assert_eq!(buf, ct128);
    c.decrypt_block(&mut buf);
    assert_eq!(buf, pt);

    let c = Cast6::new_from_slice(&key192).unwrap();
    c.encrypt_block(&mut buf);
    assert_eq!(buf, ct192);
    c.decrypt_block(&mut buf);
    assert_eq!(buf, pt);

    let c = Cast6::new_from_slice(&key256).unwrap();
    c.encrypt_block(&mut buf);
    assert_eq!(buf, ct256);
    c.decrypt_block(&mut buf);
    assert_eq!(buf, pt);
}
