use des::weak_key_test;
use hex_literal::hex;

#[test]
fn weak_des() {
    for k in &[
        hex!("0101010101010101"),
        hex!("fefefefefefefefe"),
        hex!("e0e0e0e0f1f1f1f1"),
    ] {
        assert!(weak_key_test(k).is_err());
    }

    for k in &[
        hex!("010101010101010100000000000000000000000000000000"),
        hex!("0000000000000000fefefefefefefefe0000000000000000"),
        hex!("00000000000000000000000000000000e0e0e0e0f1f1f1f1"),
        hex!("010203040506070801020304050607081112131415161718"),
        hex!("010203040506070811121314151617180102030405060708"),
        hex!("111213141516171801020304050607080102030405060708"),
    ] {
        assert!(weak_key_test(k).is_err());
    }

    for k in &[
        hex!("01010101010101010000000000000000"),
        hex!("0000000000000000fefefefefefefefe"),
        hex!("0000000000000000e0e0e0e0f1f1f1f1"),
        hex!("01020304050607080102030405060708"),
    ] {
        assert!(weak_key_test(k).is_err());
    }
}
