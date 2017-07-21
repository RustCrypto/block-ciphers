use super::u64x2;
use super::expand::expand;

#[test]
fn test() {
    let enc_keys = expand(&[0x00; 16]).0;
    assert_eq!(enc_keys, [
        u64x2(0x0000000000000000u64.to_be(), 0x0000000000000000u64.to_be()),
        u64x2(0x6263636362636363u64.to_be(), 0x6263636362636363u64.to_be()),
        u64x2(0x9b9898c9f9fbfbaau64.to_be(), 0x9b9898c9f9fbfbaau64.to_be()),
        u64x2(0x90973450696ccffau64.to_be(), 0xf2f457330b0fac99u64.to_be()),
        u64x2(0xee06da7b876a1581u64.to_be(), 0x759e42b27e91ee2bu64.to_be()),
        u64x2(0x7f2e2b88f8443e09u64.to_be(), 0x8dda7cbbf34b9290u64.to_be()),
        u64x2(0xec614b851425758cu64.to_be(), 0x99ff09376ab49ba7u64.to_be()),
        u64x2(0x217517873550620bu64.to_be(), 0xacaf6b3cc61bf09bu64.to_be()),
        u64x2(0x0ef903333ba96138u64.to_be(), 0x97060a04511dfa9fu64.to_be()),
        u64x2(0xb1d4d8e28a7db9dau64.to_be(), 0x1d7bb3de4c664941u64.to_be()),
        u64x2(0xb4ef5bcb3e92e211u64.to_be(), 0x23e951cf6f8f188eu64.to_be()),
    ]);

    let enc_keys = expand(&[0xff; 16]).0;
    assert_eq!(enc_keys, [
        u64x2(0xffffffffffffffffu64.to_be(), 0xffffffffffffffffu64.to_be()),
        u64x2(0xe8e9e9e917161616u64.to_be(), 0xe8e9e9e917161616u64.to_be()),
        u64x2(0xadaeae19bab8b80fu64.to_be(), 0x525151e6454747f0u64.to_be()),
        u64x2(0x090e2277b3b69a78u64.to_be(), 0xe1e7cb9ea4a08c6eu64.to_be()),
        u64x2(0xe16abd3e52dc2746u64.to_be(), 0xb33becd8179b60b6u64.to_be()),
        u64x2(0xe5baf3ceb766d488u64.to_be(), 0x045d385013c658e6u64.to_be()),
        u64x2(0x71d07db3c6b6a93bu64.to_be(), 0xc2eb916bd12dc98du64.to_be()),
        u64x2(0xe90d208d2fbb89b6u64.to_be(), 0xed5018dd3c7dd150u64.to_be()),
        u64x2(0x96337366b988fad0u64.to_be(), 0x54d8e20d68a5335du64.to_be()),
        u64x2(0x8bf03f233278c5f3u64.to_be(), 0x66a027fe0e0514a3u64.to_be()),
        u64x2(0xd60a3588e472f07bu64.to_be(), 0x82d2d7858cd7c326u64.to_be()),
    ]);

    let enc_keys = expand(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ]).0;
    assert_eq!(enc_keys, [
        u64x2(0x0001020304050607u64.to_be(), 0x08090a0b0c0d0e0fu64.to_be()),
        u64x2(0xd6aa74fdd2af72fau64.to_be(), 0xdaa678f1d6ab76feu64.to_be()),
        u64x2(0xb692cf0b643dbdf1u64.to_be(), 0xbe9bc5006830b3feu64.to_be()),
        u64x2(0xb6ff744ed2c2c9bfu64.to_be(), 0x6c590cbf0469bf41u64.to_be()),
        u64x2(0x47f7f7bc95353e03u64.to_be(), 0xf96c32bcfd058dfdu64.to_be()),
        u64x2(0x3caaa3e8a99f9debu64.to_be(), 0x50f3af57adf622aau64.to_be()),
        u64x2(0x5e390f7df7a69296u64.to_be(), 0xa7553dc10aa31f6bu64.to_be()),
        u64x2(0x14f9701ae35fe28cu64.to_be(), 0x440adf4d4ea9c026u64.to_be()),
        u64x2(0x47438735a41c65b9u64.to_be(), 0xe016baf4aebf7ad2u64.to_be()),
        u64x2(0x549932d1f0855768u64.to_be(), 0x1093ed9cbe2c974eu64.to_be()),
        u64x2(0x13111d7fe3944a17u64.to_be(), 0xf307a78b4d2b30c5u64.to_be()),
    ]);

    let enc_keys = expand(&[
        0x69, 0x20, 0xe2, 0x99, 0xa5, 0x20, 0x2a, 0x6d,
        0x65, 0x6e, 0x63, 0x68, 0x69, 0x74, 0x6f, 0x2a,
    ]).0;
    assert_eq!(enc_keys, [
        u64x2(0x6920e299a5202a6du64.to_be(), 0x656e636869746f2au64.to_be()),
        u64x2(0xfa8807605fa82d0du64.to_be(), 0x3ac64e6553b2214fu64.to_be()),
        u64x2(0xcf75838d90ddae80u64.to_be(), 0xaa1be0e5f9a9c1aau64.to_be()),
        u64x2(0x180d2f1488d08194u64.to_be(), 0x22cb6171db62a0dbu64.to_be()),
        u64x2(0xbaed96ad323d1739u64.to_be(), 0x10f67648cb94d693u64.to_be()),
        u64x2(0x881b4ab2ba265d8bu64.to_be(), 0xaad02bc36144fd50u64.to_be()),
        u64x2(0xb34f195d096944d6u64.to_be(), 0xa3b96f15c2fd9245u64.to_be()),
        u64x2(0xa7007778ae6933aeu64.to_be(), 0x0dd05cbbcf2dcefeu64.to_be()),
        u64x2(0xff8bccf251e2ff5cu64.to_be(), 0x5c32a3e7931f6d19u64.to_be()),
        u64x2(0x24b7182e7555e772u64.to_be(), 0x29674495ba78298cu64.to_be()),
        u64x2(0xae127cdadb479ba8u64.to_be(), 0xf220df3d4858f6b1u64.to_be()),
    ]);

    let enc_keys = expand(&[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ]).0;
    assert_eq!(enc_keys, [
        u64x2(0x2b7e151628aed2a6u64.to_be(), 0xabf7158809cf4f3cu64.to_be()),
        u64x2(0xa0fafe1788542cb1u64.to_be(), 0x23a339392a6c7605u64.to_be()),
        u64x2(0xf2c295f27a96b943u64.to_be(), 0x5935807a7359f67fu64.to_be()),
        u64x2(0x3d80477d4716fe3eu64.to_be(), 0x1e237e446d7a883bu64.to_be()),
        u64x2(0xef44a541a8525b7fu64.to_be(), 0xb671253bdb0bad00u64.to_be()),
        u64x2(0xd4d1c6f87c839d87u64.to_be(), 0xcaf2b8bc11f915bcu64.to_be()),
        u64x2(0x6d88a37a110b3efdu64.to_be(), 0xdbf98641ca0093fdu64.to_be()),
        u64x2(0x4e54f70e5f5fc9f3u64.to_be(), 0x84a64fb24ea6dc4fu64.to_be()),
        u64x2(0xead27321b58dbad2u64.to_be(), 0x312bf5607f8d292fu64.to_be()),
        u64x2(0xac7766f319fadc21u64.to_be(), 0x28d12941575c006eu64.to_be()),
        u64x2(0xd014f9a8c9ee2589u64.to_be(), 0xe13f0cc8b6630ca6u64.to_be()),
    ]);
}
