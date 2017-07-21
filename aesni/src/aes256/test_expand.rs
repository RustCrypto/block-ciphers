use super::u64x2;
use super::expand::expand;

#[test]
fn test() {
    let enc_key = expand(&[0x00; 32]).0;
    assert_eq!(enc_key, [
        u64x2(0x0000000000000000u64.to_be(), 0x0000000000000000u64.to_be()),
        u64x2(0x0000000000000000u64.to_be(), 0x0000000000000000u64.to_be()),
        u64x2(0x6263636362636363u64.to_be(), 0x6263636362636363u64.to_be()),
        u64x2(0xaafbfbfbaafbfbfbu64.to_be(), 0xaafbfbfbaafbfbfbu64.to_be()),
        u64x2(0x6f6c6ccf0d0f0facu64.to_be(), 0x6f6c6ccf0d0f0facu64.to_be()),
        u64x2(0x7d8d8d6ad7767691u64.to_be(), 0x7d8d8d6ad7767691u64.to_be()),
        u64x2(0x5354edc15e5be26du64.to_be(), 0x31378ea23c38810eu64.to_be()),
        u64x2(0x968a81c141fcf750u64.to_be(), 0x3c717a3aeb070cabu64.to_be()),
        u64x2(0x9eaa8f28c0f16d45u64.to_be(), 0xf1c6e3e7cdfe62e9u64.to_be()),
        u64x2(0x2b312bdf6acddc8fu64.to_be(), 0x56bca6b5bdbbaa1eu64.to_be()),
        u64x2(0x6406fd52a4f79017u64.to_be(), 0x553173f098cf1119u64.to_be()),
        u64x2(0x6dbba90b07767584u64.to_be(), 0x51cad331ec71792fu64.to_be()),
        u64x2(0xe7b0e89c4347788bu64.to_be(), 0x16760b7b8eb91a62u64.to_be()),
        u64x2(0x74ed0ba1739b7e25u64.to_be(), 0x2251ad14ce20d43bu64.to_be()),
        u64x2(0x10f80a1753bf729cu64.to_be(), 0x45c979e7cb706385u64.to_be()),
    ]);

    let enc_key = expand(&[0xff; 32]).0;
    assert_eq!(enc_key, [
        u64x2(0xffffffffffffffffu64.to_be(), 0xffffffffffffffffu64.to_be()),
        u64x2(0xffffffffffffffffu64.to_be(), 0xffffffffffffffffu64.to_be()),
        u64x2(0xe8e9e9e917161616u64.to_be(), 0xe8e9e9e917161616u64.to_be()),
        u64x2(0x0fb8b8b8f0474747u64.to_be(), 0x0fb8b8b8f0474747u64.to_be()),
        u64x2(0x4a4949655d5f5f73u64.to_be(), 0xb5b6b69aa2a0a08cu64.to_be()),
        u64x2(0x355858dcc51f1f9bu64.to_be(), 0xcaa7a7233ae0e064u64.to_be()),
        u64x2(0xafa80ae5f2f75596u64.to_be(), 0x4741e30ce5e14380u64.to_be()),
        u64x2(0xeca0421129bf5d8au64.to_be(), 0xe318faa9d9f81acdu64.to_be()),
        u64x2(0xe60ab7d014fde246u64.to_be(), 0x53bc014ab65d42cau64.to_be()),
        u64x2(0xa2ec6e658b5333efu64.to_be(), 0x684bc946b1b3d38bu64.to_be()),
        u64x2(0x9b6c8a188f91685eu64.to_be(), 0xdc2d69146a702bdeu64.to_be()),
        u64x2(0xa0bd9f782beeac97u64.to_be(), 0x43a565d1f216b65au64.to_be()),
        u64x2(0xfc22349173b35ccfu64.to_be(), 0xaf9e35dbc5ee1e05u64.to_be()),
        u64x2(0x0695ed132d7b4184u64.to_be(), 0x6ede24559cc8920fu64.to_be()),
        u64x2(0x546d424f27de1e80u64.to_be(), 0x88402b5b4dae355eu64.to_be()),
    ]);

    let enc_key = expand(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ]).0;
    assert_eq!(enc_key, [
        u64x2(0x0001020304050607u64.to_be(), 0x08090a0b0c0d0e0fu64.to_be()),
        u64x2(0x1011121314151617u64.to_be(), 0x18191a1b1c1d1e1fu64.to_be()),
        u64x2(0xa573c29fa176c498u64.to_be(), 0xa97fce93a572c09cu64.to_be()),
        u64x2(0x1651a8cd0244bedau64.to_be(), 0x1a5da4c10640badeu64.to_be()),
        u64x2(0xae87dff00ff11b68u64.to_be(), 0xa68ed5fb03fc1567u64.to_be()),
        u64x2(0x6de1f1486fa54f92u64.to_be(), 0x75f8eb5373b8518du64.to_be()),
        u64x2(0xc656827fc9a79917u64.to_be(), 0x6f294cec6cd5598bu64.to_be()),
        u64x2(0x3de23a75524775e7u64.to_be(), 0x27bf9eb45407cf39u64.to_be()),
        u64x2(0x0bdc905fc27b0948u64.to_be(), 0xad5245a4c1871c2fu64.to_be()),
        u64x2(0x45f5a66017b2d387u64.to_be(), 0x300d4d33640a820au64.to_be()),
        u64x2(0x7ccff71cbeb4fe54u64.to_be(), 0x13e6bbf0d261a7dfu64.to_be()),
        u64x2(0xf01afafee7a82979u64.to_be(), 0xd7a5644ab3afe640u64.to_be()),
        u64x2(0x2541fe719bf50025u64.to_be(), 0x8813bbd55a721c0au64.to_be()),
        u64x2(0x4e5a6699a9f24fe0u64.to_be(), 0x7e572baacdf8cdeau64.to_be()),
        u64x2(0x24fc79ccbf0979e9u64.to_be(), 0x371ac23c6d68de36u64.to_be()),
    ]);

    let enc_key = expand(&[
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    ]).0;
    assert_eq!(enc_key, [
        u64x2(0x603deb1015ca71beu64.to_be(), 0x2b73aef0857d7781u64.to_be()),
        u64x2(0x1f352c073b6108d7u64.to_be(), 0x2d9810a30914dff4u64.to_be()),
        u64x2(0x9ba354118e6925afu64.to_be(), 0xa51a8b5f2067fcdeu64.to_be()),
        u64x2(0xa8b09c1a93d194cdu64.to_be(), 0xbe49846eb75d5b9au64.to_be()),
        u64x2(0xd59aecb85bf3c917u64.to_be(), 0xfee94248de8ebe96u64.to_be()),
        u64x2(0xb5a9328a2678a647u64.to_be(), 0x983122292f6c79b3u64.to_be()),
        u64x2(0x812c81addadf48bau64.to_be(), 0x24360af2fab8b464u64.to_be()),
        u64x2(0x98c5bfc9bebd198eu64.to_be(), 0x268c3ba709e04214u64.to_be()),
        u64x2(0x68007bacb2df3316u64.to_be(), 0x96e939e46c518d80u64.to_be()),
        u64x2(0xc814e20476a9fb8au64.to_be(), 0x5025c02d59c58239u64.to_be()),
        u64x2(0xde1369676ccc5a71u64.to_be(), 0xfa2563959674ee15u64.to_be()),
        u64x2(0x5886ca5d2e2f31d7u64.to_be(), 0x7e0af1fa27cf73c3u64.to_be()),
        u64x2(0x749c47ab18501ddau64.to_be(), 0xe2757e4f7401905au64.to_be()),
        u64x2(0xcafaaae3e4d59b34u64.to_be(), 0x9adf6acebd10190du64.to_be()),
        u64x2(0xfe4890d1e6188d0bu64.to_be(), 0x046df344706c631eu64.to_be()),
    ]);
}
