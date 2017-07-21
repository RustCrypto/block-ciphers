use super::u64x2;
use super::expand::expand;

#[test]
fn test() {
    let enc_keys = expand(&[0x00; 24]).0;
    assert_eq!(enc_keys, [
        u64x2(0x0000000000000000u64.to_be(), 0x0000000000000000u64.to_be()),
        u64x2(0x0000000000000000u64.to_be(), 0x6263636362636363u64.to_be()),
        u64x2(0x6263636362636363u64.to_be(), 0x6263636362636363u64.to_be()),
        u64x2(0x9b9898c9f9fbfbaau64.to_be(), 0x9b9898c9f9fbfbaau64.to_be()),
        u64x2(0x9b9898c9f9fbfbaau64.to_be(), 0x90973450696ccffau64.to_be()),
        u64x2(0xf2f457330b0fac99u64.to_be(), 0x90973450696ccffau64.to_be()),
        u64x2(0xc81d19a9a171d653u64.to_be(), 0x53858160588a2df9u64.to_be()),
        u64x2(0xc81d19a9a171d653u64.to_be(), 0x7bebf49bda9a22c8u64.to_be()),
        u64x2(0x891fa3a8d1958e51u64.to_be(), 0x198897f8b8f941abu64.to_be()),
        u64x2(0xc26896f718f2b43fu64.to_be(), 0x91ed1797407899c6u64.to_be()),
        u64x2(0x59f00e3ee1094f95u64.to_be(), 0x83ecbc0f9b1e0830u64.to_be()),
        u64x2(0x0af31fa74a8b8661u64.to_be(), 0x137b885ff272c7cau64.to_be()),
        u64x2(0x432ac886d834c0b6u64.to_be(), 0xd2c7df11984c5970u64.to_be()),
    ]);

    let enc_keys = expand(&[0xff; 24]).0;
    assert_eq!(enc_keys, [
        u64x2(0xffffffffffffffffu64.to_be(), 0xffffffffffffffffu64.to_be()),
        u64x2(0xffffffffffffffffu64.to_be(), 0xe8e9e9e917161616u64.to_be()),
        u64x2(0xe8e9e9e917161616u64.to_be(), 0xe8e9e9e917161616u64.to_be()),
        u64x2(0xadaeae19bab8b80fu64.to_be(), 0x525151e6454747f0u64.to_be()),
        u64x2(0xadaeae19bab8b80fu64.to_be(), 0xc5c2d8ed7f7a60e2u64.to_be()),
        u64x2(0x2d2b3104686c76f4u64.to_be(), 0xc5c2d8ed7f7a60e2u64.to_be()),
        u64x2(0x1712403f686820ddu64.to_be(), 0x454311d92d2f672du64.to_be()),
        u64x2(0xe8edbfc09797df22u64.to_be(), 0x8f8cd3b7e7e4f36au64.to_be()),
        u64x2(0xa2a7e2b38f88859eu64.to_be(), 0x67653a5ef0f2e57cu64.to_be()),
        u64x2(0x2655c33bc1b13051u64.to_be(), 0x6316d2e2ec9e577cu64.to_be()),
        u64x2(0x8bfb6d227b09885eu64.to_be(), 0x67919b1aa620ab4bu64.to_be()),
        u64x2(0xc53679a929a82ed5u64.to_be(), 0xa25343f7d95acba9u64.to_be()),
        u64x2(0x598e482fffaee364u64.to_be(), 0x3a989acd1330b418u64.to_be()),
    ]);

    let enc_keys = expand(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ]).0;
    assert_eq!(enc_keys, [
        u64x2(0x0001020304050607u64.to_be(), 0x08090a0b0c0d0e0fu64.to_be()),
        u64x2(0x1011121314151617u64.to_be(), 0x5846f2f95c43f4feu64.to_be()),
        u64x2(0x544afef55847f0fau64.to_be(), 0x4856e2e95c43f4feu64.to_be()),
        u64x2(0x40f949b31cbabd4du64.to_be(), 0x48f043b810b7b342u64.to_be()),
        u64x2(0x58e151ab04a2a555u64.to_be(), 0x7effb5416245080cu64.to_be()),
        u64x2(0x2ab54bb43a02f8f6u64.to_be(), 0x62e3a95d66410c08u64.to_be()),
        u64x2(0xf501857297448d7eu64.to_be(), 0xbdf1c6ca87f33e3cu64.to_be()),
        u64x2(0xe510976183519b69u64.to_be(), 0x34157c9ea351f1e0u64.to_be()),
        u64x2(0x1ea0372a99530916u64.to_be(), 0x7c439e77ff12051eu64.to_be()),
        u64x2(0xdd7e0e887e2fff68u64.to_be(), 0x608fc842f9dcc154u64.to_be()),
        u64x2(0x859f5f237a8d5a3du64.to_be(), 0xc0c02952beefd63au64.to_be()),
        u64x2(0xde601e7827bcdf2cu64.to_be(), 0xa223800fd8aeda32u64.to_be()),
        u64x2(0xa4970a331a78dc09u64.to_be(), 0xc418c271e3a41d5du64.to_be()),
    ]);

    let enc_keys = expand(&[
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
    ]).0;
    assert_eq!(enc_keys, [
        u64x2(0x8e73b0f7da0e6452u64.to_be(), 0xc810f32b809079e5u64.to_be()),
        u64x2(0x62f8ead2522c6b7bu64.to_be(), 0xfe0c91f72402f5a5u64.to_be()),
        u64x2(0xec12068e6c827f6bu64.to_be(), 0x0e7a95b95c56fec2u64.to_be()),
        u64x2(0x4db7b4bd69b54118u64.to_be(), 0x85a74796e92538fdu64.to_be()),
        u64x2(0xe75fad44bb095386u64.to_be(), 0x485af05721efb14fu64.to_be()),
        u64x2(0xa448f6d94d6dce24u64.to_be(), 0xaa326360113b30e6u64.to_be()),
        u64x2(0xa25e7ed583b1cf9au64.to_be(), 0x27f939436a94f767u64.to_be()),
        u64x2(0xc0a69407d19da4e1u64.to_be(), 0xec1786eb6fa64971u64.to_be()),
        u64x2(0x485f703222cb8755u64.to_be(), 0xe26d135233f0b7b3u64.to_be()),
        u64x2(0x40beeb282f18a259u64.to_be(), 0x6747d26b458c553eu64.to_be()),
        u64x2(0xa7e1466c9411f1dfu64.to_be(), 0x821f750aad07d753u64.to_be()),
        u64x2(0xca4005388fcc5006u64.to_be(), 0x282d166abc3ce7b5u64.to_be()),
        u64x2(0xe98ba06f448c773cu64.to_be(), 0x8ecc720401002202u64.to_be()),
    ]);
}
