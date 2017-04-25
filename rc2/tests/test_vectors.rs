
pub struct RC2CipherTest {
    pub key: &'static [u8],
    pub eff_key_length: usize,
    pub input: &'static [u8],
    pub output: &'static [u8],
}

pub static RC2_EFF_KEY_LEN_TESTS: &[RC2CipherTest] = &[
    RC2CipherTest {
        key: &[0x88],
        eff_key_length: 64,
        input: &[0;8],
        output: &[0x61, 0xa8, 0xa2, 0x44, 0xad, 0xac, 0xcc, 0xf0],
    },
    RC2CipherTest {
        key: &[0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a],
        eff_key_length: 64,
        input: &[0;8],
        output: &[0x6c, 0xcf, 0x43, 0x08, 0x97, 0x4c, 0x26, 0x7f],
    },
    RC2CipherTest {
        key: &[0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f, 0x0f,
            0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2],
        eff_key_length: 64,
        input: &[0;8],
        output: &[ 0x1a, 0x80, 0x7d, 0x27, 0x2b, 0xbe, 0x5d, 0xb1],
    },
    RC2CipherTest {
        key: &[0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f, 0x0f,
            0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2, 0x16, 0xf8, 0x0a,
            0x6f, 0x85, 0x92, 0x05, 0x84, 0xc4, 0x2f, 0xce, 0xb0, 0xbe,
            0x25, 0x5d, 0xaf, 0x1e],
        eff_key_length: 129,
        input: &[0;8],
        output: &[0x5b, 0x78, 0xd3, 0xa4, 0x3d, 0xff, 0xf1, 0xf1],
    }
];
