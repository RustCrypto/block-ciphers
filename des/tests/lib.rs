#![no_std]

extern crate des;
extern crate generic_array;

use des::{Des, BlockCipher, BlockCipherFixKey};
use generic_array::GenericArray;

#[test]
fn test() {
    let key = GenericArray::from_slice(
        &[0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1],
    );
    let input = GenericArray::from_slice(
        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
    );
    let expected = GenericArray::from_slice(
        &[0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05],
    );

    let d = Des::new(&key);
    let mut output = GenericArray::from_slice(&[0; 8]);
    d.encrypt_block(&input, &mut output);
    assert_eq!(output, expected);
}
