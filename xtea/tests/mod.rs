use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, array::Array};
use xtea::Xtea;

#[test]
fn xtea() {
    // https://web.archive.org/web/20231115163347/https://asecuritysite.com/encryption/xtea
    let key = b"0123456789012345";
    let plaintext = b"ABCDEFGH";
    let ciphertext = [0xea, 0x0c, 0x3d, 0x7c, 0x1c, 0x22, 0x55, 0x7f];
    let cipher = Xtea::new_from_slice(key).unwrap();

    let mut block = Array(*plaintext);
    cipher.encrypt_block(&mut block);
    assert_eq!(ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(plaintext, block.as_slice());
}
