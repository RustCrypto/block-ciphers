use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hex_literal::hex;
use belt_block::BeltBlock;

/// Example vector from STB 34.101.31 (2020)
#[test]
fn belt_block() {
    let key_enc = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let plaintext_enc = hex!("B194BAC8 0A08F53B 366D008E 584A5DE4");
    let ciphertext_enc = hex!("69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E");

    let key_dec = hex!("92BD9B1C E5D14101 5445FBC9 5E4D0EF2 682080AA 227D642F 2687F934 90405511");
    let plaintext_dec = hex!("0DC53006 00CAB840 B38448E5 E993F421");
    let ciphertext_dec = hex!("E12BDC1A E28257EC 703FCCF0 95EE8DF1");

    let cipher_enc = BeltBlock::new(&key_enc.into());
    let cipher_dec = BeltBlock::new(&key_dec.into());

    let mut block_enc = plaintext_enc.into();
    cipher_enc.encrypt_block(&mut block_enc);
    assert_eq!(ciphertext_enc, block_enc.as_slice());

    let mut block_dec = ciphertext_dec.into();
    cipher_dec.decrypt_block(&mut block_dec);
    assert_eq!(plaintext_dec, block_dec.as_slice());
}