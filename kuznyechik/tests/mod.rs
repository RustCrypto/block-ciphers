use cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use hex_literal::hex;
use kuznyechik::{Kuznyechik, KuznyechikDec, KuznyechikEnc};

/// Example vector from GOST 34.12-2018
#[test]
fn kuznyechik() {
    let key = hex!(
        "8899AABBCCDDEEFF0011223344556677"
        "FEDCBA98765432100123456789ABCDEF"
    );
    let plaintext = hex!("1122334455667700FFEEDDCCBBAA9988");
    let ciphertext = hex!("7F679D90BEBC24305a468d42b9d4EDCD");

    let cipher = Kuznyechik::new(&key.into());
    let cipher_enc = KuznyechikEnc::new(&key.into());
    let cipher_dec = KuznyechikDec::new(&key.into());

    let mut block = plaintext.into();
    cipher.encrypt_block(&mut block);
    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());

    cipher_enc.encrypt_block(&mut block);
    assert_eq!(&ciphertext, block.as_slice());

    cipher_dec.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());

    // test that encrypt_blocks/decrypt_blocks work correctly
    let mut blocks = [Block::<Kuznyechik>::default(); 101];
    for (i, block) in blocks.iter_mut().enumerate() {
        block.iter_mut().enumerate().for_each(|(j, b)| {
            *b = (i + j) as u8;
        });
    }

    let mut blocks2 = blocks.clone();
    let blocks_cpy = blocks.clone();

    cipher.encrypt_blocks(&mut blocks);
    assert!(blocks[..] != blocks_cpy[..]);
    for block in blocks2.iter_mut() {
        cipher.encrypt_block(block);
    }
    assert_eq!(blocks[..], blocks2[..]);

    cipher.decrypt_blocks(&mut blocks);
    assert_eq!(blocks[..], blocks_cpy[..]);
    for block in blocks2.iter_mut().rev() {
        cipher.decrypt_block(block);
    }
    assert_eq!(blocks2[..], blocks_cpy[..]);

    cipher_enc.encrypt_blocks(&mut blocks);
    assert!(blocks[..] != blocks_cpy[..]);
    for block in blocks2.iter_mut() {
        cipher_enc.encrypt_block(block);
    }
    assert_eq!(blocks[..], blocks2[..]);

    cipher_dec.decrypt_blocks(&mut blocks);
    assert_eq!(blocks[..], blocks_cpy[..]);
    for block in blocks2.iter_mut().rev() {
        cipher_dec.decrypt_block(block);
    }
    assert_eq!(blocks2[..], blocks_cpy[..]);
}
