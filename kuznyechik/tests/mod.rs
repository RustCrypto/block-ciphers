use cipher::{Array, Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
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

    let mut blocks2 = blocks;
    let blocks_cpy = blocks;

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

#[test]
fn kuznyechik_chain() {
    type Blocks = [[u8; 16]; 32];
    const N: usize = 1 << 16;
    const INIT_BLOCKS: Blocks = {
        let mut i = 0;
        let mut blocks: Blocks = [[0u8; 16]; 32];
        while i < blocks.len() {
            blocks[i][0] = i as u8;
            i += 1;
        }
        blocks
    };

    let key = [42; 32];
    let mut blocks: Blocks = INIT_BLOCKS;

    let expected: Blocks = [
        hex!("11D15674379CD494AD88593829490D88"),
        hex!("CD6FADA332F2A0DA822104CC1504AC25"),
        hex!("42E01F93BA3A32B63BFD510422C3C63E"),
        hex!("98CF3C6A666C615E2E30AEA728AE5F99"),
        hex!("48D0A38142D67888B655AAB30F6A272C"),
        hex!("AAC6FB321587253415ADEC32781125B6"),
        hex!("73511E76309D5828E5B101E41A905F8B"),
        hex!("6411E97F18C3880877993C6D89320923"),
        hex!("8DFA86AAAB005B656B4DEC969C12D920"),
        hex!("62B1EC7E54B2F2AC4CD2A4CC35A667DF"),
        hex!("FB28F70F8F7E57AADBFE16914BFA182E"),
        hex!("DA549C44F5B67C35BB36B482B0D1395B"),
        hex!("B54A552F1EF9F42B9EA807573202F67D"),
        hex!("625A9CD84D0B1FFDD194ECD2967AE637"),
        hex!("8D289AFB65774FC553090FBBC4869990"),
        hex!("8CDE9FCF9BDBFCC7465481F4D305EFC3"),
        hex!("60A8836A71692E2975935E6AD357C22F"),
        hex!("90CB51859D95A03D472EAD2FE8001A73"),
        hex!("32CD8B2FBD2826646EC05400A9FD2026"),
        hex!("426B92425A2C36A1F78A6D548EE092A1"),
        hex!("7CE00E51E8BA451EE3117B3655736200"),
        hex!("A5A8D7ADA61A55E632DC18A40E11A536"),
        hex!("5506E07D1CDF1E9CBB976FE5C06F65B6"),
        hex!("968DBF83021137C4E28FBB5E045A9806"),
        hex!("2B5D4D11ED27B9F3AFDACEF63099FE8F"),
        hex!("960D76DBA4B3019AD7ABA1F2B62C195A"),
        hex!("D9CCB67B70E3EBEC9729234B57D389BE"),
        hex!("42E01DCBF710D24BB95D62BCD6D980B4"),
        hex!("4346E56B5CDE431ABD256812AF44B862"),
        hex!("5B20A5A85A484758470B102D4D8B4B5A"),
        hex!("547DBA406B244657CAC3052E4CC93616"),
        hex!("E350A265B6E2F43910C26F875CB8ADD6"),
    ];

    let cipher = Kuznyechik::new(&key.into());

    for _ in 0..N {
        for block in blocks.iter_mut() {
            cipher.encrypt_block(block.into());
        }
    }
    assert_eq!(blocks, expected);

    for _ in 0..N {
        for block in blocks.iter_mut() {
            cipher.decrypt_block(block.into());
        }
    }
    assert_eq!(blocks, INIT_BLOCKS);

    for _ in 0..N {
        cipher.encrypt_blocks(Array::cast_slice_from_core_mut(&mut blocks[..]));
    }
    assert_eq!(blocks, expected);

    for _ in 0..N {
        cipher.decrypt_blocks(Array::cast_slice_from_core_mut(&mut blocks[..]));
    }
    assert_eq!(blocks, INIT_BLOCKS);

    let cipher_enc = KuznyechikEnc::new(&key.into());
    let cipher_dec = KuznyechikDec::new(&key.into());

    for _ in 0..N {
        for block in blocks.iter_mut() {
            cipher_enc.encrypt_block(block.into());
        }
    }
    assert_eq!(blocks, expected);

    for _ in 0..N {
        for block in blocks.iter_mut() {
            cipher_dec.decrypt_block(block.into());
        }
    }
    assert_eq!(blocks, INIT_BLOCKS);

    for _ in 0..N {
        cipher_enc.encrypt_blocks(Array::cast_slice_from_core_mut(&mut blocks[..]));
    }
    assert_eq!(blocks, expected);

    for _ in 0..N {
        cipher_dec.decrypt_blocks(Array::cast_slice_from_core_mut(&mut blocks[..]));
    }
    assert_eq!(blocks, INIT_BLOCKS);
}
