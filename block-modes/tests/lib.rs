//! Test vectors generated with OpenSSL

// use aes::{Aes128, BlockCipher, NewBlockCipher};
// use block_modes::block_padding::NoPadding;
// use block_modes::{BlockMode, IvState};
// use block_modes::{CbcEncrypt, CbcCfb, Ecb, Ige, Ofb};

use cipher::generic_array::{ArrayLength, GenericArray};

macro_rules! new_test {
    (
        $name:ident, $cipher:path, $encrypt:path, $decrypt:path,
        $key_path:expr, $iv_path:expr, $pt_path:expr, $ct_path:expr,
    ) => {
        #[test]
        fn $name() {
            use cipher::{
                copy_res2out, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut,
                InnerIvInit, KeyInit,
            };
            use {$cipher as Cipher, $decrypt as Decrypt, $encrypt as Encrypt};

            let key = GenericArray::from_slice(include_bytes!($key_path));
            let iv = GenericArray::from_slice(include_bytes!($iv_path));
            let pt_blocks = to_blocks(include_bytes!($pt_path));
            let ct_blocks = to_blocks(include_bytes!($ct_path));
            assert_eq!(pt_blocks.len(), ct_blocks.len());

            let cipher = Cipher::new(key);

            let mut enc = Encrypt::inner_iv_init(&cipher, iv);
            for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
                let mut t = Default::default();
                enc.encrypt_block((ptb, &mut t));
                assert_eq!(ctb, &t);
            }
            let mut enc = Encrypt::inner_iv_init(&cipher, iv);
            for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
                let mut t = *ptb;
                enc.encrypt_block(&mut t);
                assert_eq!(ctb, &t);
            }
            let mut dec = Decrypt::inner_iv_init(&cipher, iv);
            for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
                let mut t = Default::default();
                dec.decrypt_block((ctb, &mut t));
                assert_eq!(ptb, &t);
            }
            let mut dec = Decrypt::inner_iv_init(&cipher, iv);
            for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
                let mut t = *ctb;
                dec.decrypt_block(&mut t);
                assert_eq!(ptb, &t);
            }

            for i in 0..pt_blocks.len() {
                let mut enc = Encrypt::inner_iv_init(&cipher, iv);
                let mut buf = pt_blocks.to_vec();
                for chunk in buf.chunks_mut(i + 1) {
                    enc.encrypt_blocks(chunk.into(), copy_res2out);
                }
                assert_eq!(buf, ct_blocks);

                let mut dec = Decrypt::inner_iv_init(&cipher, iv);
                let mut buf = ct_blocks.to_vec();
                for chunk in buf.chunks_mut(i + 1) {
                    dec.decrypt_blocks(chunk.into(), copy_res2out);
                }
                assert_eq!(buf, pt_blocks);
            }
        }
    };
}

// TODO: add PCBC test

new_test!(
    cbc_aes128,
    aes::Aes128,
    block_modes::cbc::Encrypt,
    block_modes::cbc::Decrypt,
    "data/aes128.key.bin",
    "data/aes128.iv.bin",
    "data/aes128.plaintext.bin",
    "data/cbc-aes128.ciphertext.bin",
);

new_test!(
    cfb_aes128,
    aes::Aes128,
    block_modes::cfb::Encrypt,
    block_modes::cfb::Decrypt,
    "data/aes128.key.bin",
    "data/aes128.iv.bin",
    "data/aes128.plaintext.bin",
    "data/cfb-aes128.ciphertext.bin",
);

new_test!(
    cfb8_aes128,
    aes::Aes128,
    block_modes::cfb8::Encrypt,
    block_modes::cfb8::Decrypt,
    "data/aes128.key.bin",
    "data/aes128.iv.bin",
    "data/aes128.plaintext.bin",
    "data/cfb8-aes128.ciphertext.bin",
);

new_test!(
    ofb_aes128,
    aes::Aes128,
    block_modes::Ofb,
    block_modes::Ofb,
    "data/aes128.key.bin",
    "data/aes128.iv.bin",
    "data/aes128.plaintext.bin",
    "data/ofb-aes128.ciphertext.bin",
);

new_test!(
    ige1_aes128,
    aes::Aes128,
    block_modes::ige::Encrypt,
    block_modes::ige::Decrypt,
    "data/ige-aes128-1.key.bin",
    "data/ige-aes128-1.iv.bin",
    "data/ige-aes128-1.plaintext.bin",
    "data/ige-aes128-1.ciphertext.bin",
);

new_test!(
    ige2_aes128,
    aes::Aes128,
    block_modes::ige::Encrypt,
    block_modes::ige::Decrypt,
    "data/ige-aes128-2.key.bin",
    "data/ige-aes128-2.iv.bin",
    "data/ige-aes128-2.plaintext.bin",
    "data/ige-aes128-2.ciphertext.bin",
);

/*
#[test]
fn cbc_aes128() {
    use block_modes::{CbcEncrypt as Encrypt, CbcDecrypt as Decrypt};
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cbc-aes128.ciphertext.bin");

    let cipher = Aes128::new_from_slice(key).unwrap();
    let pt_blocks = &to_blocks(plaintext)[..15];
    let ct_blocks = &to_blocks(ciphertext)[..15];
    assert_eq!(pt_blocks.len(), ct_blocks.len());

    let mut enc = Encrypt::inner_iv_slice_init(&cipher, iv).unwrap();
    let mut dec = Decrypt::inner_iv_slice_init(&cipher, iv).unwrap();
    for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
        let mut t = Default::default();
        enc.encrypt_block((ptb, &mut t));
        assert_eq!(ctb, &t);

        let mut t = Default::default();
        dec.decrypt_block((ctb, &mut t));
        assert_eq!(ptb, &t);
    }

    let mut enc = Encrypt::inner_iv_slice_init(&cipher, iv).unwrap();
    let mut dec = Decrypt::inner_iv_slice_init(&cipher, iv).unwrap();
    for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
        let mut t = *ptb;
        enc.encrypt_block(&mut t);
        assert_eq!(ctb, &t);

        let mut t = *ctb;
        dec.decrypt_block(&mut t);
        assert_eq!(ptb, &t);
    }

    for i in (0..pt_blocks.len()).rev() {
        println!("{:?}", i);
        let mut enc = Encrypt::inner_iv_slice_init(&cipher, iv).unwrap();
        let mut buf = pt_blocks.to_vec();
        for chunk in buf.chunks_mut(i + 1) {
            enc.encrypt_blocks(chunk.into(), copy_res2out);
        }
        assert_eq!(buf, ct_blocks);

        let mut dec = Decrypt::inner_iv_slice_init(&cipher, iv).unwrap();
        let mut buf = ct_blocks.to_vec();
        for chunk in buf.chunks_mut(i + 1) {
            dec.decrypt_blocks(chunk.into(), copy_res2out);
        }
        assert_eq!(buf, pt_blocks);
    }
}


#[test]
fn cfb_aes128() {
    use block_modes::{CfbEncrypt as Encrypt, CfbDecrypt as Decrypt};
    let key = GenericArray::from_slice(include_bytes!("data/aes128.key.bin"));
    let iv = GenericArray::from_slice(include_bytes!("data/aes128.iv.bin"));
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cfb-aes128.ciphertext.bin");

    let cipher = Aes128::new(key);
    let pt_blocks = to_blocks(plaintext);
    let ct_blocks = to_blocks(ciphertext);
    assert_eq!(pt_blocks.len(), ct_blocks.len());

    let mut enc = Encrypt::inner_iv_init(&cipher, iv);
    for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
        let mut t = Default::default();
        enc.encrypt_block((ptb, &mut t));
        assert_eq!(ctb, &t);
    }
    let mut enc = Encrypt::inner_iv_init(&cipher, iv);
    for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
        let mut t = *ptb;
        enc.encrypt_block(&mut t);
        assert_eq!(ctb, &t);
    }
    let mut dec = Decrypt::inner_iv_init(&cipher, iv);
    for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
        let mut t = Default::default();
        dec.decrypt_block((ctb, &mut t));
        assert_eq!(ptb, &t);
    }
    let mut dec = Decrypt::inner_iv_init(&cipher, iv);
    for (ptb, ctb) in pt_blocks.iter().zip(ct_blocks.iter()) {
        let mut t = *ctb;
        dec.decrypt_block(&mut t);
        assert_eq!(ptb, &t);
    }

    for i in 0..pt_blocks.len() {
        let mut enc = Encrypt::inner_iv_init(&cipher, iv);
        let mut buf = pt_blocks.to_vec();
        for chunk in buf.chunks_mut(i + 1) {
            enc.encrypt_blocks(chunk.into(), copy_res2out);
        }
        assert_eq!(buf, ct_blocks);

        let mut dec = Decrypt::inner_iv_init(&cipher, iv);
        let mut buf = ct_blocks.to_vec();
        for chunk in buf.chunks_mut(i + 1) {
            dec.decrypt_blocks(chunk.into(), copy_res2out);
        }
        assert_eq!(buf, pt_blocks);
    }
}
*/

/*
#[test]
fn cbc_aes128_continued() {
    type BlockSize = <Aes128 as BlockCipher>::BlockSize;

    let key = GenericArray::from_slice(include_bytes!("data/aes128.key.bin"));
    let iv = GenericArray::from_slice(include_bytes!("data/aes128.iv.bin"));
    let mut ciphertext = *include_bytes!("data/cbc-aes128.ciphertext.bin");
    let mut plaintext = *include_bytes!("data/aes128.plaintext.bin");
    let plaintext_blocks = to_blocks::<BlockSize>(&mut plaintext[..]);
    let ciphertext_blocks = to_blocks::<BlockSize>(&mut ciphertext[..]);

    for i in 0..ciphertext_blocks.len() {
        let mut plaintext = *include_bytes!("data/aes128.plaintext.bin");
        let blocks = to_blocks::<BlockSize>(&mut plaintext[..]);

        // Encrypt `i` blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cbc::<Aes128, NoPadding>::new(cipher, iv);
        mode.encrypt_blocks(&mut blocks[..i]);

        // Interrupt, reinitialize mode, encrypt remaining blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cbc::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.encrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, ciphertext_blocks);

        // Decrypt likewise
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cbc::<Aes128, NoPadding>::new(cipher, iv);
        mode.decrypt_blocks(&mut blocks[..i]);
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cbc::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.decrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, plaintext_blocks);
    }
}

#[test]
fn cfb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cfb-aes128.ciphertext.bin");

    let mode = Cfb::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.encrypt_vec(plaintext), &ciphertext[..]);

    let mode = Cfb::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.decrypt_vec(ciphertext).unwrap(), &plaintext[..]);
}

#[test]
fn cfb_aes128_continued() {
    type BlockSize = <Aes128 as BlockCipher>::BlockSize;

    let key = GenericArray::from_slice(include_bytes!("data/aes128.key.bin"));
    let iv = GenericArray::from_slice(include_bytes!("data/aes128.iv.bin"));
    let mut ciphertext = *include_bytes!("data/cfb-aes128.ciphertext.bin");
    let mut plaintext = *include_bytes!("data/aes128.plaintext.bin");
    let plaintext_blocks = to_blocks::<BlockSize>(&mut plaintext[..]);
    let ciphertext_blocks = to_blocks::<BlockSize>(&mut ciphertext[..]);

    for i in 0..ciphertext_blocks.len() {
        let mut plaintext = *include_bytes!("data/aes128.plaintext.bin");
        let blocks = to_blocks::<BlockSize>(&mut plaintext[..]);

        // Encrypt `i` blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cfb::<Aes128, NoPadding>::new(cipher, iv);
        mode.encrypt_blocks(&mut blocks[..i]);

        // Interrupt, reinitialize mode, encrypt remaining blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cfb::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.encrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, ciphertext_blocks);

        // Decrypt likewise
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cfb::<Aes128, NoPadding>::new(cipher, iv);
        mode.decrypt_blocks(&mut blocks[..i]);
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cfb::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.decrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, plaintext_blocks);
    }
}

#[test]
fn cfb_aes128_2() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/cfb-aes128-2.plaintext.bin");
    let ciphertext = include_bytes!("data/cfb-aes128-2.ciphertext.bin");

    let mode = Cfb::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.encrypt_vec(plaintext), &ciphertext[..]);

    let mode = Cfb::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.decrypt_vec(ciphertext).unwrap(), &plaintext[..]);
}

#[test]
fn cfb_aes128_2_continued() {
    type BlockSize = <Aes128 as BlockCipher>::BlockSize;

    let key = GenericArray::from_slice(include_bytes!("data/aes128.key.bin"));
    let iv = GenericArray::from_slice(include_bytes!("data/aes128.iv.bin"));
    let mut ciphertext = *include_bytes!("data/cfb-aes128-2.ciphertext.bin");
    let mut plaintext = *include_bytes!("data/cfb-aes128-2.plaintext.bin");
    let plaintext_blocks = to_blocks::<BlockSize>(&mut plaintext[..]);
    let ciphertext_blocks = to_blocks::<BlockSize>(&mut ciphertext[..]);

    for i in 0..ciphertext_blocks.len() {
        let mut plaintext = *include_bytes!("data/cfb-aes128-2.plaintext.bin");
        let blocks = to_blocks::<BlockSize>(&mut plaintext[..]);

        // Encrypt `i` blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cfb::<Aes128, NoPadding>::new(cipher, iv);
        mode.encrypt_blocks(&mut blocks[..i]);

        // Interrupt, reinitialize mode, encrypt remaining blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cfb::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.encrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, ciphertext_blocks);

        // Decrypt likewise
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cfb::<Aes128, NoPadding>::new(cipher, iv);
        mode.decrypt_blocks(&mut blocks[..i]);
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Cfb::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.decrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, plaintext_blocks);
    }
}

#[test]
fn ofb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/ofb-aes128.ciphertext.bin");

    let mode = Ofb::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.encrypt_vec(plaintext), &ciphertext[..]);

    let mode = Ofb::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.decrypt_vec(ciphertext).unwrap(), &plaintext[..]);
}

#[test]
fn ofb_aes128_continued() {
    type BlockSize = <Aes128 as BlockCipher>::BlockSize;

    let key = GenericArray::from_slice(include_bytes!("data/aes128.key.bin"));
    let iv = GenericArray::from_slice(include_bytes!("data/aes128.iv.bin"));
    let mut ciphertext = *include_bytes!("data/ofb-aes128.ciphertext.bin");
    let mut plaintext = *include_bytes!("data/aes128.plaintext.bin");
    let ciphertext_blocks = to_blocks::<BlockSize>(&mut ciphertext[..]);
    let plaintext_blocks = to_blocks::<BlockSize>(&mut plaintext[..]);

    for i in 0..ciphertext_blocks.len() {
        let mut plaintext = *include_bytes!("data/aes128.plaintext.bin");
        let blocks = to_blocks::<BlockSize>(&mut plaintext[..]);

        // Encrypt `i` blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ofb::<Aes128, NoPadding>::new(cipher, iv);
        mode.encrypt_blocks(&mut blocks[..i]);

        // Interrupt, reinitialize mode, encrypt remaining blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ofb::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.encrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, ciphertext_blocks);

        // Decrypt likewise
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ofb::<Aes128, NoPadding>::new(cipher, iv);
        mode.decrypt_blocks(&mut blocks[..i]);
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ofb::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.decrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, plaintext_blocks);
    }
}

/// Test that parallel code works correctly
#[test]
fn par_blocks() {
    use block_modes::block_padding::Pkcs7;
    fn run<M: BlockMode<Aes128, Pkcs7>>() {
        let key: &[u8; 16] = b"secret key data.";
        let iv: &[u8; 16] = b"public iv data..";

        for i in 1..160 {
            let mut buf = [128u8; 160];

            let cipher = M::new_from_slices(key, iv).unwrap();
            let ct_len = cipher.encrypt(&mut buf, i).unwrap().len();
            let cipher = M::new_from_slices(key, iv).unwrap();
            let pt = cipher.decrypt(&mut buf[..ct_len]).unwrap();
            assert!(pt.iter().all(|&b| b == 128));
        }
    }

    run::<block_modes::Cbc<_, _>>();
    run::<block_modes::Cfb8<_, _>>();
    run::<block_modes::Ecb<_, _>>();
    run::<block_modes::Ofb<_, _>>();
    run::<block_modes::Pcbc<_, _>>();
}

#[test]
fn ige_aes256_1() {
    let key = include_bytes!("data/ige-aes128-1.key.bin");
    let iv = include_bytes!("data/ige-aes128-1.iv.bin");
    let plaintext = include_bytes!("data/ige-aes128-1.plaintext.bin");
    let ciphertext = include_bytes!("data/ige-aes128-1.ciphertext.bin");

    let mode = Ige::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.encrypt_vec(plaintext), &ciphertext[..]);

    let mode = Ige::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.decrypt_vec(ciphertext).unwrap(), &plaintext[..]);
}

#[test]
fn ige_aes256_1_continued() {
    type BlockSize = <Aes128 as BlockCipher>::BlockSize;

    let key = GenericArray::from_slice(include_bytes!("data/ige-aes128-1.key.bin"));
    let iv = GenericArray::from_slice(include_bytes!("data/ige-aes128-1.iv.bin"));
    let mut ciphertext = *include_bytes!("data/ige-aes128-1.ciphertext.bin");
    let mut plaintext = *include_bytes!("data/ige-aes128-1.plaintext.bin");
    let plaintext_blocks = to_blocks::<BlockSize>(&mut plaintext[..]);
    let ciphertext_blocks = to_blocks::<BlockSize>(&mut ciphertext[..]);

    for i in 0..ciphertext_blocks.len() {
        let mut plaintext = *include_bytes!("data/ige-aes128-1.plaintext.bin");
        let blocks = to_blocks::<BlockSize>(&mut plaintext[..]);

        // Encrypt `i` blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ige::<Aes128, NoPadding>::new(cipher, iv);
        mode.encrypt_blocks(&mut blocks[..i]);

        // Interrupt, reinitialize mode, encrypt remaining blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ige::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.encrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, ciphertext_blocks);

        // Decrypt likewise
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ige::<Aes128, NoPadding>::new(cipher, iv);
        mode.decrypt_blocks(&mut blocks[..i]);
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ige::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.decrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, plaintext_blocks);
    }
}

#[test]
fn ige_aes256_2() {
    let key = include_bytes!("data/ige-aes128-2.key.bin");
    let iv = include_bytes!("data/ige-aes128-2.iv.bin");
    let plaintext = include_bytes!("data/ige-aes128-2.plaintext.bin");
    let ciphertext = include_bytes!("data/ige-aes128-2.ciphertext.bin");

    let mode = Ige::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.encrypt_vec(plaintext), &ciphertext[..]);

    let mode = Ige::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.decrypt_vec(ciphertext).unwrap(), &plaintext[..]);
}

#[test]
fn ige_aes256_2_continued() {
    type BlockSize = <Aes128 as BlockCipher>::BlockSize;

    let key = GenericArray::from_slice(include_bytes!("data/ige-aes128-2.key.bin"));
    let iv = GenericArray::from_slice(include_bytes!("data/ige-aes128-2.iv.bin"));
    let mut plaintext = *include_bytes!("data/ige-aes128-2.plaintext.bin");
    let mut ciphertext = *include_bytes!("data/ige-aes128-2.ciphertext.bin");
    let plaintext_blocks = to_blocks::<BlockSize>(&mut plaintext[..]);
    let ciphertext_blocks = to_blocks::<BlockSize>(&mut ciphertext[..]);

    for i in 0..ciphertext_blocks.len() {
        let mut plaintext = *include_bytes!("data/ige-aes128-2.plaintext.bin");
        let blocks = to_blocks::<BlockSize>(&mut plaintext[..]);

        // Encrypt `i` blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ige::<Aes128, NoPadding>::new(cipher, iv);
        mode.encrypt_blocks(&mut blocks[..i]);

        // Interrupt, reinitialize mode, encrypt remaining blocks
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ige::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.encrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, ciphertext_blocks);

        // Decrypt likewise
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ige::<Aes128, NoPadding>::new(cipher, iv);
        mode.decrypt_blocks(&mut blocks[..i]);
        let cipher = Aes128::new(key);
        let mut mode = block_modes::Ige::<Aes128, NoPadding>::new(cipher, &mode.iv_state());
        mode.decrypt_blocks(&mut blocks[i..]);

        assert_eq!(blocks, plaintext_blocks);
    }
}
*/

fn to_blocks_mut<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
where
    N: ArrayLength<u8>,
{
    use core::slice;
    let n = N::to_usize();
    debug_assert!(data.len() % n == 0);

    #[allow(unsafe_code)]
    unsafe {
        slice::from_raw_parts_mut(data.as_ptr() as *mut GenericArray<u8, N>, data.len() / n)
    }
}

fn to_blocks<N>(data: &[u8]) -> &[GenericArray<u8, N>]
where
    N: ArrayLength<u8>,
{
    use core::slice;
    let n = N::to_usize();
    debug_assert!(data.len() % n == 0);

    #[allow(unsafe_code)]
    unsafe {
        slice::from_raw_parts(data.as_ptr() as *const GenericArray<u8, N>, data.len() / n)
    }
}
