//! Test vectors generated with OpenSSL

use aes::{Aes128, BlockCipher, NewBlockCipher};
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, IvState};
use block_modes::{Cbc, Cfb, Ecb, Ige, Ofb};
use cipher::generic_array::{ArrayLength, GenericArray};

#[test]
fn ecb_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/ecb-aes128.ciphertext.bin");
    // ECB mode ignores IV
    let iv = Default::default();

    let mode = Ecb::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.encrypt_vec(plaintext), &ciphertext[..]);

    let mode = Ecb::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.decrypt_vec(ciphertext).unwrap(), &plaintext[..]);
}

#[test]
fn cbc_aes128() {
    let key = include_bytes!("data/aes128.key.bin");
    let iv = include_bytes!("data/aes128.iv.bin");
    let plaintext = include_bytes!("data/aes128.plaintext.bin");
    let ciphertext = include_bytes!("data/cbc-aes128.ciphertext.bin");

    let mode = Cbc::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.encrypt_vec(plaintext), &ciphertext[..]);

    let mode = Cbc::<Aes128, NoPadding>::new_from_slices(key, iv).unwrap();
    assert_eq!(mode.decrypt_vec(ciphertext).unwrap(), &plaintext[..]);
}

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

fn to_blocks<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
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
