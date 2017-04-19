extern crate block_cipher_trait;


use block_cipher_trait::{Block, BlockCipher, BlockCipherVarKey};

mod consts;
use consts::PITABLE;


#[derive(Clone,Copy)]
pub struct RC2 {
    s: [[u32; 256]; 4],
    p: [u32; 18]
}

fn expand_key(key: Vec<u8>) -> [u16; 64] {
    let key_len = key.len() as usize;

    let t1: usize = key_len<<3;
    let t8: usize = (t1+7)>>3;

    let tm: usize = (255 % ((2 as u32).pow((8+t1-8*t8) as u32))) as usize;

    let mut key_buffer: [u8; 128] = [0; 128];
    for i in 0..key_len {
        key_buffer[i] = key[i];
    }

    for i in key_len..128 {
        let pos: u32 = (key_buffer[i-1] as u32 + key_buffer[i-key_len] as u32) & 0xff;
        key_buffer[i] = PITABLE[pos as usize];
    }

    key_buffer[128-t8] = PITABLE[(key_buffer[128-t8] & tm as u8) as usize];

    for i in (0..128-t8).rev() {
        let pos: usize = (key_buffer[i+1] ^ key_buffer[i+t8]) as usize;
        key_buffer[i] = PITABLE[pos];
    }

    let mut result: [u16; 64] = [0; 64];
    for i in 0..64 {
        result[i] = ((key_buffer[2*i+1] as u16) << 8) + (key_buffer[2*i] as u16)
    }
    result
}

fn mix(r: &mut [u16; 4], j: &mut usize, k: &[u16; 64]) {
    r[0] = r[0] + k[*j] + (r[3] & r[2]) + (!r[3] & r[1]);
    *j += 1;
    r[0] = (r[0] << 1) | (r[0] >> 15);

    r[1] = r[1] + k[*j] + (r[0] & r[3]) + (!r[0] & r[2]);
    *j += 1;
    r[1] = (r[1] << 2) | (r[1] >> 14);

    r[2] = r[2] + k[*j] + (r[1] & r[0]) + (!r[1] & r[3]);
    *j += 1;
    r[2] = (r[2] << 3) | (r[2] >> 13);

    r[3] = r[3] + k[*j] + (r[2] & r[1]) + (!r[2] & r[0]);
    *j += 1;
    r[3] = (r[3] << 5) | (r[3] >> 11);
}

fn mash(r: &mut [u16; 4], k: &[u16; 64]) {
    r[0] = r[0] + k[(r[3] & 63) as usize];
    r[1] = r[1] + k[(r[0] & 63) as usize];
    r[2] = r[2] + k[(r[1] & 63) as usize];
    r[3] = r[3] + k[(r[2] & 63) as usize];
}

fn rc2_encrypt(block: [u8; 8], k: [u16; 64]) -> [u8; 8] {
    let mut r: [u16; 4] = [0; 4];

    r[0] = ((block[1] as u16) << 8) + (block[0] as u16);
    r[1] = ((block[3] as u16) << 8) + (block[2] as u16);
    r[2] = ((block[5] as u16) << 8) + (block[4] as u16);
    r[3] = ((block[7] as u16) << 8) + (block[6] as u16);

    let mut j = 0;

    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);

    mash(&mut r, &k);

    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);

    mash(&mut r, &k);

    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);
    mix(&mut r, &mut j, &k);

    let mut ct: [u8; 8] = [0; 8];
    ct[0] = r[0] as u8;
    ct[1] = (r[0] >> 8) as u8;
    ct[2] = r[1] as u8;
    ct[3] = (r[1] >> 8) as u8;
    ct[4] = r[2] as u8;
    ct[5] = (r[2] >> 8) as u8;
    ct[6] = r[3] as u8;
    ct[7] = (r[3] >> 8) as u8;

    ct
}

#[test]
fn test_rc2_encrypt() {
    let key = expand_key(vec![255,255,255,255,255,255,255,255]);
    let pt = [255,255,255,255,255,255,255,255];
    let ct = rc2_encrypt(pt, key);
    assert_eq!(ct, [0x27,0x8b,0x27,0xe4,0x2e,0x2f,0x0d,0x49]);

    let key = expand_key(vec![0x30,0,0,0,0,0,0,0]);
    let pt = [0x10,0,0,0,0,0,0,0x01];
    let ct = rc2_encrypt(pt, key);
    assert_eq!(ct, [0x30, 0x64, 0x9e, 0xdf, 0x9b, 0xe7, 0xd2, 0xc2]);
}
