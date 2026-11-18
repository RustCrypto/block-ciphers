use crate::primitives::{f0, f1};
use crate::key_schedule::keys;  

/// Encryption Initial Transformation
fn enc_initial_transformation(pt: &[u8], wk: &[u8]) -> Vec<u8> {
    vec![
        pt[7].wrapping_add(wk[0]),
        pt[6], 
        pt[5] ^ wk[1],
        pt[4], 
        pt[3].wrapping_add(wk[2]),
        pt[2], 
        pt[1] ^ wk[3], 
        pt[0]
    ]
}

/// Encryption Final Transformation
fn enc_final_transformation(mut cipher: Vec<u8>, wk: &[u8]) -> Vec<u8> {
    cipher[0] = cipher[0].wrapping_add(wk[4]);
    cipher[2] ^= wk[5]; 
    cipher[4] = cipher[4].wrapping_add(wk[6]);
    cipher[6] ^= wk[7];
    cipher
}

/// Encryption
fn encryption(mut cipher: Vec<u8>, sk: &[u8]) -> Vec<u8> {
    for i in 0..32 {
        let t0 = cipher[1].wrapping_add(f1(cipher[0]) ^  sk[4 * i]);
        let t1 = cipher[3] ^ (f0(cipher[2]).wrapping_add(sk[4 * i + 1]));
        let t2 = cipher[5].wrapping_add(f1(cipher[4]) ^  sk[4 * i + 2]);
        let t3 = cipher[7] ^ (f0(cipher[6]).wrapping_add(sk[4 * i + 3]));

        if i == 31 {
            cipher = vec![cipher[0], t0, cipher[2], t1, cipher[4], t2, cipher[6], t3];
        } else {
            cipher = vec![t3, cipher[0], t0, cipher[2], t1, cipher[4], t2, cipher[6]];
        }
    }
    cipher
}

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let (wk, sk) = keys(key);
    let transformed = enc_initial_transformation(plaintext, &wk);
    let cipher = encryption(transformed, &sk);
    let final_cipher = enc_final_transformation(cipher, &wk);
    final_cipher
}
