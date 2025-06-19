use crate::primitives::{f0, f1};
use crate::key_schedule::keys;  

/// Decryption Initial Transformation
fn dec_initial_transformation(mut cipher: Vec<u8>, wk: &[u8]) -> Vec<u8> {
    cipher[0] = cipher[0].wrapping_sub(wk[4]);
    cipher[2] ^= wk[5];
    cipher[4] = cipher[4].wrapping_sub(wk[6]);
    cipher[6] ^= wk[7];
    cipher
}

/// Decryption Final Transformation
fn dec_final_transformation(mut cipher: Vec<u8>, wk: &[u8]) -> Vec<u8> {
    cipher[0] = cipher[0].wrapping_sub(wk[0]);
    cipher[2] ^= wk[1];
    cipher[4] = cipher[4].wrapping_sub(wk[2]);
    cipher[6] ^= wk[3];
    cipher
}

/// Decryption
fn decryption(mut cipher: Vec<u8>, sk: &[u8]) -> Vec<u8> {
    for i in 0..32 {
        if i == 0 {
            cipher[1] = cipher[1].wrapping_sub(f1(cipher[0]) ^  sk[4 * i + 3]);
            cipher[3] = cipher[3] ^ (f0(cipher[2]).wrapping_add(sk[4 * i + 2]));
            cipher[5] = cipher[5].wrapping_sub(f1(cipher[4]) ^  sk[4 * i + 1]);
            cipher[7] = cipher[7] ^ (f0(cipher[6]).wrapping_add(sk[4 * i]));
        } else {
            cipher = vec![
                cipher[1], cipher[2].wrapping_sub(f1(cipher[1]) ^ sk[4 * i + 3]),
                cipher[3], cipher[4] ^ (f0(cipher[3]).wrapping_add(sk[4 * i + 2])),
                cipher[5], cipher[6].wrapping_sub(f1(cipher[5]) ^ sk[4 * i + 1]),
                cipher[7], cipher[0] ^ (f0(cipher[7]).wrapping_add(sk[4 * i])),
            ];
        }
    }
    cipher
}

pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let (wk, mut sk) = keys(key);
    sk.reverse();
    let transformed = dec_initial_transformation(ciphertext.to_vec(), &wk);
    let mut plaintext = decryption(transformed, &sk);
    plaintext = dec_final_transformation(plaintext, &wk);
    plaintext.reverse();
    plaintext
}
