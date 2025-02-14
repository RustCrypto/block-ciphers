use std::collections::VecDeque;

/// Performs binary addition with overflow, returning an 8-bit binary result.
pub fn bin_add(a: &str, b: &str) -> String {
    let a_int = u8::from_str_radix(a, 2).unwrap();
    let b_int = u8::from_str_radix(b, 2).unwrap();
    let result = a_int.wrapping_add(b_int);
    format!("{:08b}", result)
}

/// Performs binary subtraction with overflow, returning an 8-bit binary result.
pub fn bin_sub(a: &str, b: &str) -> String {
    let a_int = u8::from_str_radix(a, 2).unwrap();
    let b_int = u8::from_str_radix(b, 2).unwrap();
    let result = a_int.wrapping_sub(b_int); 
    format!("{:08b}", result)
}

/// Performs bitwise XOR on two 8-bit binary strings and returns the 8-bit binary result.
pub fn bin_xor(a: &str, b: &str) -> String {
    let a_int = u8::from_str_radix(a, 2).unwrap();
    let b_int = u8::from_str_radix(b, 2).unwrap();
    let result = a_int ^ b_int;
    format!("{:08b}", result)
}


/// Performs XOR on left-rotated versions of an 8-bit binary string for f0.
pub fn f0(x: &str) -> String {
    let rot1 = format!("{}{}", &x[1..], &x[0..1]); // Left-rotate by 1
    let rot2 = format!("{}{}", &x[2..], &x[0..2]); // Left-rotate by 2
    let rot7 = format!("{}{}", &x[7..], &x[0..7]); // Left-rotate by 7

    let result = u8::from_str_radix(&rot1, 2).unwrap()
        ^ u8::from_str_radix(&rot2, 2).unwrap()
        ^ u8::from_str_radix(&rot7, 2).unwrap();

    format!("{:08b}", result)
}

/// Performs XOR on left-rotated versions of an 8-bit binary string for f1.
pub fn f1(x: &str) -> String {
    let rot3 = format!("{}{}", &x[3..], &x[0..3]); // Left-rotate by 3
    let rot4 = format!("{}{}", &x[4..], &x[0..4]); // Left-rotate by 4
    let rot6 = format!("{}{}", &x[6..], &x[0..6]); // Left-rotate by 6

    let result = u8::from_str_radix(&rot3, 2).unwrap()
        ^ u8::from_str_radix(&rot4, 2).unwrap()
        ^ u8::from_str_radix(&rot6, 2).unwrap();

    format!("{:08b}", result)
}

/// Generates Keys
pub fn keys(mk: &[&str]) -> (Vec<String>, Vec<String>) {
    let mut s = VecDeque::from(vec![1, 0, 1, 1, 0, 1, 0]);
    let mut delta = vec![s.iter().map(|&x| x.to_string()).collect::<String>()];

    // Generate delta values (128 rounds)
    for _ in 0..128 {
        let s_next = s[3] ^ s[6];
        s.pop_back();
        s.push_front(s_next);
        delta.push(s.iter().map(|&x| x.to_string()).collect::<String>());
    }

    let mut mk_rev = mk.to_vec();
    mk_rev.reverse();

    let mut sk = vec![String::from("00000000"); 128];

    // Generate Sub-Keys (SK)
    for i in 0..8 {
        for j in 0..16 {
            let mk_index = if j < 8 {
                ((j as isize - i as isize).rem_euclid(8)) as usize
            } else {
                (((j as isize - i as isize).rem_euclid(8)) + 8) as usize
            };

            let a = mk_rev[mk_index]; 
            let b = &delta[16 * i + j];

            sk[16 * i + j] = bin_add(a, b);
        }
    }

    // Generate whitening keys (wk)
    let wk: Vec<String> = (0..8)
    .map(|i| if i <= 3 {
        mk_rev[i + 12].to_string()
    } else {
        mk_rev[i - 4].to_string()
    })
    .collect();

    (wk, sk)
}



// --------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------
// ----------------------------------------------- Encryption ---------------------------------------
// --------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------


/// Encryption Initial Transformation
pub fn enc_initial_transformation(pt: &[String], wk: &[String]) -> Vec<String> {
    vec![
        bin_add(&pt[7], &wk[0]),
        pt[6].clone(),
        bin_xor(&pt[5], &wk[1]),
        pt[4].clone(),
        bin_add(&pt[3], &wk[2]),
        pt[2].clone(),
        bin_xor(&pt[1], &wk[3]),
        pt[0].clone(),
    ]
}

/// Encryption Final Transformation
pub fn enc_final_transformation(mut cipher: Vec<String>, wk: &[String]) -> Vec<String> {
    cipher[0] = bin_add(&cipher[0], &wk[4]);
    cipher[2] = bin_xor(&cipher[2], &wk[5]);
    cipher[4] = bin_add(&cipher[4], &wk[6]);
    cipher[6] = bin_xor(&cipher[6], &wk[7]);
    cipher
}

/// Encryption
pub fn encryption(mut cipher: Vec<String>, sk: &[String]) -> Vec<String> {
    for i in 0..32 {
        let t0 = bin_add(&cipher[1], &bin_xor(&f1(&cipher[0]), &sk[4 * i]));
        let t1 = bin_xor(&cipher[3], &bin_add(&f0(&cipher[2]), &sk[4 * i + 1]));
        let t2 = bin_add(&cipher[5], &bin_xor(&f1(&cipher[4]), &sk[4 * i + 2]));
        let t3 = bin_xor(&cipher[7], &bin_add(&f0(&cipher[6]), &sk[4 * i + 3]));

        if i == 31 {
            cipher = vec![
                cipher[0].clone(), t0, cipher[2].clone(), t1, cipher[4].clone(), t2, cipher[6].clone(), t3,
            ];
        } else {
            cipher = vec![t3, cipher[0].clone(), t0, cipher[2].clone(), t1, cipher[4].clone(), t2, cipher[6].clone()];
        }
    }
    cipher
}

/// Encryption Entry
pub fn encrypt(plaintext: &[String], key: &[String]) -> Vec<String> {
    let key_refs: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
    let (wk, sk) = keys(&key_refs); // Now this matches the expected type
    let transformed = enc_initial_transformation(plaintext, &wk);
    let cipher = encryption(transformed, &sk);
    enc_final_transformation(cipher, &wk)
}


// --------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------
// ----------------------------------------------- Decryption ---------------------------------------
// --------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------


/// Encryption Final Transformation
pub fn dec_final_transformation(mut cipher: Vec<String>, wk: &[String]) -> Vec<String> {
    cipher[0] = bin_sub(&cipher[0], &wk[0]);
    cipher[2] = bin_xor(&cipher[2], &wk[1]);
    cipher[4] = bin_sub(&cipher[4], &wk[2]);
    cipher[6] = bin_xor(&cipher[6], &wk[3]);

    cipher
}

/// Decryption
pub fn decryption(mut cipher: Vec<String>, sk: &[String]) -> Vec<String> {
    for i in 0..32 {
        if i == 0 {
            cipher[1] = bin_sub(&cipher[1], &bin_xor(&f1(&cipher[0]), &sk[4 * i + 3]));
            cipher[3] = bin_xor(&cipher[3], &bin_add(&f0(&cipher[2]), &sk[4 * i + 2]));
            cipher[5] = bin_sub(&cipher[5], &bin_xor(&f1(&cipher[4]), &sk[4 * i + 1]));
            cipher[7] = bin_xor(&cipher[7], &bin_add(&f0(&cipher[6]), &sk[4 * i]));
        } else {
            cipher = vec![
                cipher[1].clone(),
                bin_sub(&cipher[2], &bin_xor(&f1(&cipher[1]), &sk[4 * i + 3])),
                cipher[3].clone(),
                bin_xor(&cipher[4], &bin_add(&f0(&cipher[3]), &sk[4 * i + 2])),
                cipher[5].clone(),
                bin_sub(&cipher[6], &bin_xor(&f1(&cipher[5]), &sk[4 * i + 1])),
                cipher[7].clone(),
                bin_xor(&cipher[0], &bin_add(&f0(&cipher[7]), &sk[4 * i])),
            ];
        }
    }

    cipher
}

pub fn dec_initial_transformation(mut cipher: Vec<String>, wk: &[String]) -> Vec<String> {
    cipher[0] = bin_sub(&cipher[0], &wk[4]);
    cipher[2] = bin_xor(&cipher[2], &wk[5]);
    cipher[4] = bin_sub(&cipher[4], &wk[6]);
    cipher[6] = bin_xor(&cipher[6], &wk[7]);

    cipher
}

pub fn decrypt(ciphertext: &[String], key: &[String]) -> Vec<String> {
    let key_refs: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
    let (wk,mut sk) = keys(&key_refs);
    let transformed = dec_initial_transformation(ciphertext.to_vec(), &wk);
    sk.reverse();  // Reverse subkeys for decryption
    let mut plaintext = decryption(transformed, &sk);
    plaintext = dec_final_transformation(plaintext, &wk);
    plaintext.reverse();  // Return decrypted plaintext
    plaintext
}
