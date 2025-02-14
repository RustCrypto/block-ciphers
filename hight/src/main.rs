mod hight;
use crate::hight::*;

struct TestVector {
    input: Vec<String>,
    key: Vec<String>,
}

fn test_block_cipher(test_vectors: &[TestVector]) {
    for test in test_vectors {
        let input_data = &test.input;
        let master_key = &test.key;

        // Encrypt the input data
        let ciphertext = encrypt(input_data, master_key);
        
        // Decrypt the ciphertext
        let recovered_plaintext = decrypt(&ciphertext, master_key);
        
        // Verify if decryption matches original input
        if &recovered_plaintext == input_data {
            println!("✅ Test PASSED for input {:?}", input_data);
        } else {
            println!("❌ Test FAILED for input {:?}", input_data);
            println!("🧐 Expected: {:?}", input_data);
            println!("👎 Got:      {:?}", recovered_plaintext);
        }
    }
}

fn main() {
    let test_vectors = vec![
        TestVector {
            input: vec!["00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000"].into_iter().map(String::from).collect(),
            key: vec!["00000000", "00010001", "00100010", "00110011", "01000100", "01010101", "01100110", "01110111", "10001000", "10011001", "10101010", "10111011", "11001100", "11011101", "11101110", "11111111"].into_iter().map(String::from).collect(),
        },
        TestVector {
            input: vec!["00000000", "00010001", "00100010", "00110011", "01000100", "01010101", "01100110", "01110111"].into_iter().map(String::from).collect(),
            key: vec!["11111111", "11101110", "11011101", "11001100", "10111011", "10101010", "10011001", "10001000", "01110111", "01100110", "01010101", "01000100", "00110011", "00100010", "00010001", "00000000"].into_iter().map(String::from).collect(),
        },
        TestVector {
            input: vec!["00000001", "00100011", "01000101", "01100111", "10001001", "10101011", "11001101", "11101111"].into_iter().map(String::from).collect(),
            key: vec!["00000000", "00000001", "00000010", "00000011", "00000100", "00000101", "00000110", "00000111", "00001000", "00001001", "00001010", "00001011", "00001100", "00001101", "00001110", "00001111"].into_iter().map(String::from).collect(),
        },
        TestVector {
            input: vec!["10110100", "00011110", "01101011", "11100010", "11101011", "10101000", "01001010", "00010100"].into_iter().map(String::from).collect(),
            key: vec!["00101000", "11011011", "11000011", "10111100", "01001001", "11111111", "11011000", "01111101", "11001111", "10100101", "00001001", "10110001", "00011101", "01000010", "00101011", "11100111"].into_iter().map(String::from).collect(),
        },
    ];
    
    test_block_cipher(&test_vectors);
}
