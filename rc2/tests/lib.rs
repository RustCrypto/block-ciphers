use block_cipher::generic_array::GenericArray;
use block_cipher::{BlockCipher, NewBlockCipher};

struct Test {
    key: &'static [u8],
    input: &'static [u8],
    output: &'static [u8],
}

#[macro_export]
macro_rules! new_tests {
    ( $( $name:expr ),*  ) => {
        [$(
            Test {
                key: include_bytes!(concat!("data/", $name, ".key.bin")),
                input: include_bytes!(concat!("data/", $name, ".input.bin")),
                output: include_bytes!(concat!("data/", $name, ".output.bin")),
            },
        )*]
    };
}

#[test]
fn rc2() {
    let tests = new_tests!("1", "2", "3", "7");
    for test in &tests {
        let cipher = rc2::Rc2::new_varkey(&test.key).unwrap();

        let mut buf = GenericArray::clone_from_slice(test.input);
        cipher.encrypt_block(&mut buf);
        assert_eq!(test.output, &buf[..]);

        let mut buf = GenericArray::clone_from_slice(test.output);
        cipher.decrypt_block(&mut buf);
        assert_eq!(test.input, &buf[..]);
    }
}

#[test]
fn rc2_effective_key_64() {
    let tests = new_tests!("4", "5", "6");
    for test in &tests {
        let cipher = rc2::Rc2::new_with_eff_key_len(test.key, 64);

        let mut buf = GenericArray::clone_from_slice(test.input);
        cipher.encrypt_block(&mut buf);
        assert_eq!(test.output, &buf[..]);

        let mut buf = GenericArray::clone_from_slice(test.output);
        cipher.decrypt_block(&mut buf);
        assert_eq!(test.input, &buf[..]);
    }
}

#[test]
fn rc2_effective_key_129() {
    let tests = new_tests!("8");
    for test in &tests {
        let cipher = rc2::Rc2::new_with_eff_key_len(test.key, 129);

        let mut buf = GenericArray::clone_from_slice(test.input);
        cipher.encrypt_block(&mut buf);
        assert_eq!(test.output, &buf[..]);

        let mut buf = GenericArray::clone_from_slice(test.output);
        cipher.decrypt_block(&mut buf);
        assert_eq!(test.input, &buf[..]);
    }
}
