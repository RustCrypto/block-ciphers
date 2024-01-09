//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/

cipher::block_cipher_test!(aes128_test, "aes128", aes::Aes128);
#[cfg(any(
    not(target_arch = "riscv64"),
    all(
        target_arch = "riscv64",
        target_feature = "zknd",
        target_feature = "zkne"
    )
))]
cipher::block_cipher_test!(aes192_test, "aes192", aes::Aes192);
cipher::block_cipher_test!(aes256_test, "aes256", aes::Aes256);
