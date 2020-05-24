//! Test vectors are from Nessie
//! http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors
#![no_std]
extern crate serpent;
#[macro_use]
extern crate block_cipher_trait;

new_test!(serpent_test_128, "serpent_key_128bits", serpent::Serpent);
new_test!(serpent_test_192, "serpent_key_192bits", serpent::Serpent);
new_test!(serpent_test_256, "serpent_key_256bits", serpent::Serpent);
