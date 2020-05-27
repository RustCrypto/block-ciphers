//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/

#![no_std]

use block_cipher::new_test;
use des;

new_test!(des_test, "des", des::Des);
new_test!(tdes_ede3_test, "tdes", des::TdesEde3);
new_test!(tdes_ede2_test, "tdes2", des::TdesEde2);
