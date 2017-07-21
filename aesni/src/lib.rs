#![cfg(target_arch = "x86_64")]
#![no_std]
#![feature(repr_simd)]
#![feature(asm)]

mod aes128;
mod aes192;
mod aes256;

pub use aes128::Aes128;
pub use aes192::Aes192;
pub use aes256::Aes256;

#[allow(non_camel_case_types)]
#[repr(simd)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct u64x2(u64, u64);


// One round of AES key schedule. Due to the limitations of inline assembly
// it's a bit more heavy on I-cache compared to code in the Intel AES-NI
// whitepaper (p. 24):
//
// https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf
//
// For more details read this document from p.21:
//
// https://www.cosic.esat.kuleuven.be/ecrypt/AESday/slides/Use_of_the_AES_Instruction_Set.pdf
