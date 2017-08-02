#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#![no_std]
#![feature(repr_simd)]
#![feature(asm)]

mod aes128;
mod aes192;
mod aes256;
mod u64x2;

pub use aes128::Aes128;
pub use aes192::Aes192;
pub use aes256::Aes256;


// Intel AES-NI whitepaper:
//
// https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf
//
// For more details read this document from p.21:
//
// https://www.cosic.esat.kuleuven.be/ecrypt/AESday/slides/Use_of_the_AES_Instruction_Set.pdf
