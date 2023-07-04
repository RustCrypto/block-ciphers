use crate::core::RC6;
use cipher::typenum::{U12, U16, U20, U24, U4, U8};

pub type RC6_8_12_4 = RC6<u8, U12, U4>;
pub type RC6_16_16_8 = RC6<u16, U16, U8>;
pub type RC6_32_20_16 = RC6<u32, U20, U8>;
pub type RC6_64_24_24 = RC6<u64, U24, U24>;
