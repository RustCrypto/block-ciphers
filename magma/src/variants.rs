#![allow(clippy::doc_markdown)]
use crate::{Gost89, sboxes};

/// Block cipher defined in GOST R 34.12-2015 (Magma)
pub type Magma = Gost89<sboxes::Tc26>;
/// Block cipher defined in GOST 28147-89 with test S-box
pub type Gost89Test = Gost89<sboxes::TestSbox>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version A
pub type Gost89CryptoProA = Gost89<sboxes::CryptoProA>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version B
pub type Gost89CryptoProB = Gost89<sboxes::CryptoProB>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version C
pub type Gost89CryptoProC = Gost89<sboxes::CryptoProC>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version D
pub type Gost89CryptoProD = Gost89<sboxes::CryptoProD>;
