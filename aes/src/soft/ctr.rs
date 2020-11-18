//! AES in counter mode (a.k.a. AES-CTR)

use super::{Aes128, Aes192, Aes256};

/// AES-128 in CTR mode
#[cfg_attr(docsrs, doc(cfg(feature = "ctr")))]
pub type Aes128Ctr = ::ctr::Ctr128<Aes128>;

/// AES-192 in CTR mode
#[cfg_attr(docsrs, doc(cfg(feature = "ctr")))]
pub type Aes192Ctr = ::ctr::Ctr128<Aes192>;

/// AES-256 in CTR mode
#[cfg_attr(docsrs, doc(cfg(feature = "ctr")))]
pub type Aes256Ctr = ::ctr::Ctr128<Aes256>;
