//! ⚠️ Low-level "hazmat" AES functions.
//!
//! # ☢️️ WARNING: HAZARDOUS API ☢️
//!
//! This module contains an extremely low-level cryptographic primitive
//! which is likewise extremely difficult to use correctly.
//!
//! There are very few valid uses cases for this API. It's intended to be used
//! for implementing well-reviewed higher-level constructions.
//!
//! We do NOT recommending using it to implement any algorithm which has not
//! received extensive peer review by cryptographers.

use crate::Block;

#[cfg(all(target_arch = "aarch64", feature = "armv8"))]
use crate::armv8::hazmat as intrinsics;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use crate::ni::hazmat as intrinsics;

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    all(target_arch = "aarch64", feature = "armv8")
)))]
compile_error!("the `hazmat` feature is currently only available on x86/x86-64 or aarch64");

cpufeatures::new!(aes_intrinsics, "aes");

/// ⚠️ AES cipher (encrypt) round function.
///
/// This API performs the following steps as described in FIPS 197 Appendix C:
///
/// - `s_box`: state after `SubBytes()`
/// - `s_row`: state after `ShiftRows()`
/// - `m_col`: state after `MixColumns()`
/// - `k_sch`: key schedule value for `round[r]`
///
/// This series of operations is equivalent to the Intel AES-NI `AESENC` instruction.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// Use this function with great care! See the [module-level documentation][crate::round]
/// for more information.
pub fn cipher_round(block: &mut Block, round_key: &Block) {
    if aes_intrinsics::get() {
        unsafe { intrinsics::cipher_round(block, round_key) };
    } else {
        todo!("soft fallback for AES hazmat functions is not yet implemented");
    }
}

/// ⚠️ AES equivalent inverse cipher (decrypt) round function.
///
/// This API performs the following steps as described in FIPS 197 Appendix C:
///
/// - `is_box`: state after `InvSubBytes()`
/// - `is_row`: state after `InvShiftRows()`
/// - `im_col`: state after `InvMixColumns()`
/// - `ik_sch`: key schedule value for `round[r]`
///
/// This series of operations is equivalent to the Intel AES-NI `AESDEC` instruction.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// Use this function with great care! See the [module-level documentation][crate::round]
/// for more information.
pub fn equiv_inv_cipher_round(block: &mut Block, round_key: &Block) {
    if aes_intrinsics::get() {
        unsafe { intrinsics::equiv_inv_cipher_round(block, round_key) };
    } else {
        todo!("soft fallback for AES hazmat functions is not yet implemented");
    }
}

/// ⚠️ AES inverse mix columns function.
///
/// This function is equivalent to the Intel AES-NI `AESIMC` instruction.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// Use this function with great care! See the [module-level documentation][crate::round]
/// for more information.
pub fn inv_mix_columns(block: &mut Block) {
    if aes_intrinsics::get() {
        unsafe { intrinsics::inv_mix_columns(block) };
    } else {
        todo!("soft fallback for AES hazmat functions is not yet implemented");
    }
}
