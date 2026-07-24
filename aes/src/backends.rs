pub(crate) mod soft;

#[cfg(all(target_arch = "aarch64", not(aes_backend = "soft")))]
pub(crate) mod aarch64_aes;

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "x86"),
    not(aes_backend = "soft")
))]
pub(crate) mod x86_aes;

#[cfg(all(
    any(aes_backend = "avx256", aes_backend = "avx512"),
    any(target_arch = "x86_64", target_arch = "x86"),
    not(aes_backend = "soft"),
))]
pub(crate) mod x86_vaes256;

#[cfg(all(
    aes_backend = "avx512",
    any(target_arch = "x86_64", target_arch = "x86"),
    not(aes_backend = "soft"),
))]
pub(crate) mod x86_vaes512;
