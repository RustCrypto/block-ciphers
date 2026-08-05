pub(crate) mod soft;

cpubits::cfg_if! {
    if #[cfg(aes_backend = "soft")] {
        // Do not add other backends if software backend is forced
    } else if #[cfg(target_arch = "aarch64")] {
        pub(crate) mod aarch64_aes;
    } else if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
        pub(crate) mod x86_aes;
        pub(crate) mod x86_vaes256;
        pub(crate) mod x86_vaes512;
    }
}
