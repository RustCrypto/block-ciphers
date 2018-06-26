#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
compile_error!("crate can only be used for x86 and x86_64 architectures");

#[cfg(all(
    feature = "ctr",
    not(all(target_feature = "aes", target_feature = "sse2", target_feature = "ssse3")),
))]
compile_error!(
    "enable aes and ssse3 target features, e.g. with \
    RUSTFLAGS=\"-C target-feature=+aes,+ssse3\" enviromental variable"
);

#[cfg(all(
    not(feature = "ctr"),
    not(all(target_feature = "aes", target_feature = "sse2")),
))]
compile_error!(
    "enable aes target feature, e.g. with \
    RUSTFLAGS=\"-C target-feature=+aes\" enviromental variable"
);
