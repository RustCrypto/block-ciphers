use std::collections::HashSet;

fn main() {
    let needs_soft = needs_soft();
    if needs_soft {
        println!("cargo::rustc-cfg=__enable_aes_soft_backend");
    }
}

/// Returns whether the soft backend is required.
///
/// The soft backend may not be required if the target's features are
/// sufficient for one of the accelerated backends and the user did not
/// explicitly opt into the soft backend.
fn needs_soft() -> bool {
    if std::env::var("CARGO_CFG_AES_BACKEND").is_ok_and(|value| value == "soft") {
        return true;
    }

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("missing target_arch");
    let target_features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let target_features = target_features.split(',').collect::<HashSet<_>>();
    let miri = std::env::var("CARGO_CFG_MIRI").is_ok();

    match &*target_arch {
        "x86" | "x86_64" => !target_features.contains("aes"),
        "aarch64" if !miri => !target_features.contains("aes"),
        _ => true,
    }
}
