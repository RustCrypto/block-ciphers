pub mod autodetect;
// The SM4 crypto extension can only be detected at runtime on Linux/Android,
// so the `sm4e` backend and its `intrinsics` are compiled only for those OSes.
#[cfg(any(target_os = "linux", target_os = "android"))]
mod intrinsics;
mod neon;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod sm4e;
