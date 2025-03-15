pub mod autodetect;
mod intrinsics;
mod neon;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod sm4e;
