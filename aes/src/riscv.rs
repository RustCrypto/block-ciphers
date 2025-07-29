#![allow(clippy::incompatible_msrv)]

//! AES block cipher implementations for RISC-V using the Cryptography
//! Extensions
//!
//! Supported targets: rv64 (scalar)
//!
//! NOTE: rv32 (scalar) is not currently implemented, primarily due to the
//! difficulty in obtaining a suitable development environment (lack of distro
//! support and lack of precompiled toolchains), the effort required for
//! maintaining a test environment as 32-bit becomes less supported, and the
//! overall scarcity of relevant hardware. If someone has a specific need for
//! such an implementation, please open an issue.
//!
//! NOTE: These implementations are currently not enabled through
//! auto-detection. In order to use this implementation, you must enable the
//! appropriate target-features.
//!
//! Examining the module structure for this implementation should give you an
//! idea of how to specify these features in your own code.
//!
//! NOTE: AES-128, AES-192, and AES-256 are supported.

#[cfg(all(target_arch = "riscv64", aes_riscv_zkned))]
pub(crate) mod rv64;
