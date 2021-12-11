# RustCrypto: block ciphers

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]
[![HAZMAT][hazmat-image]][hazmat-link]

Collection of [block ciphers] written in pure Rust.

## Warnings

Currently only the `aes` crate provides constant-time implementation and has received a third-party security audit.

Other crates in this repository are not implemented in a constant-time manner and have not yet received any formal cryptographic and security reviews.

It's generally recommended not to use other cipher implementations in this repository besides the `aes` crate.

**USE AT YOUR OWN RISK.**

## Supported algorithms

| Name | Crate name | crates.io | Docs | MSRV |
|------|------------|-----------|------|------|
| [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (Rijndael) | `aes` | [![crates.io](https://img.shields.io/crates/v/aes.svg)](https://crates.io/crates/aes) | [![Documentation](https://docs.rs/aes/badge.svg)](https://docs.rs/aes) | ![MSRV 1.56][msrv-1.56] |
| [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)) | `blowfish` | [![crates.io](https://img.shields.io/crates/v/blowfish.svg)](https://crates.io/crates/blowfish) | [![Documentation](https://docs.rs/blowfish/badge.svg)](https://docs.rs/blowfish) | ![MSRV 1.56][msrv-1.56] |
| [Camellia](https://en.wikipedia.org/wiki/Camellia_(cipher)) | `camellia` | [![crates.io](https://img.shields.io/crates/v/camellia.svg)](https://crates.io/crates/camellia) | [![Documentation](https://docs.rs/camellia/badge.svg)](https://docs.rs/camellia) | ![MSRV 1.56][msrv-1.56] |
| [CAST5](https://en.wikipedia.org/wiki/CAST-128) (CAST-128) | `cast5` | [![crates.io](https://img.shields.io/crates/v/cast5.svg)](https://crates.io/crates/cast5) | [![Documentation](https://docs.rs/cast5/badge.svg)](https://docs.rs/cast5) | ![MSRV 1.56][msrv-1.56] |
| [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) + [3DES](https://en.wikipedia.org/wiki/Triple_DES) (DEA, 3DEA) | `des` | [![crates.io](https://img.shields.io/crates/v/des.svg)](https://crates.io/crates/des) | [![Documentation](https://docs.rs/des/badge.svg)](https://docs.rs/des) | ![MSRV 1.56][msrv-1.56] |
| [IDEA](https://simple.wikipedia.org/wiki/International_Data_Encryption_Algorithm) | `idea` | [![crates.io](https://img.shields.io/crates/v/idea.svg)](https://crates.io/crates/idea) | [![Documentation](https://docs.rs/idea/badge.svg)](https://docs.rs/idea) | ![MSRV 1.56][msrv-1.56] |
| [Kuznyechik](https://en.wikipedia.org/wiki/Kuznyechik) (GOST R 34.12-2015)  | `kuznyechik` | [![crates.io](https://img.shields.io/crates/v/kuznyechik.svg)](https://crates.io/crates/kuznyechik) | [![Documentation](https://docs.rs/kuznyechik/badge.svg)](https://docs.rs/kuznyechik) | ![MSRV 1.56][msrv-1.56] |
| [Magma](https://en.wikipedia.org/wiki/GOST_(block_cipher)) (GOST R 34.12-2015) | `magma` | [![crates.io](https://img.shields.io/crates/v/magma.svg)](https://crates.io/crates/magma) | [![Documentation](https://docs.rs/magma/badge.svg)](https://docs.rs/magma) | ![MSRV 1.56][msrv-1.56] |
| [RC2](https://en.wikipedia.org/wiki/RC2) (ARC2) | `rc2` | [![crates.io](https://img.shields.io/crates/v/rc2.svg)](https://crates.io/crates/rc2) | [![Documentation](https://docs.rs/rc2/badge.svg)](https://docs.rs/rc2) | ![MSRV 1.56][msrv-1.56] |
| [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher)) | `serpent` | [![crates.io](https://img.shields.io/crates/v/serpent.svg)](https://crates.io/crates/serpent) | [![Documentation](https://docs.rs/serpent/badge.svg)](https://docs.rs/serpent) | ![MSRV 1.56][msrv-1.56] |
| [SM4](https://en.wikipedia.org/wiki/SM4_(cipher)) | `sm4` | [![crates.io](https://img.shields.io/crates/v/sm4.svg)](https://crates.io/crates/sm4) | [![Documentation](https://docs.rs/sm4/badge.svg)](https://docs.rs/sm4) | ![MSRV 1.56][msrv-1.56] |
| [Threefish](https://en.wikipedia.org/wiki/Threefish) | `threefish` | [![crates.io](https://img.shields.io/crates/v/threefish.svg)](https://crates.io/crates/threefish) | [![Documentation](https://docs.rs/threefish/badge.svg)](https://docs.rs/threefish) | ![MSRV 1.56][msrv-1.56] |
| [Twofish](https://en.wikipedia.org/wiki/Twofish) | `twofish` | [![crates.io](https://img.shields.io/crates/v/twofish.svg)](https://crates.io/crates/twofish) | [![Documentation](https://docs.rs/twofish/badge.svg)](https://docs.rs/twofish) | ![MSRV 1.56][msrv-1.56] |

### Minimum Supported Rust Version (MSRV) Policy

MSRV bump is considered a breaking change and will be performed only with a minor version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260039-block-ciphers
[deps-image]: https://deps.rs/repo/github/RustCrypto/block-ciphers/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/block-ciphers
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md
[msrv-1.56]: https://img.shields.io/badge/rustc-1.56.0+-blue.svg

[//]: # (links)

[block ciphers]: https://en.wikipedia.org/wiki/Block_cipher
