# rust-crypto's block ciphers [![Build Status](https://travis-ci.org/RustCrypto/block-ciphers.svg?branch=master)](https://travis-ci.org/RustCrypto/block-ciphers)
Collection of block cipher algorithms written in pure Rust. This is the part
of RustCrypto project.

## Warnings

Currently only `aesni` crate provides constant-time implementation.
If you do not really know what you are doing it's generally recommended not to
use other cipher implementations in this repository.

Additionally crates in this repository have not yet received any formal
cryptographic and security reviews.

**USE AT YOUR OWN RISK.**

## Supported algorithms
| Name     | Alt name   | Crates.io  | Documentation  |
| ------------- |:-------------:| :-----:| :-----:|
| [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)) |   | [![crates.io](https://img.shields.io/crates/v/blowfish.svg)](https://crates.io/crates/blowfish) | [![Documentation](https://docs.rs/blowfish/badge.svg)](https://docs.rs/blowfish) |
| [Magma](https://en.wikipedia.org/wiki/GOST_(block_cipher)) | GOST 28147-89 and GOST R 34.12-2015 | [![crates.io](https://img.shields.io/crates/v/magma.svg)](https://crates.io/crates/magma) | [![Documentation](https://docs.rs/magma/badge.svg)](https://docs.rs/magma) |
| [Kuznyechik](https://en.wikipedia.org/wiki/Kuznyechik) |  GOST R 34.12-2015  | [![crates.io](https://img.shields.io/crates/v/kuznyechik.svg)](https://crates.io/crates/kuznyechik) | [![Documentation](https://docs.rs/kuznyechik/badge.svg)](https://docs.rs/kuznyechik) |
| [RC2](https://en.wikipedia.org/wiki/RC2) |  ARC2  | [![crates.io](https://img.shields.io/crates/v/rc2.svg)](https://crates.io/crates/rc2) | [![Documentation](https://docs.rs/rc2/badge.svg)](https://docs.rs/rc2) |

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
