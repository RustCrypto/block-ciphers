# RustCrypto: Serpent Cipher

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]
[![HAZMAT][hazmat-image]][hazmat-link]

Experimental pure Rust implementation of the [Serpent block cipher][1].

<img src="https://raw.githubusercontent.com/RustCrypto/meta/master/img/block-ciphers/serpent.png" width="200px">

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

This crate does not ensure ciphertexts are authentic (i.e. by using a MAC to
verify ciphertext integrity), which can lead to serious vulnerabilities
if used incorrectly!

No security audits of this crate have ever been performed, and it has not been
thoroughly assessed to ensure its operation is constant-time on common CPU
architectures.

USE AT YOUR OWN RISK!

## Configuration flags

You can modify crate using the following configuration flags:

- `serpent_no_unroll`: do not unroll rounds loop. Reduces binary size at the cost of slightly lower performance.

The flag can be enabled using RUSTFLAGS environmental variable (e.g. RUSTFLAGS="--cfg serpent_no_unroll") or by modifying .cargo/config.

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/serpent.svg
[crate-link]: https://crates.io/crates/serpent
[docs-image]: https://docs.rs/serpent/badge.svg
[docs-link]: https://docs.rs/serpent/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260039-block-ciphers
[build-image]: https://github.com/RustCrypto/block-ciphers/workflows/serpent/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/block-ciphers/actions?query=workflow%3Aserpent

[//]: # (general links)

[1]: https://en.wikipedia.org/wiki/Serpent_(cipher)
