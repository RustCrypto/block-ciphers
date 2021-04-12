# RustCrypto: CFB

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Generic implementation of the [Cipher Feedback][CFB] (CFB) block cipher mode
of operation.

<img src="https://raw.githubusercontent.com/RustCrypto/meta/master/img/block-ciphers/modes/cfb_enc.svg" width="50%"><img src="https://raw.githubusercontent.com/RustCrypto/meta/master/img/block-ciphers/modes/cfb_dec.svg" width="50%">

See [documentation][cipher-doc] of the `cipher` crate for additional information.

## Minimum Supported Rust Version

Rust **1.41** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

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

[crate-image]: https://img.shields.io/crates/v/cfb-mode.svg
[crate-link]: https://crates.io/crates/cfb-mode
[docs-image]: https://docs.rs/cfb-mode/badge.svg
[docs-link]: https://docs.rs/cfb-mode/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260039-block-ciphers
[build-image]: https://github.com/RustCrypto/block-ciphers/workflows/cfb-mode/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/block-ciphers/actions?query=workflow%cfb-mode

[//]: # (general links)

[CFB]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)
[cipher-doc]: https://docs.rs/cipher/
