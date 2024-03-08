# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Bump `cipher` to v0.5.0-pre.1; MSRV 1.65 ([#394])
- Bump `cipher` dependency to v0.5.0-pre.2 ([#398])
- Use `BlockCipherEncrypt`/`BlockCipherDecrypt` trait names ([#400])
- mark `to_u32` function as private ([#402])
- bump `cipher` dependency to `0.5.0-pre.4` ([#413])

[#394]: https://github.com/RustCrypto/block-ciphers/pull/394
[#398]: https://github.com/RustCrypto/block-ciphers/pull/398
[#400]: https://github.com/RustCrypto/block-ciphers/pull/400
[#402]: https://github.com/RustCrypto/block-ciphers/pull/402
[#413]: https://github.com/RustCrypto/block-ciphers/pull/413

## 0.1.2 (2023-04-15)
### Added
- `belt_wblock_enc`, `belt_wblock_dec`, and `to_u32` functions ([#362])

[#362]: https://github.com/RustCrypto/block-ciphers/pull/362

## 0.1.1 (2022-09-23)
### Added
- `belt_block_raw` function and `cipher` crate feature (enabled by default) ([#333])

[#333]: https://github.com/RustCrypto/block-ciphers/pull/333

## 0.1.0 (2022-09-14)
- Initial release ([#328])

[#328]: https://github.com/RustCrypto/block-ciphers/pull/328
