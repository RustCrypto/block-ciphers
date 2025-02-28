# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (UNRELEASED)
### Changed
- Bump `cipher` dependency to v0.5
- Mark `to_u32` function as private ([#402])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#472])
- Relax MSRV policy and allow MSRV bumps in patch releases ([#477])

[#402]: https://github.com/RustCrypto/block-ciphers/pull/402
[#472]: https://github.com/RustCrypto/block-ciphers/pull/472
[#477]: https://github.com/RustCrypto/block-ciphers/pull/477

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
