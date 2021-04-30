# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.8.1 (2021-04-30)
### Changed
- Remove unnecessary `NewBlockCipher` bounds ([#240])

[#240]: https://github.com/RustCrypto/block-ciphers/pull/240

## 0.8.0 (2021-04-29)
### Added
- `IvState` trait ([#227])

### Changed
- Upgrade to `cipher v0.3` ([#202])

### Added
- Infinite Garble Extension (IGE) block mode ([#211])

[#202]: https://github.com/RustCrypto/block-ciphers/pull/202
[#211]: https://github.com/RustCrypto/block-ciphers/pull/211
[#227]: https://github.com/RustCrypto/block-ciphers/pull/227

## 0.7.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#167])

[#167]: https://github.com/RustCrypto/block-ciphers/pull/167

## 0.6.1 (2020-08-14)
### Added
- `Clone` trait implementations ([#145])

[#145]: https://github.com/RustCrypto/block-ciphers/pull/145

## 0.6.0 (2020-08-07)
### Changed
- Bump `block-cipher` dependency to v0.8 and `block-padding` to v0.2 ([#138])

[#138]: https://github.com/RustCrypto/block-ciphers/pull/138

## 0.5.0 (2020-07-03)
### Changed
- Add `IvSize` associated type to the `BlockMode` trait ([#134])

[#134]: https://github.com/RustCrypto/block-ciphers/pull/134

## 0.4.0 (2020-06-07)
### Changed
- Upgrade to Rust 2018 edition ([#87])
- Bump `block-cipher` dependency to v0.7 ([#87])

[#87]: https://github.com/RustCrypto/block-ciphers/pull/87

## 0.3.3 (2019-04-28)

## 0.3.2 (2019-02-04)

## 0.3.1 (2018-12-27)

## 0.3.0 (2018-12-27)

## 0.2.0 (2018-10-04)

## 0.1.0 (2018-03-04)
