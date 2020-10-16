# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#167])

[#167]: https://github.com/RustCrypto/block-ciphers/pull/167

## 0.3.0 (2020-08-12)
### Changed
- Bump `stream-cipher` dependency to v0.7 ([#158])

[#158]: https://github.com/RustCrypto/block-ciphers/pull/158

## 0.2.0 (2020-08-12)
### Fixed
- CFB mode ([#144])

### Changed
- Split `GostCtr` into `GostCtr128` and `GostCtr64` types ([#144])

[#144]: https://github.com/RustCrypto/block-ciphers/pull/144

## 0.1.0 (2020-07-03) [YANKED]
- Initial release ([#134])

[#134]: https://github.com/RustCrypto/block-ciphers/pull/134
