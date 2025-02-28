# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.9.0 (UNRELEASED)
### Changed
- Bump `cipher` dependency to v0.5
- Edition changed to 2024 and MSRV bumped to 1.85 ([#472])
- Relax MSRV policy and allow MSRV bumps in patch releases ([#477])
- Use const eval to generate tables ([#451])

### Fixed
- Fix kuznyechik 32bit build ([#406])

[#406]: https://github.com/RustCrypto/block-ciphers/pull/406
[#451]: https://github.com/RustCrypto/block-ciphers/pull/451
[#472]: https://github.com/RustCrypto/block-ciphers/pull/472
[#477]: https://github.com/RustCrypto/block-ciphers/pull/477

## 0.8.2 (2023-08-06)
### Fixed
- `Drop` implementations in the software backend with enabled `zeroize` feature ([#311])

[#311]: https://github.com/RustCrypto/block-ciphers/pull/311

## 0.8.1 (2022-02-17)
### Fixed
- Minimal versions build ([#303])

[#303]: https://github.com/RustCrypto/block-ciphers/pull/303

## 0.8.0 (2022-02-10)
### Changed
- Bump `cipher` dependency to v0.4 ([#284])

### Added
- Encrypt-only `KuznyechikEnc` and decrypt-only `KuznyechikDec` types ([#284])

[#284]: https://github.com/RustCrypto/block-ciphers/pull/284

## 0.7.2 (2021-08-26)
### Added
- Parallel block processing for SSE2 backend ([#278])

[#278]: https://github.com/RustCrypto/block-ciphers/pull/278

## 0.7.1 (2021-05-20)
### Added
- SSE2-based implementation ([#261])

[#261]: https://github.com/RustCrypto/block-ciphers/pull/261

## 0.7.0 (2021-04-29)
### Changed
- Bump `cipher` dependency to v0.3 ([#235])

[#235]: https://github.com/RustCrypto/block-ciphers/pull/235

## 0.6.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#167])

[#167]: https://github.com/RustCrypto/block-ciphers/pull/167

## 0.5.0 (2020-08-07)
### Changed
- Bump `block-cipher` dependency to v0.8 ([#138])
- Bump `opaque-debug` dependency to v0.3 ([#140])

[#138]: https://github.com/RustCrypto/block-ciphers/pull/138
[#140]: https://github.com/RustCrypto/block-ciphers/pull/140

## 0.4.1 (2020-07-10)
### Changed
- Improved performance by unrolling loops ([#137])

[#137]: https://github.com/RustCrypto/block-ciphers/pull/137

## 0.4.0 (2020-07-03)
### Changed
- Bump `block-cipher` dependency to v0.7 ([#92])
- Upgrade to Rust 2018 edition ([#92])

### Fixed
- Byte order ([#118])

[#118]: https://github.com/RustCrypto/block-ciphers/pull/118
[#92]: https://github.com/RustCrypto/block-ciphers/pull/92

## 0.3.0 (2018-12-23)

## 0.2.0 (2017-11-26)

## 0.1.1 (2017-01-12)

## 0.1.0 (2017-01-12)
