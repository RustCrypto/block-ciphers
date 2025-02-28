# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (UNRELEASED)
### Changed
- Bump `cipher` dependency to v0.5
- Edition changed to 2024 and MSRV bumped to 1.85 ([#472])
- Relax MSRV policy and allow MSRV bumps in patch releases ([#477])
- Unlock parameter size, add u128 and u8 word size support ([#382])

### Deprecated
- Old predefined RC5 cipher types ([#382])

[#382]: https://github.com/RustCrypto/block-ciphers/pull/382
[#472]: https://github.com/RustCrypto/block-ciphers/pull/472
[#477]: https://github.com/RustCrypto/block-ciphers/pull/477

## 0.0.1 (2023-02-10)
- Initial release
