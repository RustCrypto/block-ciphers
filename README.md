# RustCrypto: block ciphers

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]
[![HAZMAT][hazmat-image]][hazmat-link]

Collection of [block ciphers] written in pure Rust.

## Higher level constructions

Crates in this repository implement ONLY raw block cipher functionality defined by traits in the [`cipher`] crate.
In practice block ciphers are rarely used in isolation.
Instead, they usually play role of a building block for higher level constructions.
In RustCrypto such constructions are implemented generically over block ciphers in separate repositories:
- [AEADs](https://github.com/RustCrypto/AEADs): GCM, SIV, CCM, MGM, etc.
- [MACs](https://github.com/RustCrypto/MACs): CMAC, PMAC.
- [Block modes](https://github.com/RustCrypto/block-modes): CTR, CBC, CFB, etc.
- [Key wrapping](https://github.com/RustCrypto/key-wraps): AES-KW. 

Most users should use constructions defined in these repositories without directly relying on raw block cipher functionality.

[`cipher`]: https://docs.rs/cipher

## Warnings

Currently only the `aes` crate provides constant-time implementation and has received a third-party security audit.

Other crates in this repository are not implemented in a constant-time manner and have not yet received any formal cryptographic and security reviews.

It's generally recommended not to use other cipher implementations in this repository besides the `aes` crate.

**USE AT YOUR OWN RISK.**

## Supported algorithms

| Name | Crate name | crates.io | Docs | MSRV |
|------|------------|-----------|------|------|
| [AES] (Rijndael) | [`aes`] | [![crates.io](https://img.shields.io/crates/v/aes.svg)](https://crates.io/crates/aes) | [![Documentation](https://docs.rs/aes/badge.svg)](https://docs.rs/aes) | ![MSRV 1.85][msrv-1.85] |
| [ARIA] | [`aria`] | [![crates.io](https://img.shields.io/crates/v/aria.svg)](https://crates.io/crates/aria) | [![Documentation](https://docs.rs/aria/badge.svg)](https://docs.rs/aria) | ![MSRV 1.85][msrv-1.85] |
| [BelT] block cipher | [`belt-block`] | [![crates.io](https://img.shields.io/crates/v/belt-block.svg)](https://crates.io/crates/belt-block) | [![Documentation](https://docs.rs/belt-block/badge.svg)](https://docs.rs/belt-block) | ![MSRV 1.85][msrv-1.85] |
| [Blowfish] | [`blowfish`] | [![crates.io](https://img.shields.io/crates/v/blowfish.svg)](https://crates.io/crates/blowfish) | [![Documentation](https://docs.rs/blowfish/badge.svg)](https://docs.rs/blowfish) | ![MSRV 1.85][msrv-1.85] |
| [Camellia] | [`camellia`] | [![crates.io](https://img.shields.io/crates/v/camellia.svg)](https://crates.io/crates/camellia) | [![Documentation](https://docs.rs/camellia/badge.svg)](https://docs.rs/camellia) | ![MSRV 1.85][msrv-1.85] |
| [CAST5] (CAST-128) | [`cast5`] | [![crates.io](https://img.shields.io/crates/v/cast5.svg)](https://crates.io/crates/cast5) | [![Documentation](https://docs.rs/cast5/badge.svg)](https://docs.rs/cast5) | ![MSRV 1.85][msrv-1.85] |
| [CAST6] (CAST-256) | [`cast6`] | [![crates.io](https://img.shields.io/crates/v/cast6.svg)](https://crates.io/crates/cast6) | [![Documentation](https://docs.rs/cast6/badge.svg)](https://docs.rs/cast6) | ![MSRV 1.85][msrv-1.85] |
| [DES] + [3DES] (DEA, 3DEA) | [`des`] | [![crates.io](https://img.shields.io/crates/v/des.svg)](https://crates.io/crates/des) | [![Documentation](https://docs.rs/des/badge.svg)](https://docs.rs/des) | ![MSRV 1.85][msrv-1.85] |
| [IDEA] | [`idea`] | [![crates.io](https://img.shields.io/crates/v/idea.svg)](https://crates.io/crates/idea) | [![Documentation](https://docs.rs/idea/badge.svg)](https://docs.rs/idea) | ![MSRV 1.85][msrv-1.85] |
| [Kuznyechik] (GOST R 34.12-2015)  | [`kuznyechik`] | [![crates.io](https://img.shields.io/crates/v/kuznyechik.svg)](https://crates.io/crates/kuznyechik) | [![Documentation](https://docs.rs/kuznyechik/badge.svg)](https://docs.rs/kuznyechik) | ![MSRV 1.85][msrv-1.85] |
| [Magma] (GOST R 34.12-2015) | [`magma`] | [![crates.io](https://img.shields.io/crates/v/magma.svg)](https://crates.io/crates/magma) | [![Documentation](https://docs.rs/magma/badge.svg)](https://docs.rs/magma) | ![MSRV 1.85][msrv-1.85] |
| [RC2] (ARC2) | [`rc2`] | [![crates.io](https://img.shields.io/crates/v/rc2.svg)](https://crates.io/crates/rc2) | [![Documentation](https://docs.rs/rc2/badge.svg)](https://docs.rs/rc2) | ![MSRV 1.85][msrv-1.85] |
| [RC5] | [`rc5`] | [![crates.io](https://img.shields.io/crates/v/rc5.svg)](https://crates.io/crates/rc5) | [![Documentation](https://docs.rs/rc5/badge.svg)](https://docs.rs/rc5) | ![MSRV 1.85][msrv-1.85] |
| [Serpent] | [`serpent`] | [![crates.io](https://img.shields.io/crates/v/serpent.svg)](https://crates.io/crates/serpent) | [![Documentation](https://docs.rs/serpent/badge.svg)](https://docs.rs/serpent) | ![MSRV 1.85][msrv-1.85] |
| [SM4] | [`sm4`] | [![crates.io](https://img.shields.io/crates/v/sm4.svg)](https://crates.io/crates/sm4) | [![Documentation](https://docs.rs/sm4/badge.svg)](https://docs.rs/sm4) | ![MSRV 1.85][msrv-1.85] |
| [Speck] | [`speck-cipher`] | [![crates.io](https://img.shields.io/crates/v/speck-cipher.svg)](https://crates.io/crates/speck-cipher) | [![Documentation](https://docs.rs/speck-cipher/badge.svg)](https://docs.rs/speck-cipher) | ![MSRV 1.85][msrv-1.85] |
| [Threefish] | [`threefish`] | [![crates.io](https://img.shields.io/crates/v/threefish.svg)](https://crates.io/crates/threefish) | [![Documentation](https://docs.rs/threefish/badge.svg)](https://docs.rs/threefish) | ![MSRV 1.85][msrv-1.85] |
| [Twofish] | [`twofish`] | [![crates.io](https://img.shields.io/crates/v/twofish.svg)](https://crates.io/crates/twofish) | [![Documentation](https://docs.rs/twofish/badge.svg)](https://docs.rs/twofish) | ![MSRV 1.85][msrv-1.85] |
| [XTEA] | [`xtea`] | [![crates.io](https://img.shields.io/crates/v/xtea.svg)](https://crates.io/crates/xtea) | [![Documentation](https://docs.rs/xtea/badge.svg)](https://docs.rs/xtea) | ![MSRV 1.85][msrv-1.85] |

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
[msrv-1.85]: https://img.shields.io/badge/rustc-1.85.0+-blue.svg

[//]: # (crates)

[`aes`]: ./aes
[`aria`]: ./aria
[`belt-block`]: ./belt-block
[`blowfish`]: ./blowfish
[`camellia`]: ./camellia
[`cast5`]: ./cast5
[`cast6`]: ./cast6
[`des`]: ./des
[`idea`]: ./idea
[`kuznyechik`]: ./kuznyechik
[`magma`]: ./magma
[`rc2`]: ./rc2
[`rc5`]: ./rc5
[`serpent`]: ./serpent
[`sm4`]: ./sm4
[`speck-cipher`]: ./speck
[`threefish`]: ./threefish
[`twofish`]: ./twofish
[`xtea`]: ./xtea

[//]: # (links)

[block ciphers]: https://en.wikipedia.org/wiki/Block_cipher

[//]: # (algorithms)

[AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[ARIA]: https://en.wikipedia.org/wiki/ARIA_(cipher)
[BelT]: https://ru.wikipedia.org/wiki/BelT
[Blowfish]: https://en.wikipedia.org/wiki/Blowfish_(cipher)
[Camellia]: https://en.wikipedia.org/wiki/Camellia_(cipher)
[CAST5]: https://en.wikipedia.org/wiki/CAST-128
[CAST6]: https://en.wikipedia.org/wiki/CAST-256
[DES]: https://en.wikipedia.org/wiki/Data_Encryption_Standard
[3DES]: https://en.wikipedia.org/wiki/Triple_DES
[IDEA]: https://simple.wikipedia.org/wiki/International_Data_Encryption_Algorithm
[Kuznyechik]: https://en.wikipedia.org/wiki/Kuznyechik
[Magma]: https://en.wikipedia.org/wiki/GOST_(block_cipher)
[RC2]: https://en.wikipedia.org/wiki/RC2
[RC5]: https://en.wikipedia.org/wiki/RC5
[Serpent]: https://en.wikipedia.org/wiki/Serpent_(cipher)
[SM4]: https://en.wikipedia.org/wiki/SM4_(cipher)
[Speck]: https://en.wikipedia.org/wiki/Speck_(cipher)
[Threefish]: https://en.wikipedia.org/wiki/Threefish
[Twofish]: https://en.wikipedia.org/wiki/Twofish
[XTEA]: https://en.wikipedia.org/wiki/XTEA
