# RustCrypto: block ciphers
[![Build Status](https://travis-ci.org/RustCrypto/block-ciphers.svg?branch=master)](https://travis-ci.org/RustCrypto/block-ciphers) [![dependency status](https://deps.rs/repo/github/RustCrypto/block-ciphers/status.svg)](https://deps.rs/repo/github/RustCrypto/block-ciphers)

Collection of [block ciphers][1] and [block modes][2] written in pure Rust.

## Warnings

Currently only AES crates provide constant-time implementations.
If you do not really know what you are doing it's generally recommended not to
use other cipher implementations in this repository.

Additionally crates in this repository have not yet received any formal
cryptographic and security reviews.

**USE AT YOUR OWN RISK.**

## Supported algorithms
| Name     | Alt name   | Crate name | crates.io | Docs |
| ------------- |:-------------:| :-----:| :-----:| :-----:|
| [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) | Rijndael | `aes` <br/><br/> `aesni` <br/><br/> `aes-soft` | [![crates.io](https://img.shields.io/crates/v/aes.svg)](https://crates.io/crates/aes) <br/><br/> [![crates.io](https://img.shields.io/crates/v/aesni.svg)](https://crates.io/crates/aesni)  <br/><br/> [![crates.io](https://img.shields.io/crates/v/aes-soft.svg)](https://crates.io/crates/aes-soft) | [![Documentation](https://docs.rs/aes/badge.svg)](https://docs.rs/aes)  <br/><br/> [![Documentation](https://docs.rs/aesni/badge.svg)](https://docs.rs/aesni)  <br/><br/> [![Documentation](https://docs.rs/aes-soft/badge.svg)](https://docs.rs/aes-soft) |
| [Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher)) |   | `blowfish` | [![crates.io](https://img.shields.io/crates/v/blowfish.svg)](https://crates.io/crates/blowfish) | [![Documentation](https://docs.rs/blowfish/badge.svg)](https://docs.rs/blowfish) |
| [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) + [3DES](https://en.wikipedia.org/wiki/Triple_DES) |  DEA + 3DEA  | `des` | [![crates.io](https://img.shields.io/crates/v/des.svg)](https://crates.io/crates/des) | [![Documentation](https://docs.rs/des/badge.svg)](https://docs.rs/des) |
| [Kuznyechik](https://en.wikipedia.org/wiki/Kuznyechik) |  GOST R 34.12-2015  | `kuznyechik` | [![crates.io](https://img.shields.io/crates/v/kuznyechik.svg)](https://crates.io/crates/kuznyechik) | [![Documentation](https://docs.rs/kuznyechik/badge.svg)](https://docs.rs/kuznyechik) |
| [Magma](https://en.wikipedia.org/wiki/GOST_(block_cipher)) | GOST 28147-89 and GOST R 34.12-2015 | `magma` | [![crates.io](https://img.shields.io/crates/v/magma.svg)](https://crates.io/crates/magma) | [![Documentation](https://docs.rs/magma/badge.svg)](https://docs.rs/magma) |
| [RC2](https://en.wikipedia.org/wiki/RC2) |  ARC2  | `rc2` | [![crates.io](https://img.shields.io/crates/v/rc2.svg)](https://crates.io/crates/rc2) | [![Documentation](https://docs.rs/rc2/badge.svg)](https://docs.rs/rc2) |
| [Twofish](https://en.wikipedia.org/wiki/Twofish) | | `twofish` | [![crates.io](https://img.shields.io/crates/v/twofish.svg)](https://crates.io/crates/twofish) | [![Documentation](https://docs.rs/twofish/badge.svg)](https://docs.rs/twofish) |

### Minimum Rust version
All crates in this repository support Rust 1.22 or higher. (except `aesni` and
`aes` crates, which require Rust 1.27) In future minimum supported Rust version
can be changed, but it will be done with the minor version bump.

## Usage
Block cipher crates provide only bare block cipher implementations. For most
applications you will need to use some [block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
which are generically implemented in the [`block-modes`](https://docs.rs/block-modes/) crate.

Some block modes (CTR, CFB, OFV) transform block ciphers into stream ciphers.Such modes are published under separate crates in the
[RustCrypto/stream-ciphers][5] repository.

Lets use AES128-CBC with [PKCS7][3] padding to show an example:

```rust
#[macro_use] extern crate hex_literal;
extern crate aes_soft as aes;
extern crate block_modes;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use aes::Aes128;

// create an alias for convinience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

let key = hex!("000102030405060708090a0b0c0d0e0f");
let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
let plaintext = b"Hello world!";
let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();

// buffer must have enough space for message+padding
let mut buffer = [0u8; 32];
// copy message to the buffer
let pos = plaintext.len();
buffer[..pos].copy_from_slice(plaintext);
let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();

assert_eq!(ciphertext, hex!("1b7a4c403124ae2fb52bedc534d82fa8"));

// re-create cipher mode instance and decrypt the message
let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
let mut buf = ciphertext.to_vec();
let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

assert_eq!(decrypted_ciphertext, plaintext);
```

With an enabled `std` feature (which is enabled by default) you can use
`encrypt_vec` and `descrypt_vec` methods:

```rust
let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
let ciphertext = cipher.encrypt_vec(plaintext);

assert_eq!(ciphertext, hex!("1b7a4c403124ae2fb52bedc534d82fa8"));

let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
let decrypted_ciphertext = cipher.decrypt_vec(&ciphertext).unwrap();

assert_eq!(decrypted_ciphertext, plaintext);
```

Note that this example does not use any authentification which can lead to
serious vulnarabilities! For Message Authentication Code implementations take
a look at [RustCrypto/MACs][4] repository.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[1]: https://en.wikipedia.org/wiki/Block_cipher
[2]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
[3]: https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS%235_and_PKCS%237
[4]: https://github.com/RustCrypto/MACs
[5]: https://github.com/RustCrypto/stream-ciphers
