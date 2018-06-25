#!/bin/sh
# test aes crate without aesni
cd aes/ &&
cargo test &&
cd .. &&

export RUSTDOCFLAGS="-C target-feature=+aes,+ssse3" &&
export RUSTFLAGS="-C target-feature=+aes,+ssse3" &&

cd aesni/ &&
cargo test &&
cd ../aes/ &&
cargo test
