#!/bin/sh
# test aes crate without aesni
cd aes/ &&
cargo test &&
cd .. &&

export RUSTDOCFLAGS="-C target-feature=+aes" &&
export RUSTFLAGS="-C target-feature=+aes" &&

cd aesni/ &&
cargo test &&
cd ../aes/ &&
cargo test
