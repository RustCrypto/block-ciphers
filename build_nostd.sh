#!/bin/sh
# Due to the fact that cargo does not disable default features when we use
# cargo build --all --no-default-features we have to explicitly iterate over
# all crates (see https://github.com/rust-lang/cargo/issues/4753 )
DIRS=`ls -d */`
TARGET="thumbv7em-none-eabi"
cargo clean

for DIR in $DIRS; do
    # disable check for aesni, as it requires x86
    if [ $DIR = "target/" ] || [ $DIR = "aes/" ]
    then
        continue
    fi
    cd $DIR
    xargo build --no-default-features --target $TARGET || {
        echo $DIR failed
        exit 1
    }
    cd ..
done

cd aes/aes
xargo build --no-default-features --target $TARGET
cd ..
