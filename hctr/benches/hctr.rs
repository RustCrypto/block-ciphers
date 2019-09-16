use core::convert::TryInto;

use criterion::*;

use ctr::{Ctr128, stream_cipher::{NewStreamCipher, SyncStreamCipher}};
use aes::block_cipher_trait::BlockCipher;

use aes::Aes128;
use aesni::Aes128Ctr;
use polyval::Polyval;

use hctr::Hctr;

fn bench(c: &mut Criterion) {
    const KB: usize = 1024;

    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "ctr-ni",
            |b, &&size| {
                let mut aes = Aes128Ctr::new(&Default::default(), &Default::default());
                let mut buf = core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| {
                    aes.apply_keystream(&mut buf);
                });
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "ctr",
            |b, &&size| {
                let aes = Aes128::new(&Default::default());
                let mut cipher = Ctr128::from_cipher(aes, &Default::default());
                let mut buf = core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| {
                    cipher.apply_keystream(&mut buf);
                });
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "memcpy",
            |b, &&size| {
                let buf = core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| {
                    buf.clone()
                });
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "hash",
            |b, &&size| {
                let hasher = Polyval::new(Default::default());
                let buf = core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| {
                    let mut hasher = hasher.clone();
                    for chunk in buf.chunks(16) {
                        hasher.input_block(chunk.try_into().unwrap());
                    }
                    hasher.result()
                });
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "seal",
            |b, &&size| {
                let hctr = Hctr::new([0u8; 32]);
                let mut buf = core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| hctr.seal_in_place(&mut buf, &[]));
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "open",
            |b, &&size| {
                let hctr = Hctr::new([0u8; 32]);
                let mut buf = core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| hctr.open_in_place(&mut buf, &[]));
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );
}

criterion_group!(benches, bench);
criterion_main!(benches);
