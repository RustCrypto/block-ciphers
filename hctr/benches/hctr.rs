#[cfg(feature = "polyval")]
use core::convert::TryInto;

use criterion::*;

#[cfg(feature = "aesni-bench")]
use aesni::Aes128Ctr;
#[cfg(feature = "aesni-bench")]
use ctr::stream_cipher::NewStreamCipher;

#[cfg(feature = "aes")]
use aes::{block_cipher_trait::BlockCipher, Aes128};
#[cfg(feature = "aes")]
use ctr::{stream_cipher::SyncStreamCipher, Ctr128};
#[cfg(feature = "polyval")]
use polyval::{universal_hash::UniversalHash, Polyval};

#[cfg(all(feature = "aes", feature = "polyval"))]
use hctr::Aes128HctrPolyval;

fn bench(c: &mut Criterion) {
    const KB: usize = 1024;

    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "memcpy",
            |b, &&size| {
                let buf =
                    core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| buf.clone());
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    // FIXME: remove after aesni[ctr] performance isn't better than aes+ctr
    #[cfg(feature = "aesni-bench")]
    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "ctr-ni",
            |b, &&size| {
                let mut aes =
                    Aes128Ctr::new(&Default::default(), &Default::default());
                let mut buf =
                    core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| {
                    aes.apply_keystream(&mut buf);
                });
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    #[cfg(feature = "aes")]
    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "ctr",
            |b, &&size| {
                let aes = Aes128::new(&Default::default());
                let mut cipher = Ctr128::from_cipher(aes, &Default::default());
                let mut buf =
                    core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| {
                    cipher.apply_keystream(&mut buf);
                });
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    #[cfg(feature = "polyval")]
    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "polyval",
            |b, &&size| {
                let hasher = Polyval::new(&Default::default());
                let buf =
                    core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| {
                    let mut hasher = hasher.clone();
                    for chunk in buf.chunks(16) {
                        hasher.update_block(chunk.try_into().unwrap());
                    }
                    hasher.result()
                });
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    #[cfg(all(feature = "aes", feature = "polyval"))]
    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "seal",
            |b, &&size| {
                let hctr = Aes128HctrPolyval::new(Default::default());
                let mut buf =
                    core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| hctr.seal_in_place(&mut buf, &[]));
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );

    #[cfg(all(feature = "aes", feature = "polyval"))]
    c.bench(
        "throughput",
        ParameterizedBenchmark::new(
            "open",
            |b, &&size| {
                let hctr = Aes128HctrPolyval::new(Default::default());
                let mut buf =
                    core::iter::repeat(0u8).take(size).collect::<Vec<_>>();
                b.iter(|| hctr.open_in_place(&mut buf, &[]));
            },
            &[KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 1280],
        )
        .throughput(|elems| Throughput::Bytes(**elems as u64)),
    );
}

criterion_group!(benches, bench);
criterion_main!(benches);
