use criterion::{
    criterion_group, criterion_main, measurement::CyclesPerByte, BenchmarkId,
    Criterion, Throughput,
};

#[cfg(feature = "aes")]
use aes::{block_cipher_trait::BlockCipher, Aes128};
#[cfg(feature = "aes")]
use ctr::{stream_cipher::SyncStreamCipher, Ctr128};
#[cfg(feature = "polyval")]
use polyval::{universal_hash::UniversalHash, Polyval};

#[cfg(all(feature = "aes", feature = "polyval"))]
use hctr::Aes128HctrPolyval;

const KB: usize = 1024;

fn throughput(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("throughput");

    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB].into_iter() {
        let mut buf = vec![0; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("memcpy", size), |b| {
            b.iter(|| buf.clone())
        });

        #[cfg(feature = "aes")]
        group.bench_function(BenchmarkId::new("aes-ctr", size), |b| {
            let cipher = Aes128::new(&Default::default());
            b.iter(|| {
                Ctr128::from_cipher(cipher, &Default::default())
                    .apply_keystream(&mut buf)
            })
        });

        #[cfg(feature = "polyval")]
        group.bench_function(BenchmarkId::new("polyval", size), |b| {
            let mut polyval = Polyval::new(&Default::default());
            b.iter(|| {
                polyval.update_padded(&buf);
                polyval.result_reset()
            })
        });

        #[cfg(all(feature = "aes", feature = "polyval"))]
        {
            group.bench_function(BenchmarkId::new("hctr-seal", size), |b| {
                let hctr = Aes128HctrPolyval::new(Default::default());
                b.iter(|| hctr.seal_in_place(&mut buf, &[]))
            });
            group.bench_function(BenchmarkId::new("hctr-open", size), |b| {
                let hctr = Aes128HctrPolyval::new(Default::default());
                b.iter(|| hctr.open_in_place(&mut buf, &[]))
            });
        }

        #[cfg(feature = "extended-bench")]
        {
            // FIXME: remove after aesni[ctr] performance isn't better than aes+ctr
            group.bench_function(BenchmarkId::new("aesni-ctr", size), |b| {
                use aesni::Aes128Ctr;
                use ctr::stream_cipher::NewStreamCipher;
                b.iter(|| {
                    let mut aes =
                        Aes128Ctr::new(&Default::default(), &Default::default());
                    aes.apply_keystream(&mut buf)
                })
            });

            group.bench_function(BenchmarkId::new("aez-encrypt", size), |b| {
                let aez = aez::Aez::new(&[0u8; 48]);
                let mut out = vec![0; *size];
                b.iter(|| aez.encrypt(&[0], &[], &buf, &mut out))
            });

            group.bench_function(BenchmarkId::new("aez-decrypt", size), |b| {
                let aez = aez::Aez::new(&[0u8; 48]);
                let mut ct = vec![0; *size];
                aez.encrypt(&[0], &[], &buf, &mut ct);
                let mut pt = vec![0; *size];
                b.iter(|| aez.decrypt(&[0], &[], &ct, &mut pt).unwrap())
            });
        }
    }

    group.finish();
}

criterion_group!(
    name = throughput_cpb;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = throughput
);
criterion_main!(throughput_cpb);
