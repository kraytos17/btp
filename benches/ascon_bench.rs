use std::time::Duration;

use btp::ascon::{AsconAead, AsconHash};
use btp::present::{Present, modes as present_modes};
use btp::speck::{Speck64, modes as speck_modes};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const KEY_16: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const KEY_10: [u8; 10] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
const NONCE: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn custom_config() -> Criterion {
    Criterion::default()
        .sample_size(100)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
}

fn bench_ascon_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("ascon-aead128");

    const PT_SIZES: &[usize] = &[16, 64, 256, 1024];
    const AD_SIZES: &[usize] = &[0, 16, 64];

    for &pt_len in PT_SIZES {
        let pt = vec![0u8; pt_len];
        let mut ct = vec![0u8; pt_len];
        for &ad_len in AD_SIZES {
            let ad = vec![0u8; ad_len];

            group.throughput(Throughput::Bytes(pt_len as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("ad{ad_len}"), pt_len),
                &pt_len,
                |b, _| {
                    b.iter(|| {
                        let mut cipher = AsconAead::new(black_box(&KEY_16), black_box(&NONCE));
                        cipher.absorb_ad(black_box(&ad));
                        cipher.encrypt_in_place(black_box(&pt), black_box(&mut ct));
                        black_box(cipher.finalize(&KEY_16))
                    })
                },
            );
        }
    }
    group.finish();
}

fn bench_ascon_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("ascon-hash256");
    for pt_len in [16usize, 64, 256, 1024] {
        let pt = vec![0u8; pt_len];
        group.throughput(Throughput::Bytes(pt_len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(pt_len), &pt_len, |b, _| {
            b.iter(|| {
                let mut hash = AsconHash::new();
                hash.absorb(black_box(&pt));
                black_box(hash.finalize())
            })
        });
    }
    group.finish();
}

fn bench_ascon_phases(c: &mut Criterion) {
    let mut group = c.benchmark_group("ascon-phases");
    let ad = black_box([0u8; 16]);
    let pt = black_box([0u8; 16]);

    group.bench_function("init", |b| {
        b.iter(|| black_box(AsconAead::new(black_box(&KEY_16), black_box(&NONCE))))
    });

    group.bench_function("absorb_ad", |b| {
        b.iter_batched(
            || AsconAead::new(&KEY_16, &NONCE),
            |mut cipher| {
                cipher.absorb_ad(black_box(&ad));
                black_box(cipher)
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("encrypt", |b| {
        b.iter_batched(
            || {
                let mut cipher = AsconAead::new(&KEY_16, &NONCE);
                cipher.absorb_ad(&ad);
                (cipher, [0u8; 16])
            },
            |(mut cipher, mut ct)| {
                cipher.encrypt_in_place(black_box(&pt), black_box(&mut ct));
                black_box((cipher, ct))
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("finalize", |b| {
        b.iter_batched(
            || {
                let mut cipher = AsconAead::new(&KEY_16, &NONCE);
                cipher.absorb_ad(&ad);
                let mut ct = [0u8; 16];
                cipher.encrypt_in_place(&pt, &mut ct);
                cipher
            },
            |cipher| black_box(cipher.finalize(black_box(&KEY_16))),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_speck_modes(c: &mut Criterion) {
    const PT_SIZES: &[usize] = &[8, 16, 64, 256, 1024];

    let key_96 = [0x03020100u32, 0x0b0a0908, 0x13121110];
    let key_128 = [0x03020100u32, 0x0b0a0908, 0x13121110, 0x1b1a1918];
    let cipher_96 = Speck64::new(&key_96).unwrap();
    let cipher_128 = Speck64::new(&key_128).unwrap();
    let iv: [u8; 8] = [0x00; 8];

    macro_rules! speck_group {
        ($name:expr, $cipher:expr, $mode_fn:expr) => {{
            let mut group = c.benchmark_group($name);
            for &pt_len in PT_SIZES {
                let pt = vec![0u8; pt_len];
                let mut ct = vec![0u8; pt_len];
                group.throughput(Throughput::Bytes(pt_len as u64));
                group.bench_with_input(BenchmarkId::from_parameter(pt_len), &pt_len, |b, _| {
                    b.iter(|| {
                        $mode_fn(black_box($cipher), black_box(&pt), black_box(&mut ct));
                        black_box(&ct);
                    })
                });
            }
            group.finish();
        }};
        ($name:expr, $cipher:expr, $mode_fn:expr, $iv:expr) => {{
            let mut group = c.benchmark_group($name);
            for &pt_len in PT_SIZES {
                let pt = vec![0u8; pt_len];
                let mut ct = vec![0u8; pt_len];
                group.throughput(Throughput::Bytes(pt_len as u64));
                group.bench_with_input(BenchmarkId::from_parameter(pt_len), &pt_len, |b, _| {
                    b.iter(|| {
                        $mode_fn(
                            black_box($cipher),
                            black_box(&pt),
                            black_box(&mut ct),
                            black_box($iv),
                        );
                        black_box(&ct);
                    })
                });
            }
            group.finish();
        }};
    }

    speck_group!("speck-64-96-ecb", &cipher_96, speck_modes::encrypt_ecb);
    speck_group!("speck-64-96-cbc", &cipher_96, speck_modes::encrypt_cbc, iv);
    speck_group!("speck-64-96-ctr", &cipher_96, speck_modes::encrypt_ctr, iv);
    speck_group!("speck-64-128-ecb", &cipher_128, speck_modes::encrypt_ecb);
    speck_group!(
        "speck-64-128-cbc",
        &cipher_128,
        speck_modes::encrypt_cbc,
        iv
    );
    speck_group!(
        "speck-64-128-ctr",
        &cipher_128,
        speck_modes::encrypt_ctr,
        iv
    );
}

fn bench_present_modes(c: &mut Criterion) {
    const PT_SIZES: &[usize] = &[8, 16, 64, 256, 1024];

    let cipher_80 = Present::new(&KEY_10).unwrap();
    let cipher_128 = Present::new(&KEY_16).unwrap();
    let iv: [u8; 8] = [0x00; 8];

    macro_rules! present_group {
        ($name:expr, $cipher:expr, $mode_fn:expr) => {{
            let mut group = c.benchmark_group($name);
            group.measurement_time(Duration::from_secs(30));
            for &pt_len in PT_SIZES {
                let pt = vec![0u8; pt_len];
                let mut ct = vec![0u8; pt_len];
                group.throughput(Throughput::Bytes(pt_len as u64));
                group.bench_with_input(BenchmarkId::from_parameter(pt_len), &pt_len, |b, _| {
                    b.iter(|| {
                        $mode_fn(black_box($cipher), black_box(&pt), black_box(&mut ct));
                        black_box(&ct);
                    })
                });
            }
            group.finish();
        }};
        ($name:expr, $cipher:expr, $mode_fn:expr, $iv:expr) => {{
            let mut group = c.benchmark_group($name);
            group.measurement_time(Duration::from_secs(30));
            for &pt_len in PT_SIZES {
                let pt = vec![0u8; pt_len];
                let mut ct = vec![0u8; pt_len];
                group.throughput(Throughput::Bytes(pt_len as u64));
                group.bench_with_input(BenchmarkId::from_parameter(pt_len), &pt_len, |b, _| {
                    b.iter(|| {
                        $mode_fn(
                            black_box($cipher),
                            black_box(&pt),
                            black_box(&mut ct),
                            black_box($iv),
                        );
                        black_box(&ct);
                    })
                });
            }
            group.finish();
        }};
    }

    present_group!("present-80-ecb", &cipher_80, present_modes::encrypt_ecb);
    present_group!("present-80-cbc", &cipher_80, present_modes::encrypt_cbc, iv);
    present_group!("present-128-ecb", &cipher_128, present_modes::encrypt_ecb);
    present_group!(
        "present-128-cbc",
        &cipher_128,
        present_modes::encrypt_cbc,
        iv
    );
}

criterion_group! {
    name    = benches;
    config  = custom_config();
    targets =
        bench_ascon_aead,
        bench_ascon_hash,
        bench_ascon_phases,
        bench_speck_modes,
        bench_present_modes
}

criterion_main!(benches);
