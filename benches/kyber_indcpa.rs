use criterion::{
    black_box, criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup,
    BenchmarkId, Criterion,
};
use rand::{Rng, RngCore};

use crystals::{
    ciphertext::{Ciphertext, CompressedCiphertex},
    pke::*,
    poly::{
        kyber::{kyber_ciphertext_bytes, MSG_BYTES, NOISE_SEED_BYTES, POLYBYTES},
        UNIFORM_SEED_BYTES,
    },
    CPASecretKey, PublicKey,
};
use crystals_cref::{kyber as cref, randombytes::randombytes_push_bytes};

fn bench_kyber_keygen<M: Measurement, const K: usize>(group: &mut BenchmarkGroup<M>) {
    let mut rng = rand::thread_rng();

    let mut entropy = [0u8; KYBER_SYMBYTES];
    rng.fill(entropy.as_mut());
    randombytes_push_bytes(&entropy); // we need to push for every test, but that would add an unfair overhead to the C timings

    let mut sk = CPASecretKey::<K>::default();
    let mut pk = PublicKey::<K>::default();

    group.bench_function(BenchmarkId::new("Rust", K), |b| {
        b.iter(|| {
            KyberPke::<K>::keypair(black_box(&entropy), black_box(&mut sk), black_box(&mut pk))
        })
    });

    let mut pk_ref = vec![0u8; POLYBYTES * K + UNIFORM_SEED_BYTES];
    let mut sk_ref = vec![0u8; POLYBYTES * K];

    group.bench_function(BenchmarkId::new("C", K), |b| {
        b.iter(|| {
            cref::indcpa_keypair::<K>(&mut pk_ref, sk_ref.as_mut_slice());
        })
    });
}

fn bench_kyber_encrypt<M: Measurement, const K: usize>(group: &mut BenchmarkGroup<M>) {
    let mut rng = rand::thread_rng();

    let mut entropy = [0u8; KYBER_SYMBYTES];
    rng.fill(entropy.as_mut());

    let mut sk = CPASecretKey::<K>::default();
    let mut pk = PublicKey::<K>::default();
    keypair(&entropy, &mut sk, &mut pk);

    let mut msg = [0u8; MSG_BYTES];
    rng.fill(msg.as_mut());
    let mut coins = [0u8; NOISE_SEED_BYTES];
    rng.fill(coins.as_mut());

    let mut pk_ref = Vec::new();

    for b in pk.bytes {
        pk_ref.extend_from_slice(&b);
    }
    pk_ref.extend_from_slice(&pk.seed);

    // let mut pk_ref = vec![0u8; (POLYBYTES * K) + UNIFORM_SEED_BYTES];
    // let mut sk_ref = vec![0u8; POLYBYTES * K];
    type CT23<const K: usize> = Ciphertext<4, 10, K>;
    type CT4<const K: usize> = Ciphertext<5, 11, K>;

    match K {
        2 | 3 => {
            let mut ct = CT23::<K>::default();
            group.bench_function(BenchmarkId::new("Rust", K), |b| {
                b.iter(|| {
                    KyberPke::<K>::encrypt(
                        black_box(&msg),
                        black_box(&pk),
                        black_box(&coins),
                        black_box(&mut ct),
                    )
                })
            });
        }
        4 | _ => {
            let mut ct = CT4::<K>::default();
            group.bench_function(BenchmarkId::new("Rust", K), |b| {
                b.iter(|| {
                    KyberPke::<K>::encrypt(
                        black_box(&msg),
                        black_box(&pk),
                        black_box(&coins),
                        black_box(&mut ct),
                    )
                })
            });
        }
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    {
        use crystals::ciphertext::VecCipherText;
        let mut ct = VecCipherText::<K>::default();
        group.bench_function(BenchmarkId::new("Rust/VecCipherText", K), |b| {
            b.iter(|| {
                KyberPke::<K>::encrypt(
                    black_box(&msg),
                    black_box(&pk),
                    black_box(&coins),
                    black_box(&mut ct),
                )
            })
        });
    }

    let mut ct = vec![0u8; kyber_ciphertext_bytes::<K>()];

    group.bench_function(BenchmarkId::new("C", K), |b| {
        b.iter(|| {
            cref::indcpa_enc::<K>(
                black_box(&mut ct),
                black_box(&msg),
                black_box(&pk_ref),
                black_box(&coins),
            )
        })
    });
}

fn bench_kyber_decrypt<M: Measurement, const K: usize>(group: &mut BenchmarkGroup<M>) {
    let mut rng = rand::thread_rng();

    let mut entropy = [0u8; KYBER_SYMBYTES];
    rng.fill(entropy.as_mut());

    let mut sk = CPASecretKey::<K>::default();
    let mut pk = PublicKey::<K>::default();
    keypair(&entropy, &mut sk, &mut pk);

    let mut msg = [0u8; MSG_BYTES];

    // let mut pk_ref = vec![0u8; (POLYBYTES * K) + UNIFORM_SEED_BYTES];
    // let mut sk_ref = vec![0u8; POLYBYTES * K];
    type CT23<const K: usize> = Ciphertext<4, 10, K>;
    type CT4<const K: usize> = Ciphertext<5, 11, K>;

    match K {
        2 | 3 => {
            let mut ct = CT23::<K>::default();
            rng.fill(ct.poly_bytes_mut());
            rng.fill(ct.polyvec_bytes_mut());

            group.bench_function(BenchmarkId::new("Rust", K), |b| {
                b.iter(|| {
                    KyberPke::<K>::decrypt(black_box(&ct), black_box(&sk), black_box(&mut msg))
                })
            });
        }
        4 | _ => {
            let mut ct = CT4::<K>::default();
            rng.fill(ct.poly_bytes_mut());
            rng.fill(ct.polyvec_bytes_mut());

            group.bench_function(BenchmarkId::new("Rust", K), |b| {
                b.iter(|| {
                    KyberPke::<K>::decrypt(black_box(&ct), black_box(&sk), black_box(&mut msg))
                })
            });
        }
    }
    #[cfg(any(feature = "std", feature = "alloc"))]
    {
        use crystals::ciphertext::VecCipherText;
        let mut ct = VecCipherText::<K>::default();
        rng.fill(ct.poly_bytes_mut());
        rng.fill(ct.polyvec_bytes_mut());

        group.bench_function(BenchmarkId::new("Rust/VecCipherText", K), |b| {
            b.iter(|| KyberPke::<K>::decrypt(black_box(&ct), black_box(&sk), black_box(&mut msg)))
        });
    }

    let mut ct = vec![0u8; kyber_ciphertext_bytes::<K>()];
    rng.fill_bytes(ct.as_mut());

    group.bench_function(BenchmarkId::new("C", K), |b| {
        b.iter(|| {
            cref::indcpa_dec::<K>(black_box(&mut msg), black_box(&ct), black_box(&sk.bytes()))
        })
    });
}

pub fn kyber_indcpa_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber INDCPA encrypt");

    bench_kyber_encrypt::<_, 2>(&mut group);
    bench_kyber_encrypt::<_, 3>(&mut group);
    bench_kyber_encrypt::<_, 4>(&mut group);

    group.finish();
}

pub fn kyber_indcpa_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber INDCPA decrypt");

    bench_kyber_decrypt::<_, 2>(&mut group);
    bench_kyber_decrypt::<_, 3>(&mut group);
    bench_kyber_decrypt::<_, 4>(&mut group);

    group.finish();
}

pub fn kyber_indcpa_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber INDCPA keygen");

    bench_kyber_keygen::<_, 2>(&mut group);
    bench_kyber_keygen::<_, 3>(&mut group);
    bench_kyber_keygen::<_, 4>(&mut group);

    group.finish();
}

criterion_group! {
    name = kyber_indcpa;
    config = Criterion::default()
        .significance_level(0.035)
        .noise_threshold(0.02)
        .measurement_time(core::time::Duration::from_secs(10))
        .sample_size(500);
    targets = kyber_indcpa_encrypt, kyber_indcpa_decrypt, kyber_indcpa_keygen
}

criterion_main!(kyber_indcpa);
