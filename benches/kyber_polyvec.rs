use core::time::Duration;
use criterion::{
    black_box, criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup,
    BenchmarkId, Criterion,
};
use rand::Rng;

use krystals::polyvec::{KyberPolyVec, PolynomialVector};
use crystals_cref::kyber as cref;

fn kyber_ntt_bench_gen<M: Measurement, const K: usize>(group: &mut BenchmarkGroup<M>) {
    let mut rng = rand::thread_rng();

    let mut pv = KyberPolyVec::<K>::new_random(&mut rng);

    group.bench_function(BenchmarkId::new("Rust", K), |b| {
        b.iter(|| KyberPolyVec::<K>::ntt_and_reduce(black_box(&mut pv)))
    });

    let mut pv = [[0i16; 256]; K];

    for p in pv.iter_mut() {
        rng.fill(p);
    }

    group.bench_function(BenchmarkId::new("C", K), |b| {
        b.iter(|| cref::polyvec_ntt::<K>(black_box(&mut pv)))
    });
}

fn kyber_invntt_bench_gen<M: Measurement, const K: usize>(group: &mut BenchmarkGroup<M>) {
    let mut rng = rand::thread_rng();

    let mut pv = KyberPolyVec::<K>::new_random(&mut rng);

    group.bench_function(BenchmarkId::new("Rust", K), |b| {
        b.iter(|| KyberPolyVec::<K>::inv_ntt_tomont(black_box(&mut pv)))
    });

    let mut pv = [[0i16; 256]; K];

    for p in pv.iter_mut() {
        rng.fill(p);
    }

    group.bench_function(BenchmarkId::new("C", K), |b| {
        b.iter(|| cref::polyvec_invntt_tomont::<K>(black_box(&mut pv)))
    });
}

pub fn kyber_ntt_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber PolyVec NTT");

    kyber_ntt_bench_gen::<_, 2>(&mut group);
    kyber_ntt_bench_gen::<_, 3>(&mut group);
    kyber_ntt_bench_gen::<_, 4>(&mut group);

    group.finish();
}

pub fn kyber_invntt_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber PolyVec INV_NTT");

    kyber_invntt_bench_gen::<_, 2>(&mut group);
    kyber_invntt_bench_gen::<_, 3>(&mut group);
    kyber_invntt_bench_gen::<_, 4>(&mut group);

    group.finish();
}

criterion_group! {
    name = kyber_polyvec;
    config = Criterion::default()
        .significance_level(0.035)
        .noise_threshold(0.02)
        .measurement_time(Duration::new(7, 0))
        .sample_size(1000);
    targets = kyber_ntt_bench, kyber_invntt_bench
}

criterion_main!(kyber_polyvec);
