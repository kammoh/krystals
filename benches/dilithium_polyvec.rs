use core::time::Duration;
use criterion::{
    black_box, criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup,
    BenchmarkId, Criterion,
};
use rand::Rng;

use crystals::polyvec::{DilithiumPolyVec, PolynomialVector};
use crystals_cref::dilithium as cref;

fn dilithium_ntt_bench_gen<M: Measurement, const K: usize>(group: &mut BenchmarkGroup<M>) {
    let mut rng = rand::thread_rng();
    let mut pv = DilithiumPolyVec::<K>::new_random(&mut rng);
    let k_size_str = format!("K={}", K);

    group.bench_function(BenchmarkId::new("Rust", &k_size_str), |b| {
        b.iter(|| DilithiumPolyVec::<K>::ntt(black_box(&mut pv)))
    });

    let mut pv = [[0i32; 256]; K];

    for p in pv.iter_mut() {
        rng.fill(p);
    }

    group.bench_function(BenchmarkId::new("C", &k_size_str), |b| {
        b.iter(|| cref::polyveck_ntt::<K>(black_box(&mut pv)))
    });
}

fn dilithium_invntt_bench_gen<M: Measurement, const K: usize>(group: &mut BenchmarkGroup<M>) {
    let mut rng = rand::thread_rng();
    let mut pv = DilithiumPolyVec::<K>::new_random(&mut rng);
    let k_size_str = format!("K={}", K);

    group.bench_function(BenchmarkId::new("Rust", &k_size_str), |b| {
        b.iter(|| DilithiumPolyVec::<K>::inv_ntt_tomont(black_box(&mut pv)))
    });

    let mut pv = [[0i32; 256]; K];

    for p in pv.iter_mut() {
        rng.fill(p);
    }

    group.bench_function(BenchmarkId::new("C", &k_size_str), |b| {
        b.iter(|| cref::polyveck_invntt_tomont::<K>(black_box(&mut pv)))
    });
}

pub fn dilithium_ntt_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium PolyVec NTT");

    dilithium_ntt_bench_gen::<_, 4>(&mut group);
    dilithium_ntt_bench_gen::<_, 6>(&mut group);
    dilithium_ntt_bench_gen::<_, 8>(&mut group);

    group.finish();
}

pub fn dilithium_invntt_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium PolyVec INV_NTT");

    dilithium_invntt_bench_gen::<_, 4>(&mut group);
    dilithium_invntt_bench_gen::<_, 6>(&mut group);
    dilithium_invntt_bench_gen::<_, 8>(&mut group);

    group.finish();
}

criterion_group! {
    name = dilithium_polyvec;
    config = Criterion::default()
        .significance_level(0.04)
        .noise_threshold(0.015)
        .measurement_time(Duration::new(8, 0))
        .sample_size(1500);
    targets = dilithium_ntt_bench, dilithium_invntt_bench
}

criterion_main!(dilithium_polyvec);
