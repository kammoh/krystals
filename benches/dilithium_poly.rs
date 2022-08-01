use core::time::Duration;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use krystals::poly::{dilithium::DilithiumPoly, SizedPolynomial};

fn dilithium_ntt_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium NTT");

    let mut rng = rand::thread_rng();
    let mut poly = DilithiumPoly::new_random(&mut rng);

    group.bench_function("Rust", |b| {
        b.iter(|| {
            DilithiumPoly::ntt(black_box(&mut poly));
        })
    });

    let mut poly = poly.into_array();

    group.bench_function("C", |b| {
        b.iter(|| crystals_cref::dilithium::ntt(black_box(&mut poly)))
    });

    group.finish();
}

fn dilithium_invntt_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium INV_NTT");

    let mut rng = rand::thread_rng();
    let mut poly = DilithiumPoly::new_random(&mut rng);

    group.bench_function("Rust", |b| {
        b.iter(|| {
            DilithiumPoly::inv_ntt(black_box(&mut poly));
        })
    });

    let mut poly = poly.into_array();

    group.bench_function("C", |b| {
        b.iter(|| crystals_cref::dilithium::inv_ntt(black_box(&mut poly)))
    });

    group.finish();
}

fn dilithium_pwm_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium PWM");

    let mut rng = rand::thread_rng();
    let poly_a = DilithiumPoly::new_random(&mut rng);
    let poly_b = DilithiumPoly::new_random(&mut rng);
    let mut poly_r = DilithiumPoly::default();

    group.bench_function("Rust", |b| {
        b.iter(|| {
            DilithiumPoly::pointwise(
                black_box(&poly_a),
                black_box(&poly_b),
                black_box(&mut poly_r),
            )
        })
    });

    let poly_a = poly_a.into_array();
    let poly_b = poly_b.into_array();
    let mut poly_r = [0i32; 256];

    group.bench_function("C", |b| {
        b.iter(|| {
            crystals_cref::dilithium::poly_pointwise_montgomery(
                black_box(&mut poly_r),
                black_box(&poly_a),
                black_box(&poly_b),
            )
        })
    });

    group.finish();
}

criterion_group! {
    name = dilithium_poly_bench;
    config = Criterion::default()
        .significance_level(0.035)
        .noise_threshold(0.02)
        .measurement_time(Duration::new(6, 0))
        .sample_size(2500);
    targets = dilithium_ntt_bench, dilithium_invntt_bench, dilithium_pwm_bench
}

criterion_main!(dilithium_poly_bench);
