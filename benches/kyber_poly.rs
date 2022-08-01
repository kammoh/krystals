use core::time::Duration;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crystals::poly::{kyber::KyberPoly, SizedPolynomial};
use crystals_cref::kyber as cref;
use rand::thread_rng;

fn kyber_ntt_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber poly NTT");

    let mut rng = thread_rng();
    let mut poly = KyberPoly::new_random(&mut rng);

    group.bench_function("Rust", |b| {
        b.iter(|| {
            KyberPoly::ntt_and_reduce(black_box(&mut poly));
        })
    });

    let mut poly = poly.into_array();

    group.bench_function("C", |b| b.iter(|| cref::ntt(black_box(&mut poly))));

    group.finish();
}

fn kyber_invntt_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber poly INV_NTT");

    let mut rng = thread_rng();
    let mut poly = KyberPoly::new_random(&mut rng);

    group.bench_function("Rust", |b| {
        b.iter(|| {
            KyberPoly::inv_ntt(black_box(&mut poly));
        })
    });

    let mut poly = poly.into_array();

    group.bench_function("C", |b| b.iter(|| cref::inv_ntt(black_box(&mut poly))));

    group.finish();
}

fn kyber_pwm_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber poly PWM");

    let mut rng = thread_rng();
    let poly_a = KyberPoly::new_random(&mut rng);
    let poly_b = KyberPoly::new_random(&mut rng);
    let mut poly_r = KyberPoly::default();

    group.bench_function("Rust", |b| {
        b.iter(|| {
            KyberPoly::pointwise(
                black_box(&poly_a),
                black_box(&poly_b),
                black_box(&mut poly_r),
            )
        })
    });

    let poly_a = poly_a.into_array();
    let poly_b = poly_b.into_array();
    let mut poly_r = [0i16; 256];

    group.bench_function("C", |b| {
        b.iter(|| {
            cref::poly_pointwise_montgomery(
                black_box(&mut poly_r),
                black_box(&poly_a),
                black_box(&poly_b),
            )
        })
    });

    group.finish();
}

criterion_group! {
    name = kyber_poly_bench;
    // significance_level: (default = 0.05) This presents a trade-off. By setting the significance level closer to 0.0, you can increase the statistical
    // robustness against noise, but it also weakens Criterion.rs' ability to detect small but real changes in the
    // performance. By setting the significance level closer to 1.0, Criterion.rs will be more able to detect small
    // true changes, but will also report more spurious differences.

    config = Criterion::default()
        .significance_level(0.035)
        .noise_threshold(0.02)
        .measurement_time(Duration::new(6, 0))
        .sample_size(2500);
    targets = kyber_ntt_bench, kyber_invntt_bench, kyber_pwm_bench
}

criterion_main!(kyber_poly_bench);
