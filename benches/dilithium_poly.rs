use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};

use crystals::poly::{dilithium::DilithiumPoly, Polynomial};

fn dilithium_ntt_bench(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut poly = DilithiumPoly::new_random(&mut rng);

    c.bench_function("rust dilithium NTT", |b| {
        b.iter(|| {
            DilithiumPoly::ntt(black_box(&mut poly));
            DilithiumPoly::reduce(black_box(&mut poly))
        })
    });
}

fn dilithium_invntt_bench(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut poly = DilithiumPoly::new_random(&mut rng);

    c.bench_function("rust dilithium INV_NTT", |b| {
        b.iter(|| DilithiumPoly::inv_ntt(black_box(&mut poly)))
    });
}

fn dilithium_pwm_bench(c: &mut Criterion) {
    let mut rng = thread_rng();
    let poly_a = DilithiumPoly::new_random(&mut rng);
    let poly_b = DilithiumPoly::new_random(&mut rng);
    let mut poly_r = DilithiumPoly::default();

    c.bench_function("rust dilithium PWM", |b| {
        b.iter(|| {
            DilithiumPoly::pointwise(
                black_box(&poly_a),
                black_box(&poly_b),
                black_box(&mut poly_r),
            )
        })
    });
}

fn dilithium_cref_ntt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut poly = [0i32; 256];

    rng.fill(&mut poly);

    c.bench_function("C dilithium NTT", |b| {
        b.iter(|| crystals_cref::dilithium::ntt(black_box(&mut poly)))
    });
}

fn dilithium_cref_invntt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut poly = [0i32; 256];

    rng.fill(&mut poly);

    c.bench_function("C dilithium INV_NTT", |b| {
        b.iter(|| crystals_cref::dilithium::inv_ntt(black_box(&mut poly)))
    });
}

fn dilithium_cref_pwm(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut poly_a = [0i32; 256];
    let mut poly_b = [0i32; 256];
    let mut poly_r = [0i32; 256];

    rng.fill(&mut poly_a);
    rng.fill(&mut poly_b);
    rng.fill(&mut poly_r);

    c.bench_function("C dilithium PWM", |b| {
        b.iter(|| {
            crystals_cref::dilithium::poly_pointwise_montgomery(
                black_box(&mut poly_r),
                black_box(&poly_a),
                black_box(&poly_b),
            )
        })
    });
}

criterion_group! {
    name = dilithium_poly_bench;
    // This can be any expression that returns a `Criterion` object.
    // config = Criterion::default().significance_level(0.1).sample_size(500);
    config = Criterion::default().sample_size(2500);
    targets = dilithium_ntt_bench, dilithium_cref_ntt, dilithium_invntt_bench, dilithium_cref_invntt, dilithium_pwm_bench, dilithium_cref_pwm
}

criterion_main!(dilithium_poly_bench);
