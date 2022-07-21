use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};

use crystals::poly::{kyber::KyberPoly, Polynomial};

fn kyber_ntt_bench(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut poly = KyberPoly::new_random(&mut rng);

    c.bench_function("rust kyber NTT", |b| {
        b.iter(|| {
            KyberPoly::ntt(black_box(&mut poly));
            KyberPoly::reduce(black_box(&mut poly))
        })
    });
}

fn kyber_invntt_bench(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut pv = KyberPoly::new_random(&mut rng);

    c.bench_function("rust kyber INV_NTT", |b| {
        b.iter(|| KyberPoly::inv_ntt(black_box(&mut pv)))
    });
}

fn kyber_pwm_bench(c: &mut Criterion) {
    let mut rng = thread_rng();
    let poly_a = KyberPoly::new_random(&mut rng);
    let poly_b = KyberPoly::new_random(&mut rng);
    let mut poly_r = KyberPoly::default();

    c.bench_function("rust kyber PWM", |b| {
        b.iter(|| {
            KyberPoly::pointwise(
                black_box(&poly_a),
                black_box(&poly_b),
                black_box(&mut poly_r),
            )
        })
    });
}

fn kyber_cref_ntt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut poly = [0i16; 256];

    rng.fill(&mut poly);

    c.bench_function("C kyber NTT", |b| {
        b.iter(|| crystals_cref::kyber::ntt(black_box(&mut poly)))
    });
}

fn kyber_cref_invntt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut poly = [0i16; 256];

    rng.fill(&mut poly);

    c.bench_function("C kyber INV_NTT", |b| {
        b.iter(|| crystals_cref::kyber::inv_ntt(black_box(&mut poly)))
    });
}

fn kyber_cref_pwm(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut poly_a = [0i16; 256];
    let mut poly_b = [0i16; 256];
    let mut poly_r = [0i16; 256];

    rng.fill(&mut poly_a);
    rng.fill(&mut poly_b);
    rng.fill(&mut poly_r);

    c.bench_function("C kyber PWM", |b| {
        b.iter(|| {
            crystals_cref::kyber::poly_pointwise_montgomery(
                black_box(&mut poly_r),
                black_box(&poly_a),
                black_box(&poly_b),
            )
        })
    });
}

criterion_group! {
    name = kyber_poly_bench;
    // This can be any expression that returns a `Criterion` object.
    // config = Criterion::default().significance_level(0.1).sample_size(500);
    config = Criterion::default().sample_size(2500);
    targets = kyber_ntt_bench, kyber_cref_ntt, kyber_invntt_bench, kyber_cref_invntt, kyber_pwm_bench, kyber_cref_pwm
}

criterion_main!(kyber_poly_bench);
