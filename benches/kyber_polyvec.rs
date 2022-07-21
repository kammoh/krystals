use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};

use crystals::{poly::kyber::KyberPoly, polyvec::PolyVec};

#[inline]
fn kyber_ntt_bench<const K: usize>(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut pv = PolyVec::<KyberPoly, K>::new_random(&mut rng);

    c.bench_function(format!("rust NTT K={}", K).as_str(), |b| {
        b.iter(|| {
            PolyVec::<KyberPoly, K>::ntt(black_box(&mut pv));
            PolyVec::<KyberPoly, K>::reduce(black_box(&mut pv))
        })
    });
}

#[inline]
fn kyber_invntt_bench<const K: usize>(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut pv = PolyVec::<KyberPoly, K>::new_random(&mut rng);

    c.bench_function(format!("rust kyber inv NTT K={}", K).as_str(), |b| {
        b.iter(|| PolyVec::<KyberPoly, K>::invntt_tomont(black_box(&mut pv)))
    });
}

#[inline]
fn kyber_cref_ntt<const K: usize>(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut pv = [[0i16; 256]; K];

    for p in pv.iter_mut() {
        rng.fill(p);
    }

    c.bench_function(format!("C ref NTT K={}", K).as_str(), |b| {
        b.iter(|| crystals_cref::kyber::polyvec_ntt::<K>(black_box(&mut pv)))
    });
}

#[inline]
fn kyber_cref_invntt<const K: usize>(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut pv = [[0i16; 256]; K];

    for p in pv.iter_mut() {
        rng.fill(p);
    }

    c.bench_function(format!("C ref kyber inv_NTT K={}", K).as_str(), |b| {
        b.iter(|| crystals_cref::kyber::polyvec_invntt_tomont::<K>(black_box(&mut pv)))
    });
}

pub fn kyber_cref_ntt_bench_2(c: &mut Criterion) {
    kyber_cref_ntt::<2>(c);
}

pub fn kyber_cref_invntt_bench_2(c: &mut Criterion) {
    kyber_cref_invntt::<2>(c);
}

pub fn kyber_ntt_bench_2(c: &mut Criterion) {
    kyber_ntt_bench::<2>(c);
}

pub fn kyber_invntt_bench_2(c: &mut Criterion) {
    kyber_invntt_bench::<2>(c);
}

pub fn kyber_ntt_bench_3(c: &mut Criterion) {
    kyber_ntt_bench::<3>(c);
}

pub fn kyber_ntt_bench_4(c: &mut Criterion) {
    kyber_ntt_bench::<4>(c);
}

criterion_group! {
    name = kyber_polyvec;
    // This can be any expression that returns a `Criterion` object.
    // config = Criterion::default().significance_level(0.1).sample_size(500);
    config = Criterion::default().sample_size(2000);
    targets = kyber_ntt_bench_2, kyber_cref_ntt_bench_2, kyber_invntt_bench_2, kyber_cref_invntt_bench_2
}

criterion_main!(kyber_polyvec);
