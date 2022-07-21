use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};

use crystals::{poly::dilithium::DilithiumPoly, polyvec::PolyVec};

#[inline]
fn dilithium_ntt_bench<const K: usize>(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut pv = PolyVec::<DilithiumPoly, K>::new_random(&mut rng);

    c.bench_function(format!("rust dilithium NTT polyvec K={}", K).as_str(), |b| {
        b.iter(|| PolyVec::<DilithiumPoly, K>::ntt(black_box(&mut pv)))
    });
}

#[inline]
fn dilithium_invntt_bench<const K: usize>(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut pv = PolyVec::<DilithiumPoly, K>::new_random(&mut rng);

    c.bench_function(format!("rust dilithium INV_NTT polyvec K={}", K).as_str(), |b| {
        b.iter(|| PolyVec::<DilithiumPoly, K>::invntt_tomont(black_box(&mut pv)))
    });
}

#[inline]
fn dilithium_cref_ntt<const K: usize>(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut pv = [[0i32; 256]; K];

    for p in pv.iter_mut() {
        rng.fill(p);
    }

    c.bench_function(format!("cref dilithium NTT polyvec K={}", K).as_str(), |b| {
        b.iter(|| crystals_cref::dilithium::polyveck_ntt::<K>(black_box(&mut pv)))
    });
}

#[inline]
fn dilithium_cref_invntt<const K: usize>(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut pv = [[0i32; 256]; K];

    for p in pv.iter_mut() {
        rng.fill(p);
    }

    c.bench_function(format!("C ref dilithium INV_NTT polyvec  K={}", K).as_str(), |b| {
        b.iter(|| crystals_cref::dilithium::polyveck_invntt_tomont::<K>(black_box(&mut pv)))
    });
}

pub fn dilithium_cref_ntt_bench_4(c: &mut Criterion) {
    dilithium_cref_ntt::<4>(c);
}

pub fn dilithium_cref_invntt_bench_4(c: &mut Criterion) {
    dilithium_cref_invntt::<4>(c);
}

pub fn dilithium_ntt_bench_4(c: &mut Criterion) {
    dilithium_ntt_bench::<4>(c);
}

pub fn dilithium_invntt_bench_4(c: &mut Criterion) {
    dilithium_invntt_bench::<4>(c);
}

criterion_group! {
    name = dilithium_polyvec;
    // This can be any expression that returns a `Criterion` object.
    // config = Criterion::default().significance_level(0.1).sample_size(500);
    config = Criterion::default().sample_size(2000);
    targets = dilithium_ntt_bench_4, dilithium_cref_ntt_bench_4, dilithium_invntt_bench_4, dilithium_cref_invntt_bench_4
}

criterion_main!(dilithium_polyvec);
