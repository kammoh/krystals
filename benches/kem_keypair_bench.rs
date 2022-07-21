use criterion::{black_box, criterion_group, criterion_main, Criterion};
// use crystals::generate_keys;
use rand::thread_rng;

#[inline]
fn kem_keypair_bench<const K: usize>(c: &mut Criterion) {
    let mut rng = thread_rng();
    // c.bench_function(format!("keypair K={}", K).as_str(), |b| {
    // b.iter(|| generate_keys::<_, K>(black_box(&mut rng)))
    // });
}

pub fn cca_keypair_2(c: &mut Criterion) {
    kem_keypair_bench::<2>(c);
}

pub fn cca_keypair_3(c: &mut Criterion) {
    kem_keypair_bench::<3>(c);
}

pub fn cca_keypair_4(c: &mut Criterion) {
    kem_keypair_bench::<4>(c);
}

criterion_group! {
    name = kem_keypair_benches;
    // This can be any expression that returns a `Criterion` object.
    // config = Criterion::default().significance_level(0.1).sample_size(500);
    config = Criterion::default().sample_size(1000);
    targets = cca_keypair_2, cca_keypair_3, cca_keypair_4
}

criterion_main!(kem_keypair_benches);
