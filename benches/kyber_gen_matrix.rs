use core::time::Duration;
use criterion::{
    black_box, criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup,
    BenchmarkId, Criterion,
};
use rand::Rng;

use crystals::{poly::kyber::KYBER_N, polymat::KyberMatrix};
use crystals_cref::kyber as cref;

fn kyber_gen_matrix_bench_gen<M: Measurement, const K: usize, const TRANSPOSED: bool>(
    group: &mut BenchmarkGroup<M>,
) {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);

    let mut mat = KyberMatrix::<K>::default();

    group.bench_function(BenchmarkId::new("Rust", K), |b| {
        b.iter(|| {
            black_box(&mut mat).gen_matrix_into::<TRANSPOSED>(black_box(&seed));
        })
    });

    let mut mat = [[[0i16; KYBER_N]; K]; K];

    group.bench_function(BenchmarkId::new("C", K), |b| {
        b.iter(|| cref::gen_matrix(black_box(&mut mat), black_box(&seed), TRANSPOSED))
    });
}

pub fn kyber_gen_matrix_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber gen_matrix");

    kyber_gen_matrix_bench_gen::<_, 2, true>(&mut group);
    kyber_gen_matrix_bench_gen::<_, 3, true>(&mut group);
    kyber_gen_matrix_bench_gen::<_, 4, true>(&mut group);

    group.finish();
}

criterion_group! {
    name = kyber_gen_matrix;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(8))
        .sample_size(200);
    targets = kyber_gen_matrix_bench
}

criterion_main!(kyber_gen_matrix);
