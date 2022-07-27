use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crystals::keccak::fips202::Digest;
use digest::generic_array::GenericArray;
use rand::Rng;

fn keccak_sha3_256<const N: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("SHA3-256 {N}B"));

    let mut rng = rand::thread_rng();
    let mut data = [0u8; N];
    rng.fill(&mut data[..]);

    group.bench_with_input("crystals-rs", &data, |b, data| {
        use crystals::keccak::fips202::Sha3_256;
        let mut hash = [0u8; 32];
        let mut sha3 = Sha3_256::default();

        b.iter(|| {
            sha3.digest(data, black_box(&mut hash));
        })
    });

    group.bench_with_input("tiny-keccak", &data, |b, data| {
        use tiny_keccak::{Hasher, Sha3};
        let mut hash = [0u8; 32];

        b.iter(|| {
            // for tiny-keccak we need a new instance for each operation
            let mut sha3 = Sha3::v256();
            sha3.update(data);
            sha3.finalize(black_box(&mut hash));
        })
    });

    group.bench_with_input("rust-crypto", &data, |b, data| {
        let mut hash = GenericArray::default();

        use sha3::{Digest, Sha3_256};
        let mut sha3 = Sha3_256::default();

        b.iter(|| {
            sha3.update(data);
            sha3.finalize_into_reset(black_box(&mut hash));
        })
    });
    group.finish();
}

fn keccak_sha3_512<const N: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("SHA3-512 {N}B"));

    let mut rng = rand::thread_rng();
    let mut data = [0u8; N];
    rng.fill(&mut data[..]);

    group.bench_with_input("crystals-rs", &data, |b, data| {
        use crystals::keccak::fips202::Sha3_512;
        let mut hash = [0u8; 64];
        let mut sha3 = Sha3_512::default();

        b.iter(|| {
            sha3.digest(data, black_box(&mut hash));
        })
    });

    group.bench_with_input("tiny-keccak", &data, |b, data| {
        use tiny_keccak::{Hasher, Sha3};
        let mut hash = [0u8; 64];

        b.iter(|| {
            // for tiny-keccak we need a new instance for each operation
            let mut sha3 = Sha3::v512();
            sha3.update(data);
            sha3.finalize(&mut hash);
        })
    });

    group.bench_with_input("rust-crypto", &data, |b, data| {
        let mut hash = GenericArray::default();

        use sha3::{Digest, Sha3_512};
        let mut sha3 = Sha3_512::default();

        b.iter(|| {
            sha3.update(data);
            sha3.finalize_into_reset(black_box(&mut hash));
        })
    });
    group.finish();
}

criterion_group!(
    name = keccak_short_benches;
    config = Criterion::default()
        .sample_size(500)
        .measurement_time(core::time::Duration::from_secs(8));
    targets =
        keccak_sha3_256::<32>,
        keccak_sha3_512::<32>,
        keccak_sha3_256::<1024>,
        keccak_sha3_512::<1024>,
);

criterion_group!(
    name = keccak_long_benches;
    config = Criterion::default();
        // .sample_size(250)
        // .measurement_time(core::time::Duration::from_secs(10));
    targets =
        keccak_sha3_256::<8192>,
        keccak_sha3_512::<8192>
);

criterion_main!(keccak_short_benches, keccak_long_benches);
