mod buffer_rng;
mod kat;

use buffer_rng::BufferRng;
use crystals::*;
use kat::*;
use std::path::Path;

fn get_kats_iter<const KYBER_K: usize>() -> KatFile {
    let kat_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("KATs")
        .join(format!("kyber_{}.kat", kyber_k_to_security(KYBER_K)));
    println!("kat path: {:?}", kat_path);
    KatFile::new(&kat_path).expect("Unable to load KAT file")
}

fn test_kyber_kem<const KYBER_K: usize>() {
    let kats = get_kats_iter::<KYBER_K>();
    let mut rng = BufferRng::default();
    for known in kats {
        rng.reset();
        rng.load_bytes(known.keygen_rand0.as_slice());
        rng.load_bytes(known.keygen_rand1.as_slice());
        rng.load_bytes(known.encap_rand.as_slice());
        // let (pk, sk) = generate_keys::<_, KYBER_K>(&mut rng).expect("msg");
        // let mut pk_bytes = pk.bytes.flatten().to_vec();
        // pk_bytes.extend(pk.seed);
        // assert_eq!(pk_bytes, &known.pk[..], "Public key mismatch");
        // let mut sk_bytes = sk.cpa_sk.bytes.flatten().to_vec();
        // let mut spkpk_bytes = sk.pk.bytes.flatten().to_vec();
        // spkpk_bytes.extend(sk.pk.seed);
        // sk_bytes.extend(spkpk_bytes);
        // sk_bytes.extend(sk.h_pk);
        // sk_bytes.extend(sk.z);
        // assert_eq!(sk_bytes, &known.sk[..], "Secret key mismatch");

        // // FIXME
        // const CT_BYTES: usize = 320 + 128;

        // let (ct, ss) = encapsulate::<_, KYBER_K, CT_BYTES>(&pk, &mut rng).unwrap();
        // assert_eq!(&ss[..], &known.ss, "Shared secret mismatch");
        // assert_eq!(&ct[..], &known.ct, "Ciphertext mismatch");
        //     let decap_result = decapsulate(&ct, &sk);
        //     assert!(decap_result.is_ok(), "KEM decapsulation failure");
        //     assert_eq!(&decap_result.unwrap()[..], &known_ss[..], "Shared secret KAT doesn't match")
    }
}

// all
#[test]
fn kyber_keypairs_512() {
    test_kyber_kem::<2>();
}
#[test]
fn kyber_keypairs_768() {
    test_kyber_kem::<3>();
}
#[test]
fn kyber_keypairs_1024() {
    test_kyber_kem::<4>();
}
