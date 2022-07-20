use double_ratchet_2::{ratchet::{Ratchet, RatchetEncHeader}, StaticSecret};
use criterion::{Criterion, criterion_main, criterion_group};

fn ratchet_enc_single() {
    let sk = [1; 32];
    let (mut bob_ratchet, public_key) = Ratchet::<StaticSecret>::init_bob(sk);
    let mut alice_ratchet = Ratchet::<StaticSecret>::init_alice(sk, public_key);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header, encrypted, nonce) = alice_ratchet.ratchet_encrypt(&data, b"");
    let _decrypted = bob_ratchet.ratchet_decrypt(&header, &encrypted, &nonce, b"");
}

fn criterion_benchmark_1(c: &mut Criterion) {
    c.bench_function("Ratchet Enc Single", |b| b.iter(|| ratchet_enc_single()));
}

fn ratchet_enc_skip() {
    let sk = [1; 32];
    let (mut bob_ratchet, public_key) = Ratchet::<StaticSecret>::init_bob(sk);
    let mut alice_ratchet = Ratchet::<StaticSecret>::init_alice(sk, public_key);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data, b"");
    let (header2, encrypted2, nonce2) = alice_ratchet.ratchet_encrypt(&data, b"");
    let _decrypted2 = bob_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2, b"");
    let _decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1, b"");
}

fn criterion_benchmark_2(c: &mut Criterion) {
    c.bench_function("Ratchet Enc Skip", |b| b.iter(|| ratchet_enc_skip()));
}

fn ratchet_encryt_decrypt_four() {
    let sk = [1; 32];
    let data = include_bytes!("../src/dh.rs").to_vec();
    let (mut bob_ratchet, public_key) = Ratchet::<StaticSecret>::init_bob(sk);
    let mut alice_ratchet = Ratchet::<StaticSecret>::init_alice(sk, public_key);
    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data, b"");
    let _decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1, b"");
    let (header2, encrypted2, nonce2) = bob_ratchet.ratchet_encrypt(&data, b"");
    let _decrypted2 = alice_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2, b"");
}

fn criterion_benchmark_3(c: &mut Criterion) {
    c.bench_function("Ratchet Dec Four", |b| b.iter(|| ratchet_encryt_decrypt_four()));
}

fn ratchet_ench_enc_single() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::<StaticSecret>::init_bob(sk,
                                                                   shared_hka,
                                                                   shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::<StaticSecret>::init_alice(sk,
                                                         public_key,
                                                         shared_hka,
                                                         shared_nhkb);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header, encrypted, nonce) = alice_ratchet.ratchet_encrypt(&data, b"");
    let decrypted = bob_ratchet.ratchet_decrypt(&header, &encrypted, &nonce, b"");
    assert_eq!(data, decrypted)
}

fn criterion_benchmark_4(c: &mut Criterion) {
    c.bench_function("Encrypted Header Ratchet Enc Single", |b| b.iter(|| ratchet_ench_enc_single()));
}

fn ratchet_ench_enc_skip() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::<StaticSecret>::init_bob(sk,
                                                                   shared_hka,
                                                                   shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::<StaticSecret>::init_alice(sk,
                                                         public_key,
                                                         shared_hka,
                                                         shared_nhkb);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data, b"");
    let (header2, encrypted2, nonce2) = alice_ratchet.ratchet_encrypt(&data, b"");
    let _decrypted2 = bob_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2, b"");
    let _decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1, b"");
}

fn criterion_benchmark_5(c: &mut Criterion) {
    c.bench_function("Encrypted Header Ratchet Enc Skip", |b| b.iter(|| ratchet_ench_enc_skip()));
}

fn ratchet_ench_decrypt_four() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::<StaticSecret>::init_bob(sk,
                                                                   shared_hka,
                                                                   shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::<StaticSecret>::init_alice(sk, public_key, shared_hka, shared_nhkb);
    let data = include_bytes!("../src/dh.rs").to_vec();
    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data, b"");
    let _decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1, b"");
    let (header2, encrypted2, nonce2) = bob_ratchet.ratchet_encrypt(&data, b"");
    let _decrypted2 = alice_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2, b"");
}

fn criterion_benchmark_6(c: &mut Criterion) {
    c.bench_function("Encrypted Header Ratchet Dec Four", |b| b.iter(|| ratchet_ench_decrypt_four()));
}

criterion_group!(without_enc_headerd, criterion_benchmark_1, criterion_benchmark_2, criterion_benchmark_3);
criterion_group!(with_enc_headerd, criterion_benchmark_4, criterion_benchmark_5, criterion_benchmark_6);
criterion_main!(without_enc_headerd, with_enc_headerd);
