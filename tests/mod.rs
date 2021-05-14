use double_ratchet_2::ratchet::{Ratchet, RatchetEncHeader};

#[test]
fn ratchet_init() {
    let sk = [1; 32];
    let (_bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let _alice_ratchet = Ratchet::init_alice(sk, public_key);
}

#[test]
fn ratchet_enc_single() {
    let sk = [1; 32];
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header, encrypted, nonce) = alice_ratchet.ratchet_encrypt(&data);
    let decrypted = bob_ratchet.ratchet_decrypt(&header, &encrypted, &nonce);
    assert_eq!(data, decrypted)
}

#[test]
fn ratchet_enc_skip() {
    let sk = [1; 32];
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data);
    let (header2, encrypted2, nonce2) = alice_ratchet.ratchet_encrypt(&data);
    let decrypted2 = bob_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2);
    let decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1);
    let comp_res = decrypted1 == data && decrypted2 == data;
    assert!(comp_res)
}

#[test]
#[should_panic]
fn ratchet_panic_bob() {
    let sk = [1; 32];
    let (mut bob_ratchet, _) = Ratchet::init_bob(sk);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (_, _, _) = bob_ratchet.ratchet_encrypt(&data);
}

#[test]
fn ratchet_encryt_decrypt_four() {
    let sk = [1; 32];
    let data = include_bytes!("../src/dh.rs").to_vec();
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);
    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data);
    let decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1);
    let (header2, encrypted2, nonce2) = bob_ratchet.ratchet_encrypt(&data);
    let decrypted2 = alice_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2);
    let comp_res = decrypted1 == data && decrypted2 == data;
    assert!(comp_res)
}

#[test]
fn ratchet_ench_init() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (_bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk,
                                                                   shared_hka,
                                                                   shared_nhkb);
    let _alice_ratchet = RatchetEncHeader::init_alice(sk, public_key,
                                                      shared_hka, shared_nhkb);
}

#[test]
fn ratchet_ench_enc_single() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk,
                                                                   shared_hka,
                                                                   shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::init_alice(sk,
                                                         public_key,
                                                         shared_hka,
                                                         shared_nhkb);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header, encrypted, nonce) = alice_ratchet.ratchet_encrypt(&data);
    let decrypted = bob_ratchet.ratchet_decrypt(&header, &encrypted, &nonce);
    assert_eq!(data, decrypted)
}

#[test]
fn ratchet_ench_enc_skip() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk,
                                                                   shared_hka,
                                                                   shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::init_alice(sk,
                                                         public_key,
                                                         shared_hka,
                                                         shared_nhkb);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data);
    let (header2, encrypted2, nonce2) = alice_ratchet.ratchet_encrypt(&data);
    let decrypted2 = bob_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2);
    let decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1);
    let comp_res = decrypted1 == data && decrypted2 == data;
    assert!(comp_res)
}

#[test]
#[should_panic]
fn ratchet_ench_panic_bob() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk,
                                                                   shared_hka,
                                                                   shared_nhkb);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (_, _, _) = bob_ratchet.ratchet_encrypt(&data);
}

#[test]
fn ratchet_ench_decrypt_four() {
    let sk = [1; 32];
    let shared_hka = [2; 32];
    let shared_nhkb = [3; 32];
    let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk,
                                                                   shared_hka,
                                                                   shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::init_alice(sk, public_key, shared_hka, shared_nhkb);
    let data = include_bytes!("../src/dh.rs").to_vec();
    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data);
    let decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1);
    let (header2, encrypted2, nonce2) = bob_ratchet.ratchet_encrypt(&data);
    let decrypted2 = alice_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2);
    let comp_res = decrypted1 == data && decrypted2 == data;
    assert!(comp_res)
}