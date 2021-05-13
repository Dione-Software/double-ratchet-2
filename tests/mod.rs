use double_ratchet_2::ratchet::Ratchet;

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
    let (header, encrypted) = alice_ratchet.ratchet_encrypt(&data);
    let decrypted = bob_ratchet.ratchet_decrypt(&header, &encrypted);
    assert_eq!(data, decrypted)
}

#[test]
fn ratchet_enc_skip() {
    let sk = [1; 32];
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header1, encrypted1) = alice_ratchet.ratchet_encrypt(&data);
    let (header2, encrypted2) = alice_ratchet.ratchet_encrypt(&data);
    let decrypted2 = bob_ratchet.ratchet_decrypt(&header2, &encrypted2);
    let decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1);
    let comp_res = decrypted1 == data && decrypted2 == data;
    assert!(comp_res)
}

#[test]
#[should_panic]
fn ratchet_panic_bob() {
    let sk = [1; 32];
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let data = include_bytes!("../src/header.rs").to_vec();
    let (header, encrypted) = bob_ratchet.ratchet_encrypt(&data);
}

#[test]
fn ratchet_encryt_decrypt_four() {
    let sk = [1; 32];
    let data = include_bytes!("../src/dh.rs").to_vec();
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);
    let (header1, encrypted1) = alice_ratchet.ratchet_encrypt(&data);
    let decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1);
    let (header2, encrypted2) = bob_ratchet.ratchet_encrypt(&data);
    let decrypted2 = alice_ratchet.ratchet_decrypt(&header2, &encrypted2);
    let comp_res = decrypted1 == data && decrypted2 == data;
    assert!(comp_res)
}