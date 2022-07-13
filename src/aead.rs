use aes_gcm_siv::{Aes256GcmSiv, Nonce, KeyInit};
use aes_gcm_siv::aead::AeadInPlace;
use alloc::vec::Vec;
use rand_core::RngCore;

pub fn encrypt(mk: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let cipher = Aes256GcmSiv::new_from_slice(mk).unwrap();
    let mut nonce_data = [0_u8; 12];
    let mut rnd = rand::thread_rng();
    rnd.fill_bytes(&mut nonce_data);
    let nonce = Nonce::from_slice(&nonce_data);
    let mut buffer = Vec::new();
    buffer.extend_from_slice(plaintext);

    cipher.encrypt_in_place(nonce, associated_data, &mut buffer)
        .expect("Encryption failed");
    (buffer, nonce_data)
}

pub fn decrypt(mk: &[u8; 32], ciphertext: &[u8], associated_data: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new_from_slice(mk).unwrap();

    let nonce = Nonce::from_slice(nonce);
    let mut buffer = Vec::new();
    buffer.extend_from_slice(ciphertext);
    cipher.decrypt_in_place(nonce, associated_data, &mut buffer).expect("Decryption failure {}");
    buffer
}

#[cfg(test)]
mod tests {
    use crate::kdf_chain::gen_mk;
    use crate::aead::{encrypt, decrypt};

    #[test]
    fn enc_a_dec() {
        let test_data = include_bytes!("aead.rs").to_vec();
        let associated_data = include_bytes!("lib.rs").to_vec();
        let mk = gen_mk();
        let (ciphertext, nonce) = encrypt(&mk, &test_data, &associated_data);
        let plaintext = decrypt(&mk, &ciphertext, &associated_data, &nonce);
        assert_eq!(test_data, plaintext)
    }
}