
use crate::dh::DhKeyPair;
use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use crate::aead::encrypt;
use aes_gcm_siv::{Nonce, Aes256GcmSiv, KeyInit};
use aes_gcm_siv::aead::AeadInPlace;

#[cfg(test)]
use crate::dh::gen_key_pair;

use std::marker::PhantomData;
use crate::curve::{PrivateKey, PublicKey as TPublicKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header<T: TPublicKey> {
    pub public_key: Vec<u8>,
    pub ad: Option<Vec<u8>>,
    pub pn: usize, // Previous Chain Length
    pub n: usize, // Message Number
    phantom: PhantomData<T>,
}

impl<T: TPublicKey> From<&[u8]> for Header<T> {
    fn from(f: &[u8]) -> Self {
        let mut deserialized: Header<T> = bincode::deserialize(f).unwrap();
        deserialized.ad = None;
        deserialized
    }
}

// Message Header
impl<T: TPublicKey> Header<T> {
    // #[doc(hidden)]
    pub fn new<P: PrivateKey>(dh_pair: &DhKeyPair<P>, pn: usize, n: usize) -> Self {
        Header {
            public_key: dh_pair.public_key.to_bytes(),
            ad: None,
            pn,
            n,
            phantom: Default::default()
        }
    }
    // #[doc(hidden)]
    pub fn concat(&self, ad: &[u8]) -> Vec<u8> {
        let ex_header = Header::<T> {
            public_key: self.public_key.clone(),
            ad: Some(ad.to_vec()),
            pn: self.pn,
            n: self.n,
            phantom: Default::default(),
        };
        bincode::serialize(&ex_header).expect("Failed to serialize Header")
    }

    pub fn encrypt(&self, hk: &[u8; 32], ad: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let header_data = self.concat(ad);
        encrypt(hk, &header_data, b"")
    }

    pub fn decrypt(hk: &Option<[u8; 32]>, ciphertext: &[u8], nonce: &[u8; 12]) -> Option<Self> {
        let key_d = match hk {
            None => {
                return None
            },
            Some(d) => d
        };

        let cipher = Aes256GcmSiv::new_from_slice(key_d).unwrap();

        let nonce = Nonce::from_slice(nonce);
        let mut buffer = Vec::new();
        buffer.extend_from_slice(ciphertext);
        match cipher.decrypt_in_place(nonce, b"", &mut buffer) {
            Ok(_) => {}
            Err(_) => {
                return None
            }
        };
        let header: Self = bincode::deserialize(&buffer).unwrap();
        Some(header)
    }
    pub fn ex_public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

impl<T: TPublicKey> PartialEq for Header<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.public_key == other.public_key
            && self.pn == other.pn
            && self.n == other.n {
            return true
        }
        false
    }
}

#[cfg(test)]
pub fn gen_header<T: TPublicKey>() -> Header<T> {
    let dh_pair = gen_key_pair::<x25519_dalek::StaticSecret>();
    let pn = 10;
    let n = 50;
    Header::new(&dh_pair, pn, n)
}


#[cfg(test)]
mod tests {
    use crate::header::{gen_header, Header};
    use crate::kdf_chain::gen_mk;
    use crate::aead::{encrypt, decrypt};

    #[test]
    fn ser_des() {
        let ad = b"";
        let header = gen_header::<x25519_dalek::PublicKey>();
        let serialized = header.concat(ad);
        let created = Header::from(serialized.as_slice());
        assert_eq!(header, created)
    }

    #[test]
    fn enc_header() {
        let header = gen_header::<x25519_dalek::PublicKey>();
        let mk = gen_mk();
        let header_data = header.concat(b"");
        let data = include_bytes!("aead.rs");
        let (encrypted, nonce) = encrypt(&mk, data, &header_data);
        let decrypted = decrypt(&mk, &encrypted, &header_data, &nonce);
        assert_eq!(decrypted, data.to_vec())
    }

    #[test]
    fn test_eq_header() {
        let header1 = gen_header::<x25519_dalek::PublicKey>();
        let header2 = gen_header::<x25519_dalek::PublicKey>();
        assert_ne!(header1, header2)
    }

    #[test]
    fn debug_header() {
        let header = gen_header::<x25519_dalek::PublicKey>();
        let _string = alloc::format!("{:?}", header);
    }

    #[test]
    fn dec_header() {
        let header = gen_header::<x25519_dalek::PublicKey>();
        let (encrypted, nonce) = header.encrypt(&[0; 32], &[0]);
        let decrypted = Header::<x25519_dalek::PublicKey>::decrypt(&Some([1_u8; 32]), &encrypted, &nonce);
        assert_eq!(None, decrypted)
    }
}