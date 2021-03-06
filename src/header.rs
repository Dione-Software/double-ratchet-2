use p256::PublicKey;
use crate::dh::DhKeyPair;
use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use crate::aead::encrypt;
use aes_gcm_siv::{Key, Nonce, Aes256GcmSiv};
use aes_gcm_siv::aead::{NewAead, AeadInPlace};

#[cfg(test)]
use crate::dh::gen_key_pair;
use alloc::string::{ToString, String};
use core::str::FromStr;
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct Header {
    pub public_key: PublicKey,
    pub pn: usize, // Previous Chain Length
    pub n: usize, // Message Number
}

#[derive(Serialize, Deserialize, Debug, Zeroize)]
#[zeroize(drop)]
struct ExHeader {
    #[serde(with = "serde_bytes")]
    ad: Vec<u8>,
    public_key: Vec<u8>,
    pn: usize,
    n: usize
}

// Message Header
impl Header {
    // #[doc(hidden)]
    pub fn new(dh_pair: &DhKeyPair, pn: usize, n: usize) -> Self {
        Header {
            public_key: dh_pair.public_key,
            pn,
            n,
        }
    }
    // #[doc(hidden)]
    pub fn concat(&self, ad: &[u8]) -> Vec<u8> {
        let ex_header = ExHeader {
            ad: ad.to_vec(),
            public_key: self.public_key.to_string().as_bytes().to_vec(),
            pn: self.pn,
            n: self.n
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
        let key = Key::from_slice(key_d);
        let cipher = Aes256GcmSiv::new(key);

        let nonce = Nonce::from_slice(nonce);
        let mut buffer = Vec::new();
        buffer.extend_from_slice(ciphertext);
        match cipher.decrypt_in_place(nonce, b"", &mut buffer) {
            Ok(_) => {}
            Err(_) => {
                return None
            }
        };
        Some(Header::from(buffer))
    }
    pub fn ex_public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_string().as_bytes().to_vec()
    }
}

impl From<Vec<u8>> for Header {
    fn from(d: Vec<u8>) -> Self {
        let ex_header: ExHeader = bincode::deserialize(&d).unwrap();
        let public_key_string = String::from_utf8(ex_header.public_key.clone()).unwrap();
        Header {
            public_key: PublicKey::from_str(&public_key_string).unwrap(),
            pn: ex_header.pn,
            n: ex_header.n,
        }
    }
}

impl From<&[u8]> for Header {
    fn from(d: &[u8]) -> Self {
        let ex_header: ExHeader = bincode::deserialize(d).unwrap();
        let public_key_string = String::from_utf8(ex_header.public_key.clone()).unwrap();
        Header {
            public_key: PublicKey::from_str(&public_key_string).unwrap(),
            pn: ex_header.pn,
            n: ex_header.n,
        }
    }
}

impl From<Header> for Vec<u8> {
    fn from(s: Header) -> Self {
        s.concat(b"")
    }
}

impl PartialEq for Header {
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
pub fn gen_header() -> Header {
    let dh_pair = gen_key_pair();
    let pn = 10;
    let n = 50;
    Header::new(&dh_pair, pn, n)
}


#[cfg(test)]
mod tests {
    use crate::header::{gen_header, Header, ExHeader};
    use crate::kdf_chain::gen_mk;
    use crate::aead::{encrypt, decrypt};

    #[test]
    fn ser_des() {
        let ad = b"";
        let header = gen_header();
        let serialized = header.concat(ad);
        let created = Header::from(serialized.as_slice());
        assert_eq!(header, created)
    }

    #[test]
    fn enc_header() {
        let header = gen_header();
        let mk = gen_mk();
        let header_data = header.concat(b"");
        let data = include_bytes!("aead.rs");
        let (encrypted, nonce) = encrypt(&mk, data, &header_data);
        let decrypted = decrypt(&mk, &encrypted, &header_data, &nonce);
        assert_eq!(decrypted, data.to_vec())
    }

    #[test]
    fn test_eq_header() {
        let header1 = gen_header();
        let header2 = gen_header();
        assert_ne!(header1, header2)
    }

    #[test]
    fn debug_header() {
        let header = gen_header();
        let _string = alloc::format!("{:?}", header);
    }

    #[test]
    fn gen_ex_header() {
        let ex_header = ExHeader {
            ad: alloc::vec![0],
            public_key: alloc::vec![1],
            pn: 0,
            n: 0
        };
        let _string = alloc::format!("{:?}", ex_header);
    }

    #[test]
    fn dec_header() {
        let header = gen_header();
        let (encrypted, nonce) = header.encrypt(&[0; 32], &[0]);
        let decrypted = Header::decrypt(&Some([1_u8; 32]), &encrypted, &nonce);
        assert_eq!(None, decrypted)
    }
}