use x25519_dalek::PublicKey;
use crate::dh::DhKeyPair;
use alloc::vec::Vec;
use serde::{Serialize, Deserialize};

#[cfg(test)]
use crate::dh::gen_key_pair;

#[derive(Debug)]
pub struct Header {
    pub public_key: PublicKey,
    pub pn: usize, // Previous Chain Length
    pub n: usize, // Message Number
}

#[derive(Serialize, Deserialize, Debug)]
struct ExHeader {
    public_key: [u8; 32],
    pn: usize,
    n: usize
}

impl Header {
    pub fn new(dh_pair: &DhKeyPair, pn: usize, n: usize) -> Self {
        Header {
            public_key: dh_pair.public_key,
            pn,
            n,
        }
    }

    pub fn concat(&self) -> Vec<u8> {
        let ex_header = ExHeader{
            public_key: self.public_key.to_bytes(),
            pn: self.pn,
            n: self.n
        };
        bincode::serialize(&ex_header).expect("Failed to serialize Header")
    }
}

impl From<Vec<u8>> for Header {
    fn from(d: Vec<u8>) -> Self {
        let ex_header: ExHeader = bincode::deserialize(&d).unwrap();
        Header {
            public_key: PublicKey::from(ex_header.public_key),
            pn: ex_header.pn,
            n: ex_header.n,
        }
    }
}

impl From<&[u8]> for Header {
    fn from(d: &[u8]) -> Self {
        let ex_header: ExHeader = bincode::deserialize(d).unwrap();
        Header {
            public_key: PublicKey::from(ex_header.public_key),
            pn: ex_header.pn,
            n: ex_header.n,
        }
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
    use crate::header::{gen_header, Header};
    use crate::kdf_chain::gen_mk;
    use crate::aead::{encrypt, decrypt};

    #[test]
    fn ser_des() {
        let header = gen_header();
        let serialized = header.concat();
        let created = Header::from(serialized);
        assert_eq!(header, created)
    }

    #[test]
    fn enc_header() {
        let header = gen_header();
        let mk = gen_mk();
        let header_data = header.concat();
        let data = include_bytes!("aead.rs");
        let encrypted = encrypt(&mk, data, &header_data);
        let decrypted = decrypt(&mk, &encrypted, &header_data);
        assert_eq!(decrypted, data.to_vec())
    }
}