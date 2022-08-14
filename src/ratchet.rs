//! Encryption with encrypted Headers
//!

use crate::dh::DhKeyPair;
use hashbrown::HashMap;
use crate::kdf_root::{kdf_rk, kdf_rk_he};
use crate::header::Header;
use alloc::vec::Vec;
use crate::kdf_chain::kdf_ck;
use crate::aead::{encrypt, decrypt};
use zeroize::Zeroize;
use serde::{Deserialize, Serialize};
use crate::curve::{PrivateKey, PublicKey as TPublicKey, SharedSecret};

const MAX_SKIP: usize = 100;

type HeaderNonceCipherNonce = ((Vec<u8>, [u8; 12]), Vec<u8>, [u8; 12]);

/// Object Representing Ratchet
#[derive(Serialize, Deserialize)]
pub struct Ratchet<T: PrivateKey> {
    dhs: DhKeyPair<T>,
    dhr: Option<<T>::Public>,
    rk: [u8; 32],
    ckr: Option<[u8; 32]>,
    cks: Option<[u8; 32]>,
    ns: usize,
    nr: usize,
    pn: usize,
    mkskipped: HashMap<(Vec<u8>, usize), [u8; 32]>,
}


impl<T: PrivateKey> Drop for Ratchet<T> {
    fn drop(&mut self) {
        self.rk.zeroize();
        self.ckr.zeroize();
        self.cks.zeroize();
        self.ns.zeroize();
        self.nr.zeroize();
        self.pn.zeroize();
        self.mkskipped.clear();
    }
}

impl<T: PrivateKey> Ratchet<T> {
    /// Init Ratchet with other [PublicKey]. Initialized second.
    pub fn init_alice(sk: [u8; 32], bob_dh_public_key: <T>::Public) -> Self {
        let dhs = DhKeyPair::new();
        let shared: <T>::Shared = dhs.key_agreement(&bob_dh_public_key);
        let (rk, cks) = kdf_rk(&sk,
                               shared.as_bytes());
        Ratchet {
            dhs,
            dhr: Some(bob_dh_public_key),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        }
    }

    /// Init Ratchet without other [PublicKey]. Initialized first. Returns [Ratchet] and [PublicKey].
    pub fn init_bob(sk: [u8; 32]) -> (Self, <T>::Public) {
        let dhs = DhKeyPair::new();
        let public_key: T::Public = dhs.public_key();
        let ratchet = Ratchet {
            dhs,
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        };
        (ratchet, public_key)
    }

    /// Encrypt Plaintext with [Ratchet]. Returns Message [Header] and ciphertext.
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> (Header<<T>::Public>, Vec<u8>, [u8; 12]) {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
        let header = Header::new(&self.dhs, self.pn, self.ns);
        self.ns += 1;
        let (encrypted_data, nonce) = encrypt(&mk, plaintext, &header.concat(ad));
        (header, encrypted_data, nonce)
    }

    fn try_skipped_message_keys(&mut self, header: &Header<<T>::Public>, ciphertext: &[u8], nonce: &[u8; 12], ad: &[u8]) -> Option<Vec<u8>> {
        if self.mkskipped.contains_key(&(header.ex_public_key_bytes(), header.n)) {
            let mk = *self.mkskipped.get(&(header.ex_public_key_bytes(), header.n))
                .unwrap();
            self.mkskipped.remove(&(header.ex_public_key_bytes(), header.n)).unwrap();
            Some(decrypt(&mk, ciphertext, &header.concat(ad), nonce))
        } else {
            None
        }
    }

    fn skip_message_keys(&mut self, until: usize) -> Result<(), &str> {
        if self.nr + MAX_SKIP < until {
            return Err("Skipped to many keys");
        }
        match self.ckr {
            Some(mut d) => {
                while self.nr < until {
                    let (ckr, mk) = kdf_ck(&d);
                    self.ckr = Some(ckr);
                    d = ckr;
                    self.mkskipped.insert((self.dhr.as_ref().unwrap().to_bytes(), self.nr), mk);
                    self.nr += 1
                }
                Ok(())
            },
            None => { Err("No Ckr set") }
        }
    }

    /// Decrypt ciphertext with ratchet. Requires Header. Returns plaintext.
    pub fn ratchet_decrypt(&mut self, header: &Header<<T>::Public>, ciphertext: &[u8], nonce: &[u8; 12], ad: &[u8]) -> Vec<u8> {
        let plaintext = self.try_skipped_message_keys(header, ciphertext, nonce, ad);
        match plaintext {
            Some(d) => d,
            None => {
                if Some(bincode::deserialize(&header.public_key).unwrap()) != self.dhr {
                    if self.ckr != None {
                        self.skip_message_keys(header.pn).unwrap();
                    }
                    self.dhratchet(header);
                }
                self.skip_message_keys(header.n).unwrap();
                let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
                self.ckr = Some(ckr);
                self.nr += 1;
                decrypt(&mk, ciphertext, &header.concat(ad), nonce)
            }
        }
    }

    fn dhratchet(&mut self, header: &Header<T::Public>) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(bincode::deserialize(&header.public_key).unwrap());
        let shared = self.dhs.key_agreement(&self.dhr.as_ref().unwrap());
        let (rk, ckr) = kdf_rk(&self.rk,
                               shared.as_bytes());
        self.rk = rk;
        self.ckr = Some(ckr);
        self.dhs = DhKeyPair::new();
        let shared = self.dhs.key_agreement(&self.dhr.as_ref().unwrap());
        let (rk, cks) = kdf_rk(&self.rk,
        shared.as_bytes());
        self.rk = rk;
        self.cks = Some(cks);
    }
}

#[derive(Serialize, Deserialize)]
pub struct RatchetEncHeader<T: PrivateKey> {
    dhs: DhKeyPair<T>,
    dhr: Option<T::Public>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: usize,
    nr: usize,
    pn: usize,
    hks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    nhks: Option<[u8; 32]>,
    nhkr: Option<[u8; 32]>,
    mkskipped: HashMap<(Option<[u8; 32]>, usize), [u8; 32]>
}

impl<T: PrivateKey + Serialize + for<'a> Deserialize<'a>> Zeroize for RatchetEncHeader<T> {
    fn zeroize(&mut self) {
        self.rk.zeroize();
        self.cks.zeroize();
        self.ckr.zeroize();
        self.ns.zeroize();
        self.nr.zeroize();
        self.pn.zeroize();
        self.hks.zeroize();
        self.hkr.zeroize();
        self.nhks.zeroize();
        self.nhkr.zeroize();
        self.mkskipped.clear();

    }
}




impl<T: PrivateKey> RatchetEncHeader<T> {
    pub fn init_alice(sk: [u8; 32],
                      bob_dh_public_key: T::Public,
                      shared_hka: [u8; 32],
                      shared_nhkb: [u8; 32]) -> Self {
        let dhs = DhKeyPair::new();
        let shared: T::Shared = dhs.key_agreement(&bob_dh_public_key);
        let (rk, cks, nhks) = kdf_rk_he(&sk, shared.as_bytes());
        RatchetEncHeader {
            dhs,
            dhr: Some(bob_dh_public_key),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
            hks: Some(shared_hka),
            hkr: None,
            nhkr: Some(shared_nhkb),
            nhks: Some(nhks),
        }
    }

    pub fn init_bob(sk: [u8; 32], shared_hka: [u8; 32], shared_nhkb: [u8; 32]) -> (Self, T::Public) {
        let dhs = DhKeyPair::new();
        let public_key = dhs.public_key();
        let ratchet = Self {
            dhs,
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
            hks: None,
            nhks: Some(shared_nhkb),
            hkr: None,
            nhkr: Some(shared_hka),
        };
        (ratchet, public_key)
    }

    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> HeaderNonceCipherNonce {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
        let header: Header<T::Public> = Header::new(&self.dhs, self.pn, self.ns);
        let enc_header = header.encrypt(&self.hks.unwrap(), ad);
        self.ns += 1;
        let encrypted = encrypt(&mk, plaintext, &header.concat(ad));
        (enc_header, encrypted.0, encrypted.1)
    }

    fn try_skipped_message_keys(&mut self, enc_header: &(Vec<u8>, [u8; 12]),
                                ciphertext: &[u8], nonce: &[u8; 12], ad: &[u8]) -> (Option<Vec<u8>>, Option<Header<T::Public>>) {
        let ret_data = self.mkskipped.clone().into_iter().find(|e| {
            let header: Option<Header<T::Public>> = Header::decrypt(&e.0.0, &enc_header.0, &enc_header.1);
            match header {
                None => false,
                Some(h) => h.n == e.0.1
            }
        });
        match ret_data {
            None => { (None, None) },
            Some(data) => {
                let header = Header::decrypt(&data.0.0, &enc_header.0, &enc_header.1);
                let mk = data.1;
                self.mkskipped.remove(&(data.0.0, data.0.1));
                (Some(decrypt(&mk, ciphertext, &header.clone().unwrap().concat(ad), nonce)), header)
            }
        }
    }

    fn decrypt_header(&mut self, enc_header: &(Vec<u8>, [u8; 12])) -> Result<(Header<T::Public>, bool), &str> {
        let header = Header::decrypt(&self.hkr, &enc_header.0, &enc_header.1);
        if let Some(h) = header { return Ok((h, false)) };
        let header = Header::decrypt(&self.nhkr, &enc_header.0, &enc_header.1);
        match header {
            Some(h) => Ok((h, true)),
            None => Err("Header is unencryptable!")
        }
    }

    fn skip_message_keys(&mut self, until: usize) -> Result<(), &str> {
        if self.nr + MAX_SKIP < until {
            return Err("Skipping went wrong")
        }
        if let Some(d) = &mut self.ckr {
            while self.nr < until {
                let (ckr, mk) = kdf_ck(d);
                *d = ckr;
                self.mkskipped.insert((self.hkr, self.nr), mk);
                self.nr += 1
            }
        }
        Ok(())
    }

    fn dhratchet(&mut self, header: &Header<T::Public>) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = self.nhks;
        self.hkr = self.nhkr;
        self.dhr = Some(bincode::deserialize(&header.public_key).unwrap());
        let shared = self.dhs.key_agreement(&self.dhr.as_ref().unwrap());
        let (rk, ckr, nhkr) = kdf_rk_he(&self.rk,
                                        shared.as_bytes());
        self.rk = rk;
        self.ckr = Some(ckr);
        self.nhkr = Some(nhkr);
        self.dhs = DhKeyPair::new();
        let shared = self.dhs.key_agreement(&self.dhr.as_ref().unwrap());
        let (rk, cks, nhks) = kdf_rk_he(&self.rk,
                                        shared.as_bytes());
        self.rk = rk;
        self.cks = Some(cks);
        self.nhks = Some(nhks);
    }

    pub fn ratchet_decrypt(&mut self, enc_header: &(Vec<u8>, [u8; 12]), ciphertext: &[u8], nonce: &[u8; 12], ad: &[u8]) -> Vec<u8> {
        let (plaintext, _) = self.try_skipped_message_keys(enc_header, ciphertext, nonce, ad);
        if let Some(d) = plaintext { return d };
        let (header, dh_ratchet) = self.decrypt_header(enc_header).unwrap();
        if dh_ratchet {
            self.skip_message_keys(header.pn).unwrap();
            self.dhratchet(&header);
        }
        self.skip_message_keys(header.n).unwrap();
        let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
        self.ckr = Some(ckr);
        self.nr += 1;
        decrypt(&mk, ciphertext, &header.concat(ad), nonce)
    }

    pub fn ratchet_decrypt_w_header(&mut self, enc_header: &(Vec<u8>, [u8; 12]), ciphertext: &[u8], nonce: &[u8; 12], ad: &[u8]) -> (Vec<u8>, Header<T::Public>) {
        let (plaintext, header) = self.try_skipped_message_keys(enc_header, ciphertext, nonce, ad);
        if let Some(d) = plaintext { return (d, header.unwrap()) };
        let (header, dh_ratchet) = self.decrypt_header(enc_header).unwrap();
        if dh_ratchet {
            self.skip_message_keys(header.pn).unwrap();
            self.dhratchet(&header);
        }
        self.skip_message_keys(header.n).unwrap();
        let (ckr, mk) = kdf_ck(&self.ckr.unwrap());
        self.ckr = Some(ckr);
        self.nr += 1;
        (decrypt(&mk, ciphertext, &header.concat(ad), nonce), header)
    }
}

impl<T: PrivateKey + Serialize + for<'a> Deserialize<'a>> RatchetEncHeader<T> {
    /// Export the ratchet to Binary data
    pub fn export(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    /// Import the ratchet from Binary data. Panics when binary data is invalid.
    pub fn import(inp: &[u8]) -> Option<Self> {
        Some(bincode::deserialize(inp).ok()?)
    }
}
