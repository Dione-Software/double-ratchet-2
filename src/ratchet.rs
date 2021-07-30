//! Encryption with encrypted Headers
//!

use crate::dh::DhKeyPair;
use p256::{PublicKey, SecretKey};
use hashbrown::HashMap;
use crate::kdf_root::{kdf_rk, kdf_rk_he};
use crate::header::Header;
use alloc::vec::Vec;
use crate::kdf_chain::kdf_ck;
use crate::aead::{encrypt, decrypt};
use alloc::string::ToString;
use zeroize::Zeroize;
use rand_core::OsRng;

const MAX_SKIP: usize = 100;

type HeaderNonceCipherNonce = ((Vec<u8>, [u8; 12]), Vec<u8>, [u8; 12]);

/// Object Representing Ratchet
pub struct Ratchet {
    dhs: DhKeyPair,
    dhr: Option<PublicKey>,
    rk: [u8; 32],
    ckr: Option<[u8; 32]>,
    cks: Option<[u8; 32]>,
    ns: usize,
    nr: usize,
    pn: usize,
    mkskipped: HashMap<(Vec<u8>, usize), [u8; 32]>,
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.dhs.zeroize();
        if let Some(mut _d) = self.dhr {
            let sk = SecretKey::random(&mut OsRng);
            _d = sk.public_key()
        }
        self.rk.zeroize();
        self.ckr.zeroize();
        self.cks.zeroize();
        self.ns.zeroize();
        self.nr.zeroize();
        self.pn.zeroize();
        self.mkskipped.clear();
    }
}

impl Ratchet {
    /// Init Ratchet with other [PublicKey]. Initialized second.
    pub fn init_alice(sk: [u8; 32], bob_dh_public_key: PublicKey) -> Self {
        let dhs = DhKeyPair::new();
        let (rk, cks) = kdf_rk(&sk,
                               &dhs.key_agreement(&bob_dh_public_key));
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
    pub fn init_bob(sk: [u8; 32]) -> (Self, PublicKey) {
        let dhs = DhKeyPair::new();
        let public_key = dhs.public_key;
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
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> (Header, Vec<u8>, [u8; 12]) {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
        let header = Header::new(&self.dhs, self.pn, self.ns);
        self.ns += 1;
        let (encrypted_data, nonce) = encrypt(&mk, plaintext, &header.concat(ad));
        (header, encrypted_data, nonce)
    }

    fn try_skipped_message_keys(&mut self, header: &Header, ciphertext: &[u8], nonce: &[u8; 12], ad: &[u8]) -> Option<Vec<u8>> {
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
            Some(d) => {
                while self.nr < until {
                    let (ckr, mk) = kdf_ck(&d);
                    self.ckr = Some(ckr);
                    self.mkskipped.insert((self.dhr.unwrap().to_string().as_bytes().to_vec(), self.nr), mk);
                    self.nr += 1
                }
                Ok(())
            },
            None => { Err("No Ckr set") }
        }
    }

    /// Decrypt ciphertext with ratchet. Requires Header. Returns plaintext.
    pub fn ratchet_decrypt(&mut self, header: &Header, ciphertext: &[u8], nonce: &[u8; 12], ad: &[u8]) -> Vec<u8> {
        let plaintext = self.try_skipped_message_keys(header, ciphertext, nonce, ad);
        match plaintext {
            Some(d) => d,
            None => {
                if Some(header.public_key) != self.dhr {
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

    fn dhratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.public_key);
        let (rk, ckr) = kdf_rk(&self.rk,
                               &self.dhs.key_agreement(&self.dhr.unwrap()));
        self.rk = rk;
        self.ckr = Some(ckr);
        self.dhs = DhKeyPair::new();
        let (rk, cks) = kdf_rk(&self.rk,
        &self.dhs.key_agreement(&self.dhr.unwrap()));
        self.rk = rk;
        self.cks = Some(cks);
    }
}

pub struct RatchetEncHeader {
    dhs: DhKeyPair,
    dhr: Option<PublicKey>,
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

impl Zeroize for RatchetEncHeader {
    fn zeroize(&mut self) {
        self.dhs.zeroize();
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

impl Drop for RatchetEncHeader {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl RatchetEncHeader {
    pub fn init_alice(sk: [u8; 32],
                      bob_dh_public_key: PublicKey,
                      shared_hka: [u8; 32],
                      shared_nhkb: [u8; 32]) -> Self {
        let dhs = DhKeyPair::new();
        let (rk, cks, nhks) = kdf_rk_he(&sk, &dhs.key_agreement(&bob_dh_public_key));
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

    pub fn init_bob(sk: [u8; 32], shared_hka: [u8; 32], shared_nhkb: [u8; 32]) -> (Self, PublicKey) {
        let dhs = DhKeyPair::new();
        let public_key = dhs.public_key;
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
        let header = Header::new(&self.dhs, self.pn, self.ns);
        let enc_header = header.encrypt(&self.hks.unwrap(), ad);
        self.ns += 1;
        let encrypted = encrypt(&mk, plaintext, &header.concat(ad));
        (enc_header, encrypted.0, encrypted.1)
    }

    fn try_skipped_message_keys(&mut self, enc_header: &(Vec<u8>, [u8; 12]),
                                ciphertext: &[u8], nonce: &[u8; 12], ad: &[u8]) -> (Option<Vec<u8>>, Option<Header>) {

        let ret_data = self.mkskipped.clone().into_iter().find(|e| {
            let header = Header::decrypt(&e.0.0, &enc_header.0, &enc_header.1);
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

    fn decrypt_header(&mut self, enc_header: &(Vec<u8>, [u8; 12])) -> Result<(Header, bool), &str> {
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
        if let Some(d) = self.ckr {
            while self.nr < until {
                let (ckr, mk) = kdf_ck(&d);
                self.ckr = Some(ckr);
                self.mkskipped.insert((self.hkr, self.nr), mk);
                self.nr += 1
            }
        }
        Ok(())
    }

    fn dhratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.hks = self.nhks;
        self.hkr = self.nhkr;
        self.dhr = Some(header.public_key);
        let (rk, ckr, nhkr) = kdf_rk_he(&self.rk,
                                        &self.dhs.key_agreement(&self.dhr.unwrap()));
        self.rk = rk;
        self.ckr = Some(ckr);
        self.nhkr = Some(nhkr);
        self.dhs = DhKeyPair::new();
        let (rk, cks, nhks) = kdf_rk_he(&self.rk,
                                        &self.dhs.key_agreement(&self.dhr.unwrap()));
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

    pub fn ratchet_decrypt_w_header(&mut self, enc_header: &(Vec<u8>, [u8; 12]), ciphertext: &[u8], nonce: &[u8; 12], ad: &[u8]) -> (Vec<u8>, Header) {
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