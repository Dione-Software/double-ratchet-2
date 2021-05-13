use crate::dh::DhKeyPair;
use x25519_dalek::PublicKey;
use hashbrown::HashMap;
use crate::kdf_root::kdf_rk;
use crate::header::Header;
use alloc::vec::Vec;
use crate::kdf_chain::kdf_ck;
use crate::aead::{encrypt, decrypt};

const MAX_SKIP: usize = 100;

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
    mkskipped: HashMap<(PublicKey, usize), [u8; 32]>,
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
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> (Header, Vec<u8>) {
        let (cks, mk) = kdf_ck(&self.cks.unwrap());
        self.cks = Some(cks);
        let header = Header::new(&self.dhs, self.pn, self.ns);
        self.ns += 1;
        let encrypted_data = encrypt(&mk, plaintext, &header.concat());
        (header, encrypted_data)
    }

    fn try_skipped_message_keys(&mut self, header: &Header, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if self.mkskipped.contains_key(&(header.public_key, header.n)) {
            let mk = *self.mkskipped.get(&(header.public_key, header.n))
                .unwrap();
            self.mkskipped.remove(&(header.public_key, header.n)).unwrap();
            Some(decrypt(&mk, ciphertext, &header.concat()))
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
                    self.mkskipped.insert((self.dhr.unwrap(), self.nr), mk);
                    self.nr += 1
                }
                Ok(())
            },
            None => { Err("No Ckr set") }
        }
    }

    /// Decrypt ciphertext with ratchet. Requires Header. Returns plaintext.
    pub fn ratchet_decrypt(&mut self, header: &Header, ciphertext: &[u8]) -> Vec<u8> {
        let plaintext = self.try_skipped_message_keys(header, ciphertext);
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
                decrypt(&mk, ciphertext, &header.concat())
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

