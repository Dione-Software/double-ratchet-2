use rand_core::OsRng;
use core::fmt::{Debug, Formatter};
use core::fmt;
use p256::PublicKey as PublicKey;
use p256::ecdh::SharedSecret;
use p256::SecretKey;
use alloc::vec::Vec;
use alloc::string::ToString;
use p256::elliptic_curve::ecdh::diffie_hellman;

pub struct DhKeyPair {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
}

impl DhKeyPair {
    fn ex_public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_string().as_bytes().to_vec()
    }
}

impl PartialEq for DhKeyPair {
    fn eq(&self, other: &Self) -> bool {
        if self.private_key.to_bytes() != other.private_key.to_bytes() {
            return false
        }
        if self.ex_public_key_bytes() != other.ex_public_key_bytes() {
            return false
        }
        true
    }
}

impl Debug for DhKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhKeyPair")
            .field("private_key", &self.private_key.to_bytes())
            .field("public_key", &self.ex_public_key_bytes())
            .finish()
    }
}

impl Default for DhKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl DhKeyPair {
    pub fn new() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let public = PublicKey::from_secret_scalar(&secret.secret_scalar());
        DhKeyPair {
            private_key: secret,
            public_key: public,
        }
    }

    pub fn key_agreement(&self, public_key: &PublicKey) -> SharedSecret {
        diffie_hellman(self.private_key.secret_scalar(), public_key.as_affine())
    }
}

#[cfg(test)]
pub fn gen_shared_secret() -> SharedSecret {
    let alice_pair = DhKeyPair::new();
    let bob_pair = DhKeyPair::new();
    alice_pair.key_agreement(&bob_pair.public_key)
}

#[cfg(test)]
pub fn gen_key_pair() -> DhKeyPair {
    DhKeyPair::new()
}

#[cfg(test)]
mod tests {
    use crate::dh::DhKeyPair;

    #[test]
    fn key_generation() {
        let pair_1 = DhKeyPair::new();
        let pair_2 = DhKeyPair::new();
        assert_ne!(pair_1, pair_2)
    }

    #[test]
    fn key_agreement() {
        let alice_pair = DhKeyPair::new();
        let bob_pair = DhKeyPair::new();
        let alice_shared_secret = alice_pair.key_agreement(&bob_pair.public_key);
        let bob_shared_secret = bob_pair.key_agreement(&alice_pair.public_key);
        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes())
    }
}