use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use rand_core::OsRng;
use core::fmt::{Debug, Formatter};
use core::fmt;

pub struct DhKeyPair {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
}

impl PartialEq for DhKeyPair {
    fn eq(&self, other: &Self) -> bool {
        if self.private_key.to_bytes() != other.private_key.to_bytes() {
            return false
        }
        if self.public_key.to_bytes() != other.public_key.to_bytes() {
            return false
        }
        true
    }
}

impl Debug for DhKeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhKeyPair")
            .field("private_key", &self.private_key.to_bytes())
            .field("public_key", &self.public_key.to_bytes())
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
        let secret = StaticSecret::new(OsRng);
        let public = PublicKey::from(&secret);
        DhKeyPair {
            private_key: secret,
            public_key: public,
        }
    }

    pub fn key_agreement(&self, public_key: &PublicKey) -> SharedSecret {
        self.private_key.diffie_hellman(public_key)
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