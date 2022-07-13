use core::fmt::{Debug, Formatter};
use core::fmt;
use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use crate::curve::{PrivateKey, PublicKey as PublicKeyT};

#[derive(Clone, Serialize, Deserialize)]
pub struct DhKeyPair<P: PrivateKey> {
    pub private_key: P,
    pub public_key: <P as PrivateKey>::Public,
}


impl<P: PrivateKey> DhKeyPair<P> {
    fn ex_public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }

    pub(crate) fn public_key(&self) -> P::Public {
        self.public_key.clone()
    }
}

impl<T: PrivateKey + PartialEq> PartialEq for DhKeyPair<T> {
    fn eq(&self, other: &Self) -> bool {
        self.private_key.eq(&other.private_key) && self.public_key.eq(&other.public_key)
    }
}

impl<T: PrivateKey> Debug for DhKeyPair<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhKeyPair")
            .field("private_key", &self.private_key.clone().to_vec())
            .field("public_key", &self.ex_public_key_bytes())
            .finish()
    }
}

impl<T: PrivateKey> Default for DhKeyPair<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: PrivateKey> DhKeyPair<T> {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let secret = T::random(&mut rng);
        let public = secret.derive_public_key();
        DhKeyPair {
            private_key: secret,
            public_key: public,
        }
    }

    pub fn key_agreement(&self, public_key: &<T>::Public) -> <T>::Shared {
        self.private_key.diffie_hellman(public_key)
    }
}

#[cfg(test)]
pub fn gen_shared_secret() -> x25519_dalek::SharedSecret {
    let alice_pair = DhKeyPair::<x25519_dalek::StaticSecret>::new();
    let bob_pair = DhKeyPair::<x25519_dalek::StaticSecret>::new();
    alice_pair.key_agreement(&bob_pair.public_key)
}

#[cfg(test)]
pub fn gen_key_pair<T: PrivateKey>() -> DhKeyPair<T> {
    DhKeyPair::new()
}

#[cfg(test)]
mod tests {
    use crate::dh::DhKeyPair;

    #[test]
    fn key_generation() {
        let pair_1 = DhKeyPair::<x25519_dalek::StaticSecret>::new();
        let pair_2 = DhKeyPair::<x25519_dalek::StaticSecret>::new();
        assert_ne!(pair_1.ex_public_key_bytes(), pair_2.ex_public_key_bytes())
    }

    #[test]
    fn key_agreement() {
        let alice_pair = DhKeyPair::<x25519_dalek::StaticSecret>::new();
        let bob_pair = DhKeyPair::<x25519_dalek::StaticSecret>::new();
        let alice_shared_secret = alice_pair.key_agreement(&bob_pair.public_key);
        let bob_shared_secret = bob_pair.key_agreement(&alice_pair.public_key);
        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes())
    }

    #[test]
    fn ex_public_key() {
        let key_pair = DhKeyPair::<x25519_dalek::StaticSecret>::new();
        let public_key_bytes = key_pair.ex_public_key_bytes();
        let extracted_pk = key_pair.public_key.to_bytes().to_vec();
        assert_eq!(extracted_pk, public_key_bytes)
    }

    #[test]
    fn nq_key_pair() {
        let key_pair1 = DhKeyPair::<x25519_dalek::StaticSecret>::new();
        let mut key_pair2 = DhKeyPair::new();
        key_pair2.private_key = key_pair1.private_key.clone();
        assert_ne!(key_pair1.ex_public_key_bytes(), key_pair2.ex_public_key_bytes())
    }

    #[test]
    fn eq_key_pair() {
        let key_pair1 = DhKeyPair::<x25519_dalek::StaticSecret>::new();
        let key_pair2 = key_pair1.clone();
        assert_eq!(key_pair1.ex_public_key_bytes(), key_pair2.ex_public_key_bytes())
    }

    #[test]
    fn test_format() {
        let key_pair = DhKeyPair::<x25519_dalek::StaticSecret>::default();
        let _str = alloc::format!("{:?}", key_pair);
    }
}