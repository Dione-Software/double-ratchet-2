use alloc::vec::Vec;
use core::fmt::Debug;
use rand_core::{CryptoRng, RngCore};
use serde::{Serialize, Deserialize};

pub trait PublicKey: Serialize + for<'a> Deserialize<'a> + Debug + Clone + PartialEq {
	fn to_bytes(&self) -> Vec<u8>;
}

pub trait SharedSecret {
	fn as_bytes(&self) -> &[u8];
}

pub trait PrivateKey: Sized + Clone {
	type Public: PublicKey;
	type Shared: SharedSecret;

	fn random<R: CryptoRng + RngCore>(rng: R) -> Self;

	fn diffie_hellman(&self, public_key: &Self::Public) -> Self::Shared;

	fn derive_public_key(&self) -> Self::Public;

	fn from_bytes(enc: &[u8]) -> Option<Self>;

	fn to_vec(self) -> Vec<u8>;
}


impl PublicKey for x25519_dalek::PublicKey {
	fn to_bytes(&self) -> Vec<u8> {
		self.as_bytes().to_vec()
	}
}


impl SharedSecret for x25519_dalek::SharedSecret {
	fn as_bytes(&self) -> &[u8] {
		x25519_dalek::SharedSecret::as_bytes(self)
	}
}


impl PrivateKey for x25519_dalek::StaticSecret {
	type Public = x25519_dalek::PublicKey;
	type Shared = x25519_dalek::SharedSecret;

	fn random<R: CryptoRng + RngCore>(rng: R) -> Self {
		x25519_dalek::StaticSecret::new(rng)
	}

	fn diffie_hellman(&self, public_key: &Self::Public) -> Self::Shared {
		self.diffie_hellman(public_key)
	}

	fn derive_public_key(&self) -> Self::Public {
		x25519_dalek::PublicKey::from(self)
	}

	fn from_bytes(enc: &[u8]) -> Option<Self> {
		if enc.len() != 32 {
			return None;
		}
		let mut bytes = [0u8; 32];
		bytes.copy_from_slice(enc);
		Some(x25519_dalek::StaticSecret::from(bytes))
	}

	fn to_vec(self) -> Vec<u8> {
		self.to_bytes().to_vec()
	}
}