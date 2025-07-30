use crate::error::Result;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    #[serde(with = "serde_arrays")]
    pub private_key: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphemeralKeyPair {
    #[serde(with = "serde_arrays")]
    pub private_key: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyPair {
    pub id: u32,
    #[serde(with = "serde_arrays")]
    pub private_key: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPreKeyPair {
    pub id: u32,
    #[serde(with = "serde_arrays")]
    pub private_key: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub public_key: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64],
    pub timestamp: u64,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let private_key_bytes = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
            bytes
        };
        let private_key = X25519PrivateKey::from(private_key_bytes);
        let public_key = X25519PublicKey::from(&private_key);

        Self {
            private_key: private_key_bytes,
            public_key: public_key.to_bytes(),
        }
    }

    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let secret = X25519PrivateKey::from(private_key);
        let public_key = X25519PublicKey::from(&secret);

        Self {
            private_key,
            public_key: public_key.to_bytes(),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub fn private_key(&self) -> [u8; 32] {
        self.private_key
    }

    pub fn shared_secret(&self, their_public: &[u8; 32]) -> Result<[u8; 32]> {
        let our_private = X25519PrivateKey::from(self.private_key);
        let their_public = X25519PublicKey::from(*their_public);

        let shared = our_private.diffie_hellman(&their_public);
        Ok(shared.to_bytes())
    }
}

impl EphemeralKeyPair {
    pub fn generate() -> Self {
        let private_key_bytes = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
            bytes
        };
        let private_key = X25519PrivateKey::from(private_key_bytes);
        let public_key = X25519PublicKey::from(&private_key);

        Self {
            private_key: private_key_bytes,
            public_key: public_key.to_bytes(),
        }
    }

    pub fn shared_secret(&self, their_public: &[u8; 32]) -> Result<[u8; 32]> {
        let our_private = X25519PrivateKey::from(self.private_key);
        let their_public = X25519PublicKey::from(*their_public);

        let shared = our_private.diffie_hellman(&their_public);
        Ok(shared.to_bytes())
    }
}

impl PreKeyPair {
    pub fn generate(id: u32) -> Self {
        let private_key_bytes = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
            bytes
        };
        let private_key = X25519PrivateKey::from(private_key_bytes);
        let public_key = X25519PublicKey::from(&private_key);

        Self {
            id,
            private_key: private_key_bytes,
            public_key: public_key.to_bytes(),
        }
    }

    pub fn shared_secret(&self, their_public: &[u8; 32]) -> Result<[u8; 32]> {
        let our_private = X25519PrivateKey::from(self.private_key);
        let their_public = X25519PublicKey::from(*their_public);

        let shared = our_private.diffie_hellman(&their_public);
        Ok(shared.to_bytes())
    }
}

impl SignedPreKeyPair {
    pub fn generate(id: u32, identity_key: &IdentityKeyPair) -> Result<Self> {
        let private_key_bytes = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
            bytes
        };
        let private_key = X25519PrivateKey::from(private_key_bytes);
        let public_key = X25519PublicKey::from(&private_key);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature =
            crate::crypto::xeddsa::sign(&identity_key.private_key, &public_key.to_bytes())?;

        Ok(Self {
            id,
            private_key: private_key_bytes,
            public_key: public_key.to_bytes(),
            signature,
            timestamp,
        })
    }

    pub fn verify_signature(&self, identity_public_key: &[u8; 32]) -> Result<bool> {
        crate::crypto::xeddsa::verify(identity_public_key, &self.public_key, &self.signature)
    }

    pub fn shared_secret(&self, their_public: &[u8; 32]) -> Result<[u8; 32]> {
        let our_private = X25519PrivateKey::from(self.private_key);
        let their_public = X25519PublicKey::from(*their_public);

        let shared = our_private.diffie_hellman(&their_public);
        Ok(shared.to_bytes())
    }
}

pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    bytes
}
