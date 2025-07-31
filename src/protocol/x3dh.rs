use crate::crypto::{hkdf, EphemeralKeyPair, IdentityKeyPair, PreKeyPair, SignedPreKeyPair};
use crate::error::{Result, SignalError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyBundle {
    #[serde(with = "serde_arrays")]
    pub identity_key: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub signed_prekey: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub signed_prekey_signature: [u8; 64],
    pub signed_prekey_id: u32,
    pub one_time_prekey: Option<[u8; 32]>,
    pub one_time_prekey_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct X3DHKeyExchange {
    #[serde(with = "serde_arrays")]
    pub identity_key: [u8; 32],
    #[serde(with = "serde_arrays")]
    pub ephemeral_key: [u8; 32],
    pub used_one_time_prekey_id: Option<u32>,
}

pub struct X3DHSession {
    pub shared_secret: [u8; 32],
    pub associated_data: Vec<u8>,
}

impl PreKeyBundle {
    pub fn new(
        identity_key: &IdentityKeyPair,
        signed_prekey: &SignedPreKeyPair,
        one_time_prekey: Option<&PreKeyPair>,
    ) -> Self {
        Self {
            identity_key: identity_key.public_key(),
            signed_prekey: signed_prekey.public_key,
            signed_prekey_signature: signed_prekey.signature,
            signed_prekey_id: signed_prekey.id,
            one_time_prekey: one_time_prekey.map(|pk| pk.public_key),
            one_time_prekey_id: one_time_prekey.map(|pk| pk.id),
        }
    }

    pub fn verify(&self) -> Result<bool> {
        crate::crypto::xeddsa::verify(
            &self.identity_key,
            &self.signed_prekey,
            &self.signed_prekey_signature,
        )
    }
}

pub fn initiate_x3dh(
    alice_identity: &IdentityKeyPair,
    bob_bundle: &PreKeyBundle,
) -> Result<(X3DHSession, X3DHKeyExchange)> {
    if !bob_bundle.verify()? {
        return Err(SignalError::InvalidSignature);
    }

    let alice_ephemeral = EphemeralKeyPair::generate();

    let dh1 = alice_identity.shared_secret(&bob_bundle.signed_prekey)?;
    let dh2 = alice_ephemeral.shared_secret(&bob_bundle.identity_key)?;
    let dh3 = alice_ephemeral.shared_secret(&bob_bundle.signed_prekey)?;

    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    let mut used_one_time_prekey_id = None;

    if let Some(one_time_prekey) = bob_bundle.one_time_prekey {
        let dh4 = alice_ephemeral.shared_secret(&one_time_prekey)?;
        dh_concat.extend_from_slice(&dh4);
        used_one_time_prekey_id = bob_bundle.one_time_prekey_id;
    }

    let shared_secret_bytes = hkdf::derive_keys(
        &dh_concat,
        Some(b"signal_x3dh"),
        b"signal_x3dh_shared_secret",
        32,
    )?;

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_bytes);

    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(&alice_identity.public_key());
    associated_data.extend_from_slice(&bob_bundle.identity_key);

    let key_exchange = X3DHKeyExchange {
        identity_key: alice_identity.public_key(),
        ephemeral_key: alice_ephemeral.public_key,
        used_one_time_prekey_id,
    };

    let session = X3DHSession {
        shared_secret,
        associated_data,
    };

    Ok((session, key_exchange))
}

pub fn respond_x3dh(
    bob_identity: &IdentityKeyPair,
    bob_signed_prekey: &SignedPreKeyPair,
    bob_one_time_prekey: Option<&PreKeyPair>,
    key_exchange: &X3DHKeyExchange,
) -> Result<X3DHSession> {
    let alice_ephemeral_key = key_exchange.ephemeral_key;

    let dh1 = bob_signed_prekey.shared_secret(&key_exchange.identity_key)?;
    let dh2 = bob_identity.shared_secret(&alice_ephemeral_key)?;
    let dh3 = bob_signed_prekey.shared_secret(&alice_ephemeral_key)?;

    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    if let (Some(one_time_prekey), Some(_)) =
        (bob_one_time_prekey, key_exchange.used_one_time_prekey_id)
    {
        let dh4 = one_time_prekey.shared_secret(&alice_ephemeral_key)?;
        dh_concat.extend_from_slice(&dh4);
    }

    let shared_secret_bytes = hkdf::derive_keys(
        &dh_concat,
        Some(b"signal_x3dh"),
        b"signal_x3dh_shared_secret",
        32,
    )?;

    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_bytes);

    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(&key_exchange.identity_key);
    associated_data.extend_from_slice(&bob_identity.public_key());

    Ok(X3DHSession {
        shared_secret,
        associated_data,
    })
}
