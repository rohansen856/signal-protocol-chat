use crate::crypto::{hkdf, EphemeralKeyPair};
use crate::error::{Result, SignalError};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_SKIP: usize = 1000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetState {
    pub dhs: Option<EphemeralKeyPair>,
    pub dhr: Option<[u8; 32]>,
    #[serde(with = "serde_arrays")]
    pub rk: [u8; 32],
    pub cks: Option<[u8; 32]>,
    pub ckr: Option<[u8; 32]>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub mkskipped: HashMap<(Vec<u8>, u32), [u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    pub dh_public_key: Option<[u8; 32]>,
    pub previous_chain_length: u32,
    pub message_number: u32,
}

impl RatchetState {
    pub fn init_alice(shared_secret: &[u8; 32], bob_dh_public: &[u8; 32]) -> Result<Self> {
        let dhs = EphemeralKeyPair::generate();
        let dh_output = dhs.shared_secret(bob_dh_public)?;
        let (rk, cks) = hkdf::kdf_rk(shared_secret, &dh_output)?;

        Ok(Self {
            dhs: Some(dhs),
            dhr: Some(*bob_dh_public),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        })
    }

    pub fn init_bob(shared_secret: &[u8; 32], bob_dh_keypair: EphemeralKeyPair) -> Self {
        Self {
            dhs: Some(bob_dh_keypair),
            dhr: None,
            rk: *shared_secret,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        }
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedMessage> {
        let (message_key, new_cks) = match &self.cks {
            Some(cks) => hkdf::kdf_ck(cks)?,
            None => return Err(SignalError::Protocol("No sending chain key".to_string())),
        };

        self.cks = Some(new_cks);
        let current_ns = self.ns;
        self.ns += 1;

        let header = MessageHeader {
            dh_public_key: self.dhs.as_ref().map(|dhs| dhs.public_key),
            previous_chain_length: self.pn,
            message_number: current_ns,
        };

        let ciphertext = self.encrypt_message(&message_key, plaintext, associated_data, &header)?;

        Ok(EncryptedMessage { header, ciphertext })
    }

    pub fn decrypt(
        &mut self,
        message: &EncryptedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let plaintext = self.try_skipped_message_keys(message, associated_data)?;
        if plaintext.is_some() {
            return Ok(plaintext.unwrap());
        }

        if let Some(dh_public_key) = message.header.dh_public_key {
            if Some(dh_public_key) != self.dhr {
                self.skip_message_keys(message.header.previous_chain_length)?;
                self.dh_ratchet(&dh_public_key)?;
            }

            self.skip_message_keys(message.header.message_number)?;
            let (message_key, new_ckr) = match &self.ckr {
                Some(ckr) => hkdf::kdf_ck(ckr)?,
                None => return Err(SignalError::Protocol("No receiving chain key".to_string())),
            };

            self.ckr = Some(new_ckr);
            self.nr += 1;

            self.decrypt_message(
                &message_key,
                &message.ciphertext,
                associated_data,
                &message.header,
            )
        } else {
            Err(SignalError::Protocol(
                "Missing DH public key in header".to_string(),
            ))
        }
    }

    fn encrypt_message(
        &self,
        key: &[u8; 32],
        plaintext: &[u8],
        associated_data: &[u8],
        header: &MessageHeader,
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut aad = Vec::new();
        aad.extend_from_slice(associated_data);
        aad.extend_from_slice(
            &serde_json::to_vec(header)
                .map_err(|_| SignalError::Crypto("Header serialization failed".to_string()))?,
        );

        let mut ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SignalError::Crypto("Encryption failed".to_string()))?;

        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.append(&mut ciphertext);

        Ok(result)
    }

    fn decrypt_message(
        &self,
        key: &[u8; 32],
        ciphertext: &[u8],
        associated_data: &[u8],
        header: &MessageHeader,
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(SignalError::DecryptionFailed);
        }

        let nonce = Nonce::from_slice(&ciphertext[0..12]);
        let actual_ciphertext = &ciphertext[12..];

        let cipher = Aes256Gcm::new(key.into());

        let mut aad = Vec::new();
        aad.extend_from_slice(associated_data);
        aad.extend_from_slice(
            &serde_json::to_vec(header)
                .map_err(|_| SignalError::Crypto("Header serialization failed".to_string()))?,
        );

        cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|_| SignalError::DecryptionFailed)
    }

    fn dh_ratchet(&mut self, remote_public_key: &[u8; 32]) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(*remote_public_key);

        let dh_output = match &self.dhs {
            Some(dhs) => dhs.shared_secret(remote_public_key)?,
            None => return Err(SignalError::Protocol("No DH key pair".to_string())),
        };

        let (new_rk, new_ckr) = hkdf::kdf_rk(&self.rk, &dh_output)?;
        self.rk = new_rk;
        self.ckr = Some(new_ckr);

        self.dhs = Some(EphemeralKeyPair::generate());
        let new_dh_output = match &self.dhs {
            Some(dhs) => dhs.shared_secret(remote_public_key)?,
            None => {
                return Err(SignalError::Protocol(
                    "Failed to generate new DH key pair".to_string(),
                ))
            }
        };

        let (new_rk2, new_cks) = hkdf::kdf_rk(&self.rk, &new_dh_output)?;
        self.rk = new_rk2;
        self.cks = Some(new_cks);

        Ok(())
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if let Some(ckr) = &self.ckr {
            let mut current_ckr = *ckr;

            while self.nr < until {
                if self.mkskipped.len() >= MAX_SKIP {
                    return Err(SignalError::Protocol(
                        "Too many skipped messages".to_string(),
                    ));
                }

                let (mk, new_ckr) = hkdf::kdf_ck(&current_ckr)?;
                current_ckr = new_ckr;

                let key = (
                    self.dhr
                        .ok_or_else(|| SignalError::Protocol("No remote DH key".to_string()))?
                        .to_vec(),
                    self.nr,
                );
                self.mkskipped.insert(key, mk);
                self.nr += 1;
            }

            self.ckr = Some(current_ckr);
        }

        Ok(())
    }

    fn try_skipped_message_keys(
        &mut self,
        message: &EncryptedMessage,
        associated_data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if let Some(dh_public_key) = message.header.dh_public_key {
            let key = (dh_public_key.to_vec(), message.header.message_number);

            if let Some(mk) = self.mkskipped.remove(&key) {
                let plaintext = self.decrypt_message(
                    &mk,
                    &message.ciphertext,
                    associated_data,
                    &message.header,
                )?;
                return Ok(Some(plaintext));
            }
        }

        Ok(None)
    }
}
