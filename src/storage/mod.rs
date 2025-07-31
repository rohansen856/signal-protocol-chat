use crate::crypto::{IdentityKeyPair, PreKeyPair, SignedPreKeyPair};
use crate::error::{Result, SignalError};
use crate::protocol::{ChatMessage, PreKeyBundle, RatchetState};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub identity_key: IdentityKeyPair,
    pub signed_prekey: SignedPreKeyPair,
    pub one_time_prekeys: Vec<PreKeyPair>,
    pub next_prekey_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub address: String,
    pub identity_key: [u8; 32],
    pub last_seen: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub contact_name: String,
    pub ratchet_state: RatchetState,
    pub established: bool,
}

pub struct Storage {
    pub db: Db,
    path: std::path::PathBuf,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let db = sled::open(&path_buf)
            .map_err(|e| SignalError::Storage(format!("Failed to open database: {e}")))?;

        Ok(Self { db, path: path_buf })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn store_identity(&self, identity: &Identity) -> Result<()> {
        let serialized = serde_json::to_vec(identity).map_err(SignalError::from)?;

        self.db
            .insert("identity", serialized)
            .map_err(|e| SignalError::Storage(format!("Failed to store identity: {e}")))?;

        Ok(())
    }

    pub fn load_identity(&self) -> Result<Option<Identity>> {
        match self.db.get("identity") {
            Ok(Some(data)) => {
                let identity = serde_json::from_slice(&data).map_err(SignalError::from)?;
                Ok(Some(identity))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(SignalError::Storage(format!(
                "Failed to load identity: {e}"
            ))),
        }
    }

    pub fn store_contact(&self, contact: &Contact) -> Result<()> {
        let key = format!("contact:{}", contact.name);
        let serialized = serde_json::to_vec(contact).map_err(SignalError::from)?;

        self.db
            .insert(key, serialized)
            .map_err(|e| SignalError::Storage(format!("Failed to store contact: {e}")))?;

        Ok(())
    }

    pub fn load_contact(&self, name: &str) -> Result<Option<Contact>> {
        let key = format!("contact:{name}");
        match self.db.get(&key) {
            Ok(Some(data)) => {
                let contact = serde_json::from_slice(&data).map_err(SignalError::from)?;
                Ok(Some(contact))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(SignalError::Storage(format!(
                "Failed to load contact: {e}"
            ))),
        }
    }

    pub fn list_contacts(&self) -> Result<Vec<Contact>> {
        let mut contacts = Vec::new();

        for result in self.db.scan_prefix("contact:") {
            match result {
                Ok((_key, value)) => {
                    if let Ok(contact) = serde_json::from_slice::<Contact>(&value) {
                        contacts.push(contact);
                    }
                }
                Err(e) => {
                    return Err(SignalError::Storage(format!(
                        "Failed to scan contacts: {e}"
                    )))
                }
            }
        }

        Ok(contacts)
    }

    pub fn store_session(&self, contact_name: &str, session: &Session) -> Result<()> {
        let key = format!("session:{contact_name}");
        let serialized = serde_json::to_vec(session).map_err(SignalError::from)?;

        self.db
            .insert(key, serialized)
            .map_err(|e| SignalError::Storage(format!("Failed to store session: {e}")))?;

        Ok(())
    }

    pub fn load_session(&self, contact_name: &str) -> Result<Option<Session>> {
        let key = format!("session:{contact_name}");
        match self.db.get(&key) {
            Ok(Some(data)) => {
                let session = serde_json::from_slice(&data).map_err(SignalError::from)?;
                Ok(Some(session))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(SignalError::Storage(format!(
                "Failed to load session: {e}"
            ))),
        }
    }

    pub fn store_message(&self, contact_name: &str, message: &ChatMessage) -> Result<()> {
        let key = format!("message:{}:{}", contact_name, message.id);
        let serialized = serde_json::to_vec(message).map_err(SignalError::from)?;

        self.db
            .insert(key, serialized)
            .map_err(|e| SignalError::Storage(format!("Failed to store message: {e}")))?;

        Ok(())
    }

    pub fn load_messages(&self, contact_name: &str, limit: usize) -> Result<Vec<ChatMessage>> {
        let prefix = format!("message:{contact_name}:");
        let mut messages = Vec::new();

        for result in self.db.scan_prefix(&prefix) {
            match result {
                Ok((_key, value)) => {
                    if let Ok(message) = serde_json::from_slice::<ChatMessage>(&value) {
                        messages.push(message);
                    }
                }
                Err(e) => {
                    return Err(SignalError::Storage(format!(
                        "Failed to scan messages: {e}"
                    )))
                }
            }
        }

        messages.sort_by_key(|m| m.timestamp);
        if messages.len() > limit {
            messages.truncate(limit);
        }

        Ok(messages)
    }

    pub fn consume_one_time_prekey(&self, identity: &mut Identity) -> Result<Option<PreKeyPair>> {
        if let Some(prekey) = identity.one_time_prekeys.pop() {
            self.store_identity(identity)?;
            Ok(Some(prekey))
        } else {
            Ok(None)
        }
    }

    pub fn generate_one_time_prekeys(&self, identity: &mut Identity, count: u32) -> Result<()> {
        for _ in 0..count {
            let prekey = PreKeyPair::generate(identity.next_prekey_id);
            identity.one_time_prekeys.push(prekey);
            identity.next_prekey_id += 1;
        }

        self.store_identity(identity)
    }
}

impl Identity {
    pub fn new(name: String) -> Result<Self> {
        let identity_key = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKeyPair::generate(1, &identity_key)?;

        let mut one_time_prekeys = Vec::new();
        for i in 0..10 {
            one_time_prekeys.push(PreKeyPair::generate(i + 1));
        }

        Ok(Self {
            name,
            identity_key,
            signed_prekey,
            one_time_prekeys,
            next_prekey_id: 11,
        })
    }

    pub fn to_prekey_bundle(&self, one_time_prekey: Option<&PreKeyPair>) -> PreKeyBundle {
        PreKeyBundle::new(&self.identity_key, &self.signed_prekey, one_time_prekey)
    }
}
