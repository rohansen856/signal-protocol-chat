use crate::crypto::{IdentityKeyPair, PreKeyPair, SignedPreKeyPair};
use crate::error::{Result, SignalError};
use crate::protocol::{ChatMessage, RatchetState, PreKeyBundle};
use futures::stream::TryStreamExt;
use mongodb::{
    bson::doc,
    options::ClientOptions,
    Client, Collection, Database,
};
use serde::{Deserialize, Serialize};
use std::env;

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
    pub owner: String,
    pub name: String,
    pub address: String,
    pub identity_key: [u8; 32],
    pub last_seen: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub owner: String,
    pub contact_name: String,
    pub ratchet_state: RatchetState,
    pub established: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub owner: String,
    pub contact_name: String,
    pub sender: String,
    pub content: String,
    pub timestamp: u64,
    pub message_type: String,
}

pub struct Storage {
    db: Database,
    identities: Collection<Identity>,
    contacts: Collection<Contact>,
    sessions: Collection<Session>,
    messages: Collection<StoredMessage>,
}

impl Storage {
    pub async fn new() -> Result<Self> {
        // Load environment variables
        dotenv::dotenv().ok();

        let mongodb_uri = env::var("MONGODB_URI")
            .unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let database_name = env::var("MONGODB_DATABASE")
            .unwrap_or_else(|_| "signal_chat".to_string());

        // Parse MongoDB URI
        let client_options = ClientOptions::parse(&mongodb_uri)
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to parse MongoDB URI: {}", e)))?;

        // Create client
        let client = Client::with_options(client_options)
            .map_err(|e| SignalError::Storage(format!("Failed to create MongoDB client: {}", e)))?;

        // Test connection
        client
            .database("admin")
            .run_command(doc! {"ping": 1})
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to connect to MongoDB: {}", e)))?;

        let db = client.database(&database_name);
        let identities = db.collection("identities");
        let contacts = db.collection("contacts");
        let sessions = db.collection("sessions");
        let messages = db.collection("messages");

        Ok(Self {
            db,
            identities,
            contacts,
            sessions,
            messages,
        })
    }

    pub fn new_with_path(_path: &str) -> Result<Self> {
        // For compatibility - MongoDB doesn't use local paths
        // Return a blocking version that creates the connection
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(Self::new())
        })
    }

    pub fn path(&self) -> &str {
        // Return a placeholder path for MongoDB compatibility
        "mongodb://localhost:27017"
    }

    pub async fn store_identity(&self, identity: &Identity) -> Result<()> {
        let filter = doc! { "name": &identity.name };

        self.identities
            .replace_one(filter, identity)
            .upsert(true)
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to store identity: {}", e)))?;

        Ok(())
    }

    pub async fn load_identity(&self, name: &str) -> Result<Option<Identity>> {
        let filter = doc! { "name": name };

        match self.identities.find_one(filter).await {
            Ok(identity) => Ok(identity),
            Err(e) => Err(SignalError::Storage(format!("Failed to load identity: {}", e))),
        }
    }

    pub async fn store_contact(&self, owner: &str, contact: &Contact) -> Result<()> {
        let mut contact_with_owner = contact.clone();
        contact_with_owner.owner = owner.to_string();

        let filter = doc! { "owner": owner, "name": &contact.name };

        self.contacts
            .replace_one(filter, &contact_with_owner)
            .upsert(true)
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to store contact: {}", e)))?;

        Ok(())
    }

    pub async fn load_contact(&self, owner: &str, name: &str) -> Result<Option<Contact>> {
        let filter = doc! { "owner": owner, "name": name };

        match self.contacts.find_one(filter).await {
            Ok(contact) => Ok(contact),
            Err(e) => Err(SignalError::Storage(format!("Failed to load contact: {}", e))),
        }
    }

    pub async fn list_contacts(&self, owner: &str) -> Result<Vec<Contact>> {
        let filter = doc! { "owner": owner };
        let cursor = self.contacts
            .find(filter)
            .sort(doc! { "name": 1 })
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to list contacts: {}", e)))?;

        let contacts: Vec<Contact> = cursor
            .try_collect()
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to collect contacts: {}", e)))?;

        Ok(contacts)
    }

    pub async fn store_session(&self, owner: &str, session: &Session) -> Result<()> {
        let mut session_with_owner = session.clone();
        session_with_owner.owner = owner.to_string();

        let filter = doc! { "owner": owner, "contact_name": &session.contact_name };

        self.sessions
            .replace_one(filter, &session_with_owner)
            .upsert(true)
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to store session: {}", e)))?;

        Ok(())
    }

    pub async fn load_session(&self, owner: &str, contact_name: &str) -> Result<Option<Session>> {
        let filter = doc! { "owner": owner, "contact_name": contact_name };

        match self.sessions.find_one(filter).await {
            Ok(session) => Ok(session),
            Err(e) => Err(SignalError::Storage(format!("Failed to load session: {}", e))),
        }
    }

    pub async fn store_message(&self, owner: &str, contact_name: &str, message: &ChatMessage) -> Result<()> {
        let stored_message = StoredMessage {
            id: message.id.clone(),
            owner: owner.to_string(),
            contact_name: contact_name.to_string(),
            sender: message.sender.clone(),
            content: message.content.clone(),
            timestamp: message.timestamp,
            message_type: format!("{:?}", message.message_type),
        };

        let filter = doc! { "id": &message.id };

        self.messages
            .replace_one(filter, &stored_message)
            .upsert(true)
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to store message: {}", e)))?;

        Ok(())
    }

    pub async fn load_messages(&self, owner: &str, contact_name: &str, limit: usize) -> Result<Vec<ChatMessage>> {
        let filter = doc! { "owner": owner, "contact_name": contact_name };
        let cursor = self.messages
            .find(filter)
            .sort(doc! { "timestamp": -1 })
            .limit(limit as i64)
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to load messages: {}", e)))?;

        let stored_messages: Vec<StoredMessage> = cursor
            .try_collect()
            .await
            .map_err(|e| SignalError::Storage(format!("Failed to collect messages: {}", e)))?;

        let mut messages: Vec<ChatMessage> = stored_messages
            .into_iter()
            .map(|sm| ChatMessage {
                id: sm.id,
                sender: sm.sender,
                content: sm.content,
                timestamp: sm.timestamp,
                message_type: match sm.message_type.as_str() {
                    "Text" => crate::protocol::MessageType::Text,
                    "System" => crate::protocol::MessageType::System,
                    "Error" => crate::protocol::MessageType::Error,
                    _ => crate::protocol::MessageType::Text,
                },
            })
            .collect();

        // Reverse to get chronological order (oldest first)
        messages.reverse();
        Ok(messages)
    }

    pub async fn consume_one_time_prekey(&self, identity: &mut Identity) -> Result<Option<PreKeyPair>> {
        if let Some(prekey) = identity.one_time_prekeys.pop() {
            self.store_identity(identity).await?;
            Ok(Some(prekey))
        } else {
            Ok(None)
        }
    }

    pub async fn generate_one_time_prekeys(&self, identity: &mut Identity, count: u32) -> Result<()> {
        for _ in 0..count {
            let prekey = PreKeyPair::generate(identity.next_prekey_id);
            identity.one_time_prekeys.push(prekey);
            identity.next_prekey_id += 1;
        }

        self.store_identity(identity).await
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