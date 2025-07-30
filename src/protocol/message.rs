use crate::protocol::{EncryptedMessage, X3DHKeyExchange};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignalMessage {
    KeyExchange {
        exchange: X3DHKeyExchange,
        initial_message: Option<EncryptedMessage>,
    },
    Regular {
        message: EncryptedMessage,
    },
    GroupMessage {
        sender_id: String,
        message: EncryptedMessage,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub sender: String,
    pub content: String,
    pub timestamp: u64,
    pub message_type: MessageType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageType {
    Text,
    System,
    Error,
}

impl ChatMessage {
    pub fn new_text(sender: String, content: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender,
            content,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            message_type: MessageType::Text,
        }
    }

    pub fn new_system(content: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender: "system".to_string(),
            content,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            message_type: MessageType::System,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}
