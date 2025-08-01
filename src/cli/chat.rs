use crate::crypto::EphemeralKeyPair;
use crate::error::{Result, SignalError};
use crate::network::{NetworkManager, NetworkMessage};
use crate::protocol::{
    initiate_x3dh, respond_x3dh, ChatMessage, EncryptedMessage, RatchetState, SignalMessage,
    X3DHKeyExchange,
};
use crate::storage::{Contact, Identity, Session, Storage};

pub struct ChatSession {
    storage: Storage,
    identity: Identity,
    network: NetworkManager,
    current_contact: Option<Contact>,
    session: Option<Session>,
}

impl ChatSession {
    pub fn new(storage: Storage, identity: Identity, network: NetworkManager) -> Self {
        Self {
            storage,
            identity,
            network,
            current_contact: None,
            session: None,
        }
    }

    pub async fn start_conversation(&mut self, contact_name: &str) -> Result<()> {
        let contact = self
            .storage
            .load_contact(contact_name)?
            .ok_or_else(|| SignalError::ContactNotFound(contact_name.to_string()))?;

        self.current_contact = Some(contact.clone());

        // Check if we have an existing session
        if let Some(session) = self.storage.load_session(&contact.name)? {
            self.session = Some(session);
        } else {
            // Initiate new session with X3DH
            self.initiate_session(&contact).await?;
        }

        Ok(())
    }

    async fn initiate_session(&mut self, contact: &Contact) -> Result<()> {
        // Create a prekey bundle for the contact (in real implementation, this would be fetched)
        let contact_identity =
            crate::crypto::IdentityKeyPair::from_private_key(contact.identity_key);
        let contact_signed_prekey =
            crate::crypto::SignedPreKeyPair::generate(1, &contact_identity)?;
        let contact_one_time_prekey = Some(crate::crypto::PreKeyPair::generate(1));

        let prekey_bundle = crate::protocol::PreKeyBundle::new(
            &contact_identity,
            &contact_signed_prekey,
            contact_one_time_prekey.as_ref(),
        );

        let (x3dh_session, key_exchange) =
            initiate_x3dh(&self.identity.identity_key, &prekey_bundle)?;

        // Initialize Double Ratchet
        let bob_dh_public = contact_signed_prekey.public_key;
        let ratchet_state = RatchetState::init_alice(&x3dh_session.shared_secret, &bob_dh_public)?;

        let session = Session {
            contact_name: contact.name.clone(),
            ratchet_state,
            established: true,
        };

        self.storage.store_session(&contact.name, &session)?;
        self.session = Some(session);

        // Send key exchange message
        let signal_message = SignalMessage::KeyExchange {
            exchange: key_exchange,
            initial_message: None,
        };

        let network_message = NetworkMessage {
            from: self.identity.name.clone(),
            to: contact.name.clone(),
            payload: signal_message,
        };

        self.network
            .send_message(&contact.address, &network_message)
            .await?;

        Ok(())
    }

    pub async fn send_message(&mut self, content: &str) -> Result<()> {
        let contact = self
            .current_contact
            .as_ref()
            .ok_or_else(|| SignalError::Protocol("No active conversation".to_string()))?;

        let mut session = self.session.take().ok_or(SignalError::NoSession)?;

        let chat_message = ChatMessage::new_text(self.identity.name.clone(), content.to_string());
        let plaintext = chat_message.to_bytes();

        let encrypted_message = session
            .ratchet_state
            .encrypt(&plaintext, session.contact_name.as_bytes())?;

        let signal_message = SignalMessage::Regular {
            message: encrypted_message,
        };

        let network_message = NetworkMessage {
            from: self.identity.name.clone(),
            to: contact.name.clone(),
            payload: signal_message,
        };

        self.network
            .send_message(&contact.address, &network_message)
            .await?;

        // Store the session state
        self.storage.store_session(&contact.name, &session)?;
        self.session = Some(session);

        // Store the message locally
        self.storage.store_message(&contact.name, &chat_message)?;

        Ok(())
    }

    pub async fn handle_incoming_message(
        &mut self,
        network_message: NetworkMessage,
    ) -> Result<Option<ChatMessage>> {
        match network_message.payload {
            SignalMessage::KeyExchange {
                exchange,
                initial_message,
            } => {
                self.handle_key_exchange(network_message.from, exchange, initial_message)
                    .await
            }
            SignalMessage::Regular { message } => {
                self.handle_regular_message(network_message.from, message)
                    .await
            }
            SignalMessage::GroupMessage { .. } => {
                // Group messages not implemented yet
                Ok(None)
            }
        }
    }

    async fn handle_key_exchange(
        &mut self,
        from: String,
        exchange: X3DHKeyExchange,
        _initial_message: Option<EncryptedMessage>,
    ) -> Result<Option<ChatMessage>> {
        // In a real implementation, we would need to validate the key exchange
        // For now, we'll create a simple response

        let bob_dh_keypair = EphemeralKeyPair::generate();
        let x3dh_session = respond_x3dh(
            &self.identity.identity_key,
            &self.identity.signed_prekey,
            None, // No one-time prekey for simplicity
            &exchange,
        )?;

        let ratchet_state = RatchetState::init_bob(&x3dh_session.shared_secret, bob_dh_keypair);

        let session = Session {
            contact_name: from.clone(),
            ratchet_state,
            established: true,
        };

        self.storage.store_session(&from, &session)?;

        // If this contact doesn't exist, create it
        if self.storage.load_contact(&from)?.is_none() {
            let contact = Contact {
                name: from.clone(),
                address: "unknown".to_string(), // Would be filled from network info
                identity_key: exchange.identity_key,
                last_seen: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            self.storage.store_contact(&contact)?;
        }

        Ok(Some(ChatMessage::new_system(format!(
            "Secure session established with {from}"
        ))))
    }

    async fn handle_regular_message(
        &mut self,
        from: String,
        encrypted_message: EncryptedMessage,
    ) -> Result<Option<ChatMessage>> {
        let mut session = self
            .storage
            .load_session(&from)?
            .ok_or(SignalError::NoSession)?;

        let decrypted_bytes = session
            .ratchet_state
            .decrypt(&encrypted_message, from.as_bytes())?;

        // Update session state
        self.storage.store_session(&from, &session)?;

        if let Some(chat_message) = ChatMessage::from_bytes(&decrypted_bytes) {
            // Store the message
            self.storage.store_message(&from, &chat_message)?;
            Ok(Some(chat_message))
        } else {
            Err(SignalError::InvalidMessage)
        }
    }

    pub fn get_current_contact(&self) -> Option<&Contact> {
        self.current_contact.as_ref()
    }

    pub fn get_session_status(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.established)
    }

    pub fn load_message_history(
        &self,
        contact_name: &str,
        limit: usize,
    ) -> Result<Vec<ChatMessage>> {
        self.storage.load_messages(contact_name, limit)
    }
}
