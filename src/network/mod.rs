use crate::error::{Result, SignalError};
use crate::protocol::SignalMessage;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkMessage {
    pub from: String,
    pub to: String,
    pub payload: SignalMessage,
}

pub struct NetworkManager {
    local_addr: SocketAddr,
    message_sender: mpsc::UnboundedSender<NetworkMessage>,
    message_receiver: mpsc::UnboundedReceiver<NetworkMessage>,
}

impl NetworkManager {
    pub fn new(port: u16) -> (Self, mpsc::UnboundedReceiver<NetworkMessage>) {
        let local_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (_tx, rx) = mpsc::unbounded_channel();
        let (internal_tx, internal_rx) = mpsc::unbounded_channel();

        let manager = Self {
            local_addr,
            message_sender: internal_tx,
            message_receiver: internal_rx,
        };

        (manager, rx)
    }

    pub async fn start_server(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.local_addr).await.map_err(|e| {
            SignalError::Network(format!("Failed to bind to {}: {}", self.local_addr, e))
        })?;

        println!("Server listening on {}", self.local_addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let sender = self.message_sender.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer_addr, sender).await {
                            eprintln!("Error handling connection from {peer_addr}: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {e}");
                }
            }
        }
    }

    pub async fn send_message(&self, target_addr: &str, message: &NetworkMessage) -> Result<()> {
        let stream = TcpStream::connect(target_addr).await.map_err(|e| {
            SignalError::Network(format!("Failed to connect to {target_addr}: {e}"))
        })?;

        send_message_to_stream(stream, message).await
    }

    pub async fn recv_message(&mut self) -> Option<NetworkMessage> {
        self.message_receiver.recv().await
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    sender: mpsc::UnboundedSender<NetworkMessage>,
) -> Result<()> {
    let mut buffer = vec![0; 4096];

    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                println!("Connection closed by {peer_addr}");
                break;
            }
            Ok(n) => {
                let data = &buffer[..n];

                if let Ok(length_bytes) = data[..4].try_into() {
                    let message_length = u32::from_be_bytes(length_bytes) as usize;

                    if data.len() >= 4 + message_length {
                        let message_data = &data[4..4 + message_length];

                        match serde_json::from_slice::<NetworkMessage>(message_data) {
                            Ok(message) => {
                                if sender.send(message).is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "Failed to deserialize message from {peer_addr}: {e}"
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from {peer_addr}: {e}");
                break;
            }
        }
    }

    Ok(())
}

async fn send_message_to_stream(mut stream: TcpStream, message: &NetworkMessage) -> Result<()> {
    let serialized = serde_json::to_vec(message).map_err(SignalError::from)?;

    let length = serialized.len() as u32;
    let length_bytes = length.to_be_bytes();

    stream
        .write_all(&length_bytes)
        .await
        .map_err(|e| SignalError::Network(format!("Failed to write message length: {e}")))?;

    stream
        .write_all(&serialized)
        .await
        .map_err(|e| SignalError::Network(format!("Failed to write message: {e}")))?;

    stream
        .flush()
        .await
        .map_err(|e| SignalError::Network(format!("Failed to flush stream: {e}")))?;

    Ok(())
}

pub fn parse_address(addr: &str) -> Result<String> {
    if addr.contains(':') {
        Ok(addr.to_string())
    } else {
        Ok(format!("{addr}:8080"))
    }
}
