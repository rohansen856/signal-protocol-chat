pub mod chat;

use crate::error::{Result, SignalError};
use crate::network::{parse_address, NetworkManager, NetworkMessage};
use crate::protocol::ChatMessage;
use crate::storage::{Contact, Identity, Storage};
use chat::ChatSession;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use std::path::Path;
use tokio::sync::mpsc;

pub async fn init_identity(name: &str, _data_dir: &Path) -> Result<()> {
    let storage = Storage::new().await?;

    if storage.load_identity(name).await?.is_some() {
        return Err(SignalError::Protocol("Identity already exists".to_string()));
    }

    let identity = Identity::new(name.to_string())?;
    storage.store_identity(&identity).await?;

    println!("Identity created for '{name}'");
    println!(
        "Your identity key: {}",
        hex::encode(identity.identity_key.public_key())
    );

    Ok(())
}

pub async fn add_contact(name: &str, address: &str, owner: &str) -> Result<()> {
    let storage = Storage::new().await?;

    let contact = Contact {
        owner: owner.to_string(),
        name: name.to_string(),
        address: parse_address(address)?,
        identity_key: [0u8; 32], // Will be filled when first connecting
        last_seen: 0,
    };

    storage.store_contact(owner, &contact).await?;
    Ok(())
}

pub async fn list_contacts(owner: &str) -> Result<()> {
    let storage = Storage::new().await?;
    let contacts = storage.list_contacts(owner).await?;

    if contacts.is_empty() {
        println!("No contacts found");
        return Ok(());
    }

    println!("Contacts:");
    for contact in contacts {
        println!("  {} - {}", contact.name, contact.address);
    }

    Ok(())
}

pub async fn start_chat(peer: Option<String>, port: u16, _data_dir: &Path, user: &str) -> Result<()> {
    let storage = Storage::new().await?;

    let identity = storage
        .load_identity(user).await?
        .ok_or_else(|| SignalError::Protocol("No identity found. Run 'init' first.".to_string()))?;

    let (network, mut network_rx) = NetworkManager::new(port);

    // Start network server
    let server_handle = tokio::spawn(async move {
        if let Err(e) = network.start_server().await {
            eprintln!("Server error: {e}");
        }
    });

    // Start TUI
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app_result = run_chat_app(&mut terminal, &storage, &identity, peer, &mut network_rx).await;

    // Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    server_handle.abort();

    app_result
}

async fn run_chat_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    storage: &Storage,
    identity: &Identity,
    peer: Option<String>,
    network_rx: &mut mpsc::UnboundedReceiver<NetworkMessage>,
) -> Result<()> {
    let mut input = String::new();
    let mut messages: Vec<ChatMessage> = Vec::new();

    // Create ChatSession (placeholder network manager)
    let (network_manager, _) = NetworkManager::new(8080);
    let mut chat_session = ChatSession::new(
        Storage::new().await?,
        identity.clone(),
        network_manager,
    );

    if let Some(peer_name) = peer {
        if let Ok(_) = chat_session.start_conversation(&peer_name).await {
            messages = chat_session.load_message_history(&peer_name, 100).await?;
        }
    }

    loop {
        let current_contact = chat_session.get_current_contact();
        let session_established = chat_session.get_session_status();
        terminal.draw(|f| draw_ui(f, &messages, &input, current_contact, session_established))?;

        tokio::select! {
            // Handle keyboard input
            event_result = tokio::task::spawn_blocking(|| event::poll(std::time::Duration::from_millis(10))) => {
                if let Ok(Ok(true)) = event_result {
                    if let Ok(Event::Key(key)) = event::read() {
                        if key.kind == KeyEventKind::Press {
                            match key.code {
                                KeyCode::Char('q') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                                    break;
                                }
                                KeyCode::Enter => {
                                    if !input.trim().is_empty() && chat_session.get_current_contact().is_some() {
                                        if let Ok(_) = chat_session.send_message(&input).await {
                                            let message = ChatMessage::new_text(identity.name.clone(), input.clone());
                                            messages.push(message);
                                        }
                                        input.clear();
                                    }
                                }
                                KeyCode::Char(c) => {
                                    input.push(c);
                                }
                                KeyCode::Backspace => {
                                    input.pop();
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            // Handle incoming network messages
            network_msg = network_rx.recv() => {
                if let Some(msg) = network_msg {
                    if let Ok(Some(chat_msg)) = chat_session.handle_incoming_message(msg).await {
                        messages.push(chat_msg);
                    }
                }
            }
        }
    }

    Ok(())
}

fn draw_ui(
    f: &mut Frame,
    messages: &[ChatMessage],
    input: &str,
    current_contact: Option<&Contact>,
    session_established: bool,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

    // Header
    let title = match current_contact {
        Some(contact) => format!("Signal Chat - Connected to {}", contact.name),
        None => "Signal Chat - No active conversation".to_string(),
    };

    let session_status = if session_established {
        " [Encrypted]"
    } else {
        " [No Session]"
    };

    let header = Paragraph::new(format!("{title}{session_status}"))
        .block(Block::default().borders(Borders::ALL).title("Status"))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(header, chunks[0]);

    // Messages area
    let message_items: Vec<ListItem> = messages
        .iter()
        .map(|msg| {
            let style = match msg.message_type {
                crate::protocol::MessageType::System => Style::default().fg(Color::Yellow),
                crate::protocol::MessageType::Error => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::White),
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{}] ", msg.sender),
                    Style::default().fg(Color::Green),
                ),
                Span::styled(msg.content.clone(), style),
            ]))
        })
        .collect();

    let messages_widget =
        List::new(message_items).block(Block::default().borders(Borders::ALL).title("Messages"));
    f.render_widget(messages_widget, chunks[1]);

    // Input area
    let input_widget = Paragraph::new(input)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Type a message (Ctrl+Q to quit)"),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(input_widget, chunks[2]);
}
