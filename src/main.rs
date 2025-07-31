mod cli;
mod crypto;
mod error;
mod network;
mod protocol;
mod storage;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "signal-chat")]
#[command(about = "A secure CLI chat application implementing Signal protocols")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(long, default_value = "~/.signal-chat")]
    pub data_dir: PathBuf,

    #[arg(long, default_value = "8080")]
    pub port: u16,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new identity
    Init {
        #[arg(short, long)]
        name: String,
    },
    /// Start the chat client
    Chat {
        #[arg(short, long)]
        peer: Option<String>,
    },
    /// List available contacts
    Contacts,
    /// Add a new contact
    AddContact { name: String, address: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { name } => {
            cli::init_identity(&name, &cli.data_dir).await?;
            println!("Identity '{name}' initialized successfully");
        }
        Commands::Chat { peer } => {
            cli::start_chat(peer, cli.port, &cli.data_dir).await?;
        }
        Commands::Contacts => {
            cli::list_contacts(&cli.data_dir).await?;
        }
        Commands::AddContact { name, address } => {
            cli::add_contact(&name, &address, &cli.data_dir).await?;
            println!("Contact '{name}' added successfully");
        }
    }

    Ok(())
}
