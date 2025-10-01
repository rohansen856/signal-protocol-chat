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

    #[arg(long)]
    pub user: Option<String>,
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

    // Load environment variables
    dotenv::dotenv().ok();

    match cli.command {
        Commands::Init { name } => {
            cli::init_identity(&name, &cli.data_dir).await?;
            println!("Identity '{name}' initialized successfully");
        }
        Commands::Chat { peer } => {
            let user = cli.user.as_deref().unwrap_or("default");
            cli::start_chat(peer, cli.port, &cli.data_dir, user).await?;
        }
        Commands::Contacts => {
            let user = cli.user.as_deref().unwrap_or("default");
            cli::list_contacts(user).await?;
        }
        Commands::AddContact { name, address } => {
            let user = cli.user.as_deref().unwrap_or("default");
            cli::add_contact(&name, &address, user).await?;
            println!("Contact '{name}' added successfully");
        }
    }

    Ok(())
}
