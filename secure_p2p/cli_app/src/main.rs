use clap::{Parser, Subcommand};
use crypto::{generate_keypair, keypair_exists, load_keypair, save_keypair, CryptoError, Keypair};
use p2p_core::run_swarm;
use rpassword::prompt_password;
use std::process;
use ledger_core::{Ledger, EventType};
use chrono::{DateTime, Utc};

#[derive(Parser, Debug)]
#[clap(name = "secure-p2p-cli", version = "0.1.0", author = "Jules")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Listen for incoming connections
    Listen,
    /// Dial a remote peer
    Dial {
        #[clap(long)]
        remote_addr: libp2p::Multiaddr,
    },
    /// Display the event ledger
    Ledger {
        /// Display ledger in raw JSON format
        #[clap(long)]
        json: bool,
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Listen | Commands::Dial { .. } => {
            let keypair = match manage_keypair() {
                Ok(kp) => kp,
                Err(e) => {
                    log::error!("Failed to manage keypair: {}", e);
                    process::exit(1);
                }
            };

            let remote_addr = match cli.command {
                Commands::Dial { remote_addr } => Some(remote_addr),
                _ => None,
            };

            if let Err(e) = run_swarm(keypair, remote_addr).await {
                log::error!("P2P swarm failed: {}", e);
                process::exit(1);
            }
        }
        Commands::Ledger { json } => {
            if let Err(e) = display_ledger(json) {
                log::error!("Failed to display ledger: {}", e);
                process::exit(1);
            }
        }
    }
}

fn manage_keypair() -> Result<Keypair, CryptoError> {
    if keypair_exists() {
        log::info!("Existing keypair found. Please enter your passphrase to unlock.");
        let passphrase = prompt_password("Passphrase: ").unwrap();
        load_keypair(&passphrase)
    } else {
        log::info!("No existing keypair found. Let's create one.");
        let passphrase = prompt_password("Enter a new passphrase (will be used to encrypt your key): ").unwrap();
        let confirm_passphrase = prompt_password("Confirm passphrase: ").unwrap();

        if passphrase != confirm_passphrase {
            return Err(CryptoError::PassphraseMismatch);
        }

        log::info!("Generating new keypair...");
        let keypair = generate_keypair();
        save_keypair(&keypair, &passphrase)?;
        log::info!("New keypair generated and saved successfully.");
        Ok(keypair)
    }
}

fn display_ledger(use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let ledger = Ledger::load("p2p_ledger.dat")?;

    if !ledger.verify_integrity() {
        log::warn!("WARNING: Ledger integrity check failed!");
    } else {
        log::info!("Ledger integrity check passed.");
    }

    println!("--- Ledger Content ---");

    if use_json {
        let json_output = serde_json::to_string_pretty(&ledger.entries)?;
        println!("{}", json_output);
    } else {
        for entry in &ledger.entries {
            let timestamp: DateTime<Utc> = entry.timestamp;
            let event_name = match entry.event_type {
                EventType::ConnectionEstablished => "ConnectionEstablished",
                EventType::ConnectionLost => "ConnectionLost",
                EventType::HeartbeatReceived => "HeartbeatReceived",
                EventType::FileLockRequested => "FileLockRequested",
            };
            let peer_id_short = hex::encode(&entry.peer_id).chars().take(12).collect::<String>();
            println!(
                "[{}] Peer: {}... | Event: {}",
                timestamp.to_rfc3339(),
                peer_id_short,
                event_name
            );
        }
    }

    Ok(())
}
