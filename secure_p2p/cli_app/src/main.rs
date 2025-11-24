use clap::{Parser, Subcommand};
use crypto::{generate_keypair, keypair_exists, load_keypair, save_keypair, CryptoError, Keypair};
use p2p_core::{client::{run_client, ClientCommand}, run_server};
use rpassword::prompt_password;
use std::process;
use ledger_core::EventType;
use chrono::{DateTime, Utc};
use libp2p::Multiaddr;

#[derive(Parser, Debug)]
#[clap(name = "secure-p2p-cli", version = "0.1.0", author = "Jules")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Listen for incoming connections (run as a persistent peer)
    Listen,
    /// Dial a remote peer (run as a persistent peer)
    Dial {
        #[clap(long)]
        remote_addr: Multiaddr,
    },
    /// Display the event ledger
    Ledger {
        /// Display ledger in raw JSON format
        #[clap(long)]
        json: bool,
    },
    /// Request a lock for a file from a set of peers
    RequestLock {
        #[clap(long)]
        file_path: String,
        /// The multiaddresses of the peers to request the lock from
        #[clap(long, use_value_delimiter = true)]
        peers: Vec<Multiaddr>,
        #[clap(long, default_value_t = 60)]
        bail_duration: u64,
    },
    /// Transfer a file from a remote peer
    TransferFile {
        #[clap(long)]
        file_path: String,
        #[clap(long)]
        peer_addr: Multiaddr,
    },
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Ledger { json } => {
            if let Err(e) = display_ledger(json) {
                log::error!("Failed to display ledger: {}", e);
                process::exit(1);
            }
        },
        _ => {
            let keypair = match manage_keypair() {
                Ok(kp) => kp,
                Err(e) => {
                    log::error!("Failed to manage keypair: {}", e);
                    process::exit(1);
                }
            };

            match cli.command {
                Commands::Listen => {
                    if let Err(e) = run_server(keypair, None).await {
                        log::error!("Server failed: {}", e);
                        process::exit(1);
                    }
                },
                Commands::Dial { remote_addr } => {
                    if let Err(e) = run_server(keypair, Some(remote_addr)).await {
                        log::error!("Server failed: {}", e);
                        process::exit(1);
                    }
                },
                Commands::RequestLock { file_path, peers, bail_duration } => {
                    let command = ClientCommand::RequestLock { file_path, peers, bail_duration };
                    if let Err(e) = run_client(keypair, command).await {
                        log::error!("Client command failed: {}", e);
                        process::exit(1);
                    }
                },
                Commands::TransferFile { file_path, peer_addr } => {
                    let command = ClientCommand::TransferFile { file_path, remote_addr: peer_addr };
                    if let Err(e) = run_client(keypair, command).await {
                        log::error!("Client command failed: {}", e);
                        process::exit(1);
                    }
                },
                _ => unreachable!(), // Already handled Ledger
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
    let ledger = ledger_core::Ledger::load("p2p_ledger.dat")?;

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
            let event_info = match &entry.event_type {
                EventType::ConnectionEstablished => "ConnectionEstablished".to_string(),
                EventType::ConnectionLost => "ConnectionLost".to_string(),
                EventType::HeartbeatReceived => "HeartbeatReceived".to_string(),
                EventType::FileLockRequested { file_path } => format!("FileLockRequested | File: {}", file_path),
                EventType::LockGranted { file_path } => format!("LockGranted | File: {}", file_path),
                EventType::LockDenied { file_path } => format!("LockDenied | File: {}", file_path),
                EventType::FileUpdated { file_hash } => format!("FileUpdated | Hash: {}...", hex::encode(file_hash).chars().take(12).collect::<String>()),
            };
            let peer_id_short = hex::encode(&entry.peer_id).chars().take(12).collect::<String>();
            println!(
                "[{}] Peer: {}... | Event: {}",
                timestamp.to_rfc3339(),
                peer_id_short,
                event_info
            );
        }
    }

    Ok(())
}
