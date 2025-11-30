use clap::{Parser, Subcommand, ValueEnum};
use crypto::{generate_keypair, keypair_exists, load_keypair, save_keypair, CryptoError, Keypair};
use p2p_core::{client::{run_client, ClientCommand}, run_server, roles::RoleRegistry};
use std::process;
use ledger_core::{EventType, Role};
use chrono::{DateTime, Utc};
use libp2p::{Multiaddr, PeerId};
use std::str::FromStr;

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
    /// Transfer a file from a remote peer
    TransferFile {
        #[clap(long)]
        file_path: String,
        #[clap(long)]
        peer_addr: Multiaddr,
    },
    /// Set the role for a peer (Admin only)
    SetRole {
        #[clap(long)]
        peer_id: String,
        #[clap(long)]
        role: CliRole,
        #[clap(long)]
        admin_peer: Multiaddr,
    },
    /// Show the current roles from the local ledger
    ShowRoles,
    /// Update a file to connected peers (Notifies of update)
    UpdateFile {
        #[clap(long)]
        file_path: String,
        /// The multiaddresses of the peers to notify of the update
        #[clap(long, use_value_delimiter = true)]
        peers: Vec<Multiaddr>,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum CliRole {
    Reader,
    Contributor,
    Admin,
}

impl From<CliRole> for Role {
    fn from(role: CliRole) -> Self {
        match role {
            CliRole::Reader => Role::Reader,
            CliRole::Contributor => Role::Contributor,
            CliRole::Admin => Role::Admin,
        }
    }
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
        Commands::ShowRoles => {
            if let Err(e) = show_roles() {
                log::error!("Failed to show roles: {}", e);
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
                    if let Err(e) = run_server(keypair, None, None, None, None).await {
                        log::error!("Server failed: {}", e);
                        process::exit(1);
                    }
                },
                Commands::Dial { remote_addr } => {
                    if let Err(e) = run_server(keypair, Some(remote_addr), None, None, None).await {
                        log::error!("Server failed: {}", e);
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
                Commands::SetRole { peer_id, role, admin_peer } => {
                    let target_peer_id = match PeerId::from_str(&peer_id) {
                        Ok(id) => id.to_bytes(),
                        Err(e) => {
                            log::error!("Invalid PeerId format: {}", e);
                            process::exit(1);
                        }
                    };
                    let command = ClientCommand::SetRole {
                        target_peer_id,
                        role: role.into(),
                        admin_peer,
                    };
                    if let Err(e) = run_client(keypair, command).await {
                        log::error!("Client command failed: {}", e);
                        process::exit(1);
                    }
                },
                Commands::UpdateFile { file_path, peers } => {
                    let command = ClientCommand::UpdateFile { file_path, peers };
                    if let Err(e) = run_client(keypair, command).await {
                        log::error!("Client command failed: {}", e);
                        process::exit(1);
                    }
                },
                _ => unreachable!(), // Ledger and ShowRoles are handled
            }
        }
    }
}

fn manage_keypair() -> Result<Keypair, CryptoError> {
    if keypair_exists() {
        log::info!("Existing keypair found. Loading...");
        load_keypair("") // Pass an empty passphrase for now
    } else {
        log::info!("No existing keypair found. Generating a new one...");
        let keypair = generate_keypair();
        save_keypair(&keypair, "")?;
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
                EventType::PresenceUpdate { file_path, status } => format!("Presence | File: {} | Status: {}", file_path, status),
                EventType::FileUpdated { file_hash, .. } => format!("FileUpdated | Hash: {}...", hex::encode(file_hash).chars().take(12).collect::<String>()),
                EventType::RoleUpdate { target_peer_id, new_role } => format!("RoleUpdate | Target: {}..., Role: {:?}", hex::encode(target_peer_id).chars().take(12).collect::<String>(), new_role),
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

fn show_roles() -> Result<(), Box<dyn std::error::Error>> {
    let ledger = ledger_core::Ledger::load("p2p_ledger.dat")?;
    let registry = RoleRegistry::new_from_ledger(&ledger);

    println!("--- Role Registry ---");
    if registry.roles().next().is_none() {
        println!("No roles have been assigned yet.");
    } else {
        for (peer_id_bytes, role) in registry.roles() {
            let peer_id_str = match PeerId::from_bytes(peer_id_bytes) {
                Ok(pid) => pid.to_base58(),
                Err(_) => hex::encode(peer_id_bytes),
            };
            println!("Peer: {:<52} | Role: {:?}", peer_id_str, role);
        }
    }

    Ok(())
}
