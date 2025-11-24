use clap::{Parser, Subcommand};
use crypto::{generate_keypair, keypair_exists, load_keypair, save_keypair, CryptoError, Keypair};
use p2p_core::run_swarm;
use rpassword::prompt_password;
use std::process;

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
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let cli = Cli::parse();
    let keypair = match manage_keypair() {
        Ok(kp) => kp,
        Err(e) => {
            log::error!("Failed to manage keypair: {}", e);
            process::exit(1);
        }
    };

    let remote_addr = match cli.command {
        Commands::Listen => None,
        Commands::Dial { remote_addr } => Some(remote_addr),
    };

    if let Err(e) = run_swarm(keypair, remote_addr).await {
        log::error!("P2P swarm failed: {}", e);
        process::exit(1);
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
