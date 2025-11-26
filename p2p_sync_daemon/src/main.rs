use p2p_sync_daemon::{
    journal::service::{JournalService, JOURNAL_INTERVAL},
    network::service::NetworkService,
    sync::{engine::SyncEngine, watcher::{FileWatcher, FileSystemEvent}},
};
use std::path::PathBuf;
use tokio::{signal, sync::mpsc, time::interval};

// Declare the modules to make them available in the main binary.
pub mod journal;
pub mod lock;
pub mod network;
pub mod sync;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Initialization ---
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("Starting P2P Sync Daemon...");

    // For this example, we'll sync a directory named "sync_folder" in the current directory.
    let sync_dir = PathBuf::from("sync_folder");
    if !sync_dir.exists() {
        log::info!("Creating sync directory: {:?}", sync_dir);
        std::fs::create_dir_all(&sync_dir)?;
    }
    let sync_dir = std::fs::canonicalize(sync_dir)?;

    // Create channels for communication between components.
    let (network_command_sender, network_command_receiver) = mpsc::channel(100);
    let (network_event_sender, mut network_event_receiver) = mpsc::channel(100);
    let (fs_event_sender, mut fs_event_receiver) = mpsc::channel(100);

    // Initialize the core services.
    let mut sync_engine = SyncEngine::new(sync_dir.clone(), network_command_sender.clone());
    let journal_service = JournalService::new(&sync_dir)?;

    // --- Startup & Recovery ---

    // Cleanup stale locks from a potential previous crash.
    sync_engine.lock_manager.cleanup_stale_locks()?;

    // Check the journal for signs of an abnormal shutdown.
    let files_to_recover = journal_service.check_for_recovery()?;
    for file_path in files_to_recover {
        log::info!("File {:?} needs recovery. Triggering sync.", file_path);
        sync_engine.handle_fs_event(file_path).await;
    }

    // Start the network service in a separate task.
    let network_service = NetworkService::new(network_command_receiver, network_event_sender).await?;
    tokio::spawn(network_service.run());

    // Start the file system watcher.
    FileWatcher::start(fs_event_sender, sync_dir.clone())?;

    // --- Main Event Loop ---
    log::info!("Entering main event loop...");
    let mut journal_ticker = interval(JOURNAL_INTERVAL);

    loop {
        tokio::select! {
            // An event from the network service.
            Some(event) = network_event_receiver.recv() => {
                sync_engine.handle_network_event(event).await;
            },

            // An event from the file system watcher.
            Some(event) = fs_event_receiver.recv() => {
                match event {
                    FileSystemEvent::Modified(path) => {
                        sync_engine.handle_fs_event(path).await;
                    },
                    FileSystemEvent::Deleted(_path) => {
                        // TODO: Implement file deletion logic.
                        // This would involve creating a `FileDeleted` gossip message.
                    }
                }
            },

            // The journal ticker fires.
            _ = journal_ticker.tick() => {
                let active_locks = sync_engine.lock_manager.get_local_locks();
                if !active_locks.is_empty() {
                     if let Err(e) = journal_service.log_activity(&active_locks) {
                         log::error!("Failed to write to journal: {}", e);
                     }
                }
            },

            // Handle graceful shutdown on Ctrl+C.
            _ = signal::ctrl_c() => {
                log::info!("Ctrl+C received, shutting down gracefully...");
                journal_service.clear()?; // Clear the journal for a clean shutdown.
                break;
            }
        }
    }

    Ok(())
}
