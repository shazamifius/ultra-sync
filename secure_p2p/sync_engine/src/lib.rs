use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use tokio::sync::broadcast;
use log::{info, error};

// Define Sync Events
#[derive(Debug, Clone)]
pub enum SyncEvent {
    FileChanged(PathBuf),
    FileCreated(PathBuf),
    FileDeleted(PathBuf),
}

pub struct SyncEngine {
    watch_path: PathBuf,
    event_sender: broadcast::Sender<SyncEvent>,
}

impl SyncEngine {
    pub fn new(watch_path: PathBuf) -> Self {
        let (tx, _) = broadcast::channel(100);
        Self {
            watch_path,
            event_sender: tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SyncEvent> {
        self.event_sender.subscribe()
    }

    pub async fn start(&self) {
        let path = self.watch_path.clone();
        let tx = self.event_sender.clone();

        tokio::task::spawn_blocking(move || {
            let (notify_tx, notify_rx) = channel();

            let mut watcher = RecommendedWatcher::new(notify_tx, Config::default()).unwrap();

            if let Err(e) = watcher.watch(&path, RecursiveMode::Recursive) {
                error!("Failed to watch directory: {:?}", e);
                return;
            }

            info!("SyncEngine watching: {:?}", path);

            loop {
                match notify_rx.recv() {
                    Ok(Ok(event)) => {
                         // Simple debouncing/filtering logic could go here
                         // For now, map notify events to SyncEvents
                         match event.kind {
                             notify::EventKind::Create(_) => {
                                 for path in event.paths {
                                     let _ = tx.send(SyncEvent::FileCreated(path));
                                 }
                             },
                             notify::EventKind::Modify(_) => {
                                 for path in event.paths {
                                     let _ = tx.send(SyncEvent::FileChanged(path));
                                 }
                             },
                             notify::EventKind::Remove(_) => {
                                 for path in event.paths {
                                     let _ = tx.send(SyncEvent::FileDeleted(path));
                                 }
                             },
                             _ => {}
                         }
                    },
                    Ok(Err(e)) => error!("Watch error: {:?}", e),
                    Err(e) => {
                        error!("Watcher channel error: {:?}", e);
                        break;
                    }
                }
            }
        });
    }
}
