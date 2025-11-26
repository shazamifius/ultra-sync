use notify::{self, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;

const DEBOUNCE_DURATION: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum FileSystemEvent {
    Modified(PathBuf),
    // Created is handled as Modified
    Deleted(PathBuf),
}

/// A service that watches the file system for changes and sends debounced events.
pub struct FileWatcher;

impl FileWatcher {
    /// Starts the file watcher service in a new Tokio task.
    pub fn start(
        event_sender: mpsc::Sender<FileSystemEvent>,
        sync_dir: PathBuf,
    ) -> notify::Result<()> {
        let (notify_tx, mut notify_rx) = mpsc::channel(100);

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                notify_tx.blocking_send(res).unwrap();
            },
            notify::Config::default(),
        )?;

        watcher.watch(&sync_dir, RecursiveMode::Recursive)?;

        let sync_dir_clone = sync_dir.clone();
        tokio::spawn(async move {
            let mut pending_events: HashMap<PathBuf, Instant> = HashMap::new();
            let sync_dir_task = sync_dir_clone;

            loop {
                // Wait for either a new event or for the debounce timer to expire.
                tokio::select! {
                    Some(event_result) = notify_rx.recv() => {
                        match event_result {
                            Ok(event) => {
                                // We are interested in any event kind, as we just want to know
                                // that *something* happened to this path.
                                if let Some(path) = event.paths.first() {
                                    pending_events.insert(path.clone(), Instant::now());
                                }
                            }
                            Err(e) => log::error!("Watch error: {:?}", e),
                        }
                    },
                    _ = sleep(DEBOUNCE_DURATION) => {
                        // When the timer expires, process events that are old enough.
                        let now = Instant::now();
                        let mut events_to_send = Vec::new();

                        pending_events.retain(|path, &mut instant| {
                            if now.duration_since(instant) >= DEBOUNCE_DURATION {
                                // This event is ready to be processed.
                                events_to_send.push(path.clone());
                                false // Remove from pending
                            } else {
                                true // Keep in pending
                            }
                        });

                        for path in events_to_send {
                            // Re-query the state of the path to send a single, correct event.
                            let is_deleted = !path.exists();
                            if let Some(fs_event) = Self::create_fs_event(&path, &sync_dir_task, is_deleted) {
                                 if let Err(e) = event_sender.send(fs_event).await {
                                     log::error!("Failed to send debounced file event: {}", e);
                                 }
                            }
                        }
                    }
                }
            }
        });

        log::info!("Started watching directory: {:?}", sync_dir);
        // The watcher is intentionally leaked here to keep it alive for the lifetime of the program.
        std::mem::forget(watcher);
        Ok(())
    }

    /// Creates a FileSystemEvent from a path.
    fn create_fs_event(path: &Path, sync_dir: &Path, is_deleted: bool) -> Option<FileSystemEvent> {
        if path.starts_with(sync_dir.join(".sync")) || path.extension().map_or(false, |s| s == "lock") {
            return None;
        }

        let relative_path = match path.strip_prefix(sync_dir) {
            Ok(p) => p.to_path_buf(),
            Err(_) => return None,
        };

        if is_deleted {
            Some(FileSystemEvent::Deleted(relative_path))
        } else {
            // To keep it simple, we treat creates and modifies as the same event.
            // The sync engine can determine if the file is new or just modified.
            Some(FileSystemEvent::Modified(relative_path))
        }
    }
}
