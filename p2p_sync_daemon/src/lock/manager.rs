use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::network::protocol::{GossipMessage, LockState};

#[derive(Error, Debug)]
pub enum LockError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("File is already locked by a peer")]
    LockedByPeer,
    #[error("File is not currently locked")]
    NotLocked,
}

/// Manages the state of file locks, both local and remote.
pub struct LockManager {
    /// The root directory being synced.
    sync_dir: PathBuf,
    /// Set of paths currently locked by remote peers.
    peer_locks: HashSet<PathBuf>,
    /// Set of paths currently locked by the local user.
    local_locks: HashSet<PathBuf>,
}

impl LockManager {
    /// Creates a new LockManager.
    pub fn new(sync_dir: PathBuf) -> Self {
        Self {
            sync_dir,
            peer_locks: HashSet::new(),
            local_locks: HashSet::new(),
        }
    }

    /// Attempts to acquire a lock on a file.
    /// Creates a .lock file locally.
    pub fn acquire_lock(&mut self, relative_path: &Path) -> Result<GossipMessage, LockError> {
        if self.is_locked_by_peer(relative_path) {
            return Err(LockError::LockedByPeer);
        }

        let lock_path = self.get_lock_path(relative_path);
        fs::write(&lock_path, "")?; // Create an empty .lock file

        self.local_locks.insert(relative_path.to_path_buf());
        log::info!("Acquired local lock for: {:?}", relative_path);

        Ok(GossipMessage::LockStateChanged {
            path: relative_path.to_string_lossy().to_string(),
            state: LockState::Acquired,
        })
    }

    /// Releases a lock on a file.
    /// Removes the .lock file.
    pub fn release_lock(&mut self, relative_path: &Path) -> Result<GossipMessage, LockError> {
        if !self.is_locked_locally(relative_path) {
            return Err(LockError::NotLocked);
        }

        let lock_path = self.get_lock_path(relative_path);
        fs::remove_file(&lock_path)?;

        self.local_locks.remove(relative_path);
        log::info!("Released local lock for: {:?}", relative_path);

        Ok(GossipMessage::LockStateChanged {
            path: relative_path.to_string_lossy().to_string(),
            state: LockState::Released,
        })
    }

    /// Handles an incoming lock state change from a peer.
    pub fn handle_peer_lock_state(
        &mut self,
        path_str: &str,
        state: &LockState,
    ) {
        let path = PathBuf::from(path_str);
        match state {
            LockState::Acquired => {
                log::info!("Peer acquired lock for: {:?}", path);
                self.peer_locks.insert(path);
            }
            LockState::Released => {
                log::info!("Peer released lock for: {:?}", path);
                self.peer_locks.remove(&path);
            }
        }
    }

    /// Checks if a file is locked by anyone (local or peer).
    pub fn is_locked(&self, relative_path: &Path) -> bool {
        self.is_locked_locally(relative_path) || self.is_locked_by_peer(relative_path)
    }

    /// Checks if a file is locked by a remote peer.
    pub fn is_locked_by_peer(&self, relative_path: &Path) -> bool {
        self.peer_locks.contains(relative_path)
    }

    /// Checks if a file is locked by the local user.
    pub fn is_locked_locally(&self, relative_path: &Path) -> bool {
        self.local_locks.contains(relative_path)
    }

    /// Constructs the full path for a .lock file.
    fn get_lock_path(&self, relative_path: &Path) -> PathBuf {
        self.sync_dir.join(relative_path).with_extension(
            relative_path
                .extension()
                .map(|s| s.to_str().unwrap_or(""))
                .unwrap_or("")
                .to_owned()
                + ".lock",
        )
    }

    /// Returns a clone of the set of locally locked files.
    pub fn get_local_locks(&self) -> HashSet<PathBuf> {
        self.local_locks.clone()
    }

    /// Scans the sync directory on startup to clean up any stale .lock files.
    pub fn cleanup_stale_locks(&mut self) -> std::io::Result<()> {
        log::info!("Cleaning up stale .lock files...");
        for entry in fs::read_dir(&self.sync_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |s| s == "lock") {
                log::warn!("Found stale lock file, removing: {:?}", path);
                fs::remove_file(path)?;
            }
        }
        self.local_locks.clear();
        Ok(())
    }
}
