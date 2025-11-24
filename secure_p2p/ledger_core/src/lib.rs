use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use chrono::{DateTime, Utc};
use std::fs::OpenOptions;
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Bincode serialization/deserialization error: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
}

/// Defines the roles a peer can have.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Reader,
    Contributor,
    Admin,
}

/// Defines the type of event being logged.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum EventType {
    ConnectionEstablished,
    ConnectionLost,
    HeartbeatReceived,
    FileLockRequested { file_path: String },
    LockGranted { file_path: String },
    LockDenied { file_path: String },
    LeaseExpired { file_path: String },
    FileUpdated {
        file_hash: Vec<u8>,
        previous_manifest_hash: Option<Vec<u8>>,
    },
    RoleUpdate {
        target_peer_id: Vec<u8>,
        new_role: Role,
    },
}

/// A separate struct containing only the fields to be hashed.
/// This makes the hashing process more robust and less error-prone.
#[derive(Serialize)]
struct HashableContent<'a> {
    timestamp: &'a DateTime<Utc>,
    peer_id: &'a Vec<u8>,
    event_type: &'a EventType,
    payload: &'a Vec<u8>,
    prev_hash: &'a Vec<u8>,
}

/// Represents a single entry in the immutable ledger.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub peer_id: Vec<u8>,
    pub event_type: EventType,
    pub payload: Vec<u8>,
    pub prev_hash: Vec<u8>,
    pub self_hash: Vec<u8>,
}

impl LogEntry {
    /// Creates a new LogEntry, calculating its own hash.
    pub fn new(
        peer_id: Vec<u8>,
        event_type: EventType,
        payload: Vec<u8>,
        prev_hash: Vec<u8>,
    ) -> Result<Self, LedgerError> {
        let timestamp = Utc::now();
        let mut entry = Self {
            timestamp,
            peer_id,
            event_type,
            payload,
            prev_hash,
            self_hash: vec![], // Placeholder
        };
        entry.self_hash = entry.calculate_hash()?;
        Ok(entry)
    }

    /// Calculates the SHA-256 hash of the entry's core fields.
    pub fn calculate_hash(&self) -> Result<Vec<u8>, LedgerError> {
        let hashable_content = HashableContent {
            timestamp: &self.timestamp,
            peer_id: &self.peer_id,
            event_type: &self.event_type,
            payload: &self.payload,
            prev_hash: &self.prev_hash,
        };

        let serialized_content = bincode::serialize(&hashable_content)?;
        let mut hasher = Sha256::new();
        hasher.update(serialized_content);
        Ok(hasher.finalize().to_vec())
    }
}

/// Represents the immutable, chained log of events.
pub struct Ledger {
    pub entries: Vec<LogEntry>,
    path: PathBuf,
}

impl Ledger {
    /// Loads a ledger from a file, or creates a new one if it doesn't exist.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, LedgerError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;

        let mut reader = BufReader::new(file);
        let mut entries = Vec::new();

        while let Ok(entry) = bincode::deserialize_from::<_, LogEntry>(&mut reader) {
            entries.push(entry);
        }

        if entries.is_empty() {
            let genesis_entry = LogEntry::new(
                vec![],
                EventType::ConnectionEstablished,
                b"Genesis".to_vec(),
                vec![0; 32],
            )?;
            entries.push(genesis_entry);

            let mut writer = BufWriter::new(
                OpenOptions::new().write(true).open(&path)?
            );
            bincode::serialize_into(&mut writer, &entries[0])?;
        }

        Ok(Self { entries, path })
    }

    /// Retrieves the hash of the most recent entry in the ledger.
    pub fn get_last_hash(&self) -> Vec<u8> {
        self.entries
            .last()
            .map(|e| e.self_hash.clone())
            .unwrap_or_else(|| vec![0; 32])
    }

    /// Appends a new entry to the ledger and persists it to the file.
    pub fn append_entry(&mut self, peer_id: Vec<u8>, event_type: EventType, payload: Vec<u8>) -> Result<(), LedgerError> {
        let prev_hash = self.get_last_hash();
        let new_entry = LogEntry::new(peer_id, event_type, payload, prev_hash)?;

        let file = OpenOptions::new().append(true).open(&self.path)?;
        let mut writer = BufWriter::new(file);
        bincode::serialize_into(&mut writer, &new_entry)?;

        self.entries.push(new_entry);
        Ok(())
    }

    /// Verifies the integrity of the entire ledger chain.
    pub fn verify_integrity(&self) -> bool {
        if self.entries.is_empty() {
            return true;
        }

        if self.entries[0].prev_hash != vec![0; 32] {
            return false;
        }
        if let Ok(hash) = self.entries[0].calculate_hash() {
            if self.entries[0].self_hash != hash {
                return false;
            }
        } else {
            return false;
        }

        for i in 1..self.entries.len() {
            let prev_entry = &self.entries[i - 1];
            let current_entry = &self.entries[i];

            if current_entry.prev_hash != prev_entry.self_hash {
                return false;
            }
            if let Ok(hash) = current_entry.calculate_hash() {
                if current_entry.self_hash != hash {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn ledger_chaining_is_correct() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        let mut ledger = Ledger::load(path).unwrap();

        let peer1 = b"peer1".to_vec();
        let peer2 = b"peer2".to_vec();

        ledger.append_entry(peer1.clone(), EventType::ConnectionEstablished, vec![]).unwrap();
        ledger.append_entry(peer2.clone(), EventType::HeartbeatReceived, b"ping".to_vec()).unwrap();

        assert!(ledger.verify_integrity());
    }

    #[test]
    fn ledger_persistence_and_loading_works() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let mut ledger = Ledger::load(path).unwrap();
        assert_eq!(ledger.entries.len(), 1);
        assert!(ledger.verify_integrity());

        let peer1 = b"peer1".to_vec();
        ledger.append_entry(peer1.clone(), EventType::FileLockRequested { file_path: "file1.txt".to_string() }, vec![]).unwrap();
        ledger.append_entry(peer1, EventType::ConnectionLost, vec![]).unwrap();

        assert_eq!(ledger.entries.len(), 3);
        let last_hash = ledger.get_last_hash();

        let reloaded_ledger = Ledger::load(path).unwrap();
        assert_eq!(reloaded_ledger.entries.len(), 3);
        assert_eq!(reloaded_ledger.get_last_hash(), last_hash);
        assert!(reloaded_ledger.verify_integrity());
    }

    #[test]
    fn ledger_integrity_check_fails_on_tampering() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let mut ledger = Ledger::load(path).unwrap();
        ledger.append_entry(b"peer1".to_vec(), EventType::HeartbeatReceived, vec![]).unwrap();
        ledger.append_entry(b"peer2".to_vec(), EventType::HeartbeatReceived, vec![]).unwrap();

        // Tamper with the ledger data in memory
        ledger.entries[1].payload = b"tampered".to_vec();

        assert!(!ledger.verify_integrity());
    }
}
