use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BLOCK_SIZE: usize = 1024 * 1024; // 1MB blocks

/// Represents a single block of a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInfo {
    pub index: u64,
    pub hash: String, // hex-encoded SHA-256 hash
}

/// Represents the complete state of a file.
/// This is what gets gossiped around the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileManifest {
    pub path: String,
    pub modified_ts: u64, // Unix timestamp
    pub total_size: u64,
    pub blocks: Vec<BlockInfo>,
}

impl FileManifest {
    /// Creates a new manifest from file content.
    pub fn from_bytes(path: String, content: &[u8], modified_ts: u64) -> Self {
        let total_size = content.len() as u64;
        let blocks = content
            .chunks(BLOCK_SIZE)
            .enumerate()
            .map(|(i, chunk)| {
                let mut hasher = Sha256::new();
                hasher.update(chunk);
                let hash = hex::encode(hasher.finalize());
                BlockInfo {
                    index: i as u64,
                    hash,
                }
            })
            .collect();

        FileManifest {
            path,
            modified_ts,
            total_size,
            blocks,
        }
    }
}

/// Represents the state of a file lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockState {
    Acquired,
    Released,
}

/// Top-level message enum for all gossip communication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipMessage {
    ManifestUpdated(FileManifest),
    LockStateChanged { path: String, state: LockState },
}

// --- Request-Response Protocol Definitions ---

/// A request to a peer for a specific block of a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRequest {
    pub path: String,
    pub block_index: u64,
}

/// The response containing the raw data of the requested block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockResponse {
    pub data: Vec<u8>,
}
