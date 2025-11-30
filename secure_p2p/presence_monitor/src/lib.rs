use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PresenceState {
    pub peer_id: String,
    pub file_path: String,
    pub status: String, // "Editing", "Viewing"
    pub timestamp: u64,
}

pub struct PresenceMonitor {
    // Map<FilePath, Map<PeerId, State>>
    active_presences: Arc<Mutex<HashMap<String, HashMap<String, PresenceState>>>>,
}

impl PresenceMonitor {
    pub fn new() -> Self {
        Self {
            active_presences: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn update_presence(&self, peer_id: String, file_path: String, status: String) {
        let mut guard = self.active_presences.lock().unwrap();
        let file_presences = guard.entry(file_path.clone()).or_insert_with(HashMap::new);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        file_presences.insert(peer_id.clone(), PresenceState {
            peer_id,
            file_path,
            status,
            timestamp: now,
        });
    }

    pub fn get_active_presences(&self, file_path: &str) -> Vec<PresenceState> {
        let guard = self.active_presences.lock().unwrap();
        // First cleanup expired entries (e.g. older than 30s)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // We need to iterate and cleanup.
        // For simplicity in this step, we'll just filter on read.
        // A dedicated cleanup task should be run periodically.

        if let Some(map) = guard.get(file_path) {
            map.values()
                .filter(|p| now - p.timestamp < 30)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn cleanup_expired(&self) {
        let mut guard = self.active_presences.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        for presences in guard.values_mut() {
            presences.retain(|_, state| now - state.timestamp < 30);
        }
    }
}
