use ledger_core::{Ledger, LogEntry, EventType, Role};
use std::collections::HashMap;
use crypto_core::{CryptoError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RoleRegistryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bincode error: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// The registry that holds the role of each peer.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct RoleRegistry {
    roles: HashMap<Vec<u8>, Role>,
}

impl RoleRegistry {
    /// Reconstructs the role registry by replaying the entire ledger.
    /// This is the authoritative way to build the role state.
    pub fn new_from_ledger(ledger: &Ledger) -> Self {
        let mut registry = RoleRegistry::default();
        for entry in &ledger.entries {
            registry.apply_entry(entry);
        }
        registry
    }

    /// Applies a single log entry to the registry.
    pub fn apply_entry(&mut self, entry: &LogEntry) {
        if let EventType::RoleUpdate { target_peer_id, new_role } = &entry.event_type {
            self.roles.insert(target_peer_id.clone(), new_role.clone());
        }
    }

    /// Gets the role for a given PeerId.
    pub fn get_role(&self, peer_id: &[u8]) -> Option<&Role> {
        self.roles.get(peer_id)
    }

    /// Returns an iterator over the roles.
    pub fn roles(&self) -> impl Iterator<Item = (&Vec<u8>, &Role)> {
        self.roles.iter()
    }

    /// A peer is considered an admin if they have the Admin role.
    pub fn is_admin(&self, peer_id: &[u8]) -> bool {
        self.get_role(peer_id) == Some(&Role::Admin)
    }

    /// Checks if there are any admins in the registry.
    pub fn has_admin(&self) -> bool {
        self.roles.values().any(|role| *role == Role::Admin)
    }

    /// Sets the role for a peer. This should only be used when initializing the first admin.
    pub fn set_initial_admin(&mut self, peer_id: Vec<u8>) {
        if !self.has_admin() {
            self.roles.insert(peer_id, Role::Admin);
        }
    }
}
