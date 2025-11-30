use ledger_core::Ledger;
use std::path::{Path, PathBuf};
use std::io;
use log::info;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConflictError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid path")]
    InvalidPath,
}

pub enum ResolutionAction {
    ApplyUpdate,
    CreateConflictCopy { new_path: PathBuf },
    Ignore, // If we already have the exact same file content
}

pub struct ConflictSolver;

impl ConflictSolver {
    pub fn resolve(
        local_file_path: &Path,
        _incoming_hash: &[u8],
        incoming_prev_hash: Option<&[u8]>,
        ledger: &Ledger,
    ) -> Result<ResolutionAction, ConflictError> {

        // 1. If file doesn't exist locally, apply update
        if !local_file_path.exists() {
            return Ok(ResolutionAction::ApplyUpdate);
        }

        // 2. Check Ledger for the last known state of this file
        // In a real implementation, we'd query the ledger for the authoritative tip.
        // For this simplified logic:

        let last_update_hash = ledger.entries.iter().rev()
            .find_map(|e| match &e.event_type {
                 ledger_core::EventType::FileUpdated { file_hash, .. } => Some(file_hash.clone()),
                 _ => None,
            });

        // If incoming update builds on top of what we think is the latest, it's good.
        if let Some(prev) = incoming_prev_hash {
             if let Some(local_tip) = last_update_hash {
                 if prev == &local_tip {
                     return Ok(ResolutionAction::ApplyUpdate);
                 }
             }
        }

        // 3. Conflict Detected: The incoming update is not based on our current tip.
        // Or our local file has changed since the last ledger update (Dirty local state).

        // We default to "Keep both" (Conflict Copy)
        let file_stem = local_file_path.file_stem().ok_or(ConflictError::InvalidPath)?.to_string_lossy();
        let extension = local_file_path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();

        // Naming convention: filename (Conflict PeerID - Timestamp).ext
        // Simplified for this step: filename (Conflict).ext
        let new_name = if extension.is_empty() {
            format!("{} (Conflict)", file_stem)
        } else {
            format!("{} (Conflict).{}", file_stem, extension)
        };

        let new_path = local_file_path.with_file_name(new_name);

        info!("Conflict detected for {:?}. Renaming incoming to {:?}", local_file_path, new_path);

        Ok(ResolutionAction::CreateConflictCopy { new_path })
    }
}
