use ledger_core::Ledger;
use chunk_engine::create_file_manifest;
use std::path::Path;
use log::{info, error};

pub struct CrashRecovery;

impl CrashRecovery {
    pub fn recover(
        watched_dir: &Path,
        ledger: &Ledger,
    ) {
        info!("Starting crash recovery / state reconciliation...");

        // 1. Replay Ledger to build "Expected State"
        // (In a real system, we'd build a Map<Path, Hash> from the ledger events)
        let expected_state = Self::build_expected_state(ledger);

        // 2. Scan disk to build "Actual State"
        // For simplicity, we just iterate the expected state and check if files exist and match hashes.

        for (file_path, expected_hash) in expected_state {
             let full_path = watched_dir.join(&file_path);

             if !full_path.exists() {
                 info!("RECOVERY: File missing on disk: {:?}. Marking for re-download.", file_path);
                 // In a full implementation, we would queue a download request here.
                 continue;
             }

             match create_file_manifest(&full_path) {
                 Ok(manifest) => {
                     if manifest.total_hash != expected_hash {
                          info!("RECOVERY: Hash mismatch for {:?}. Local file is corrupted or modified offline. Marking for re-sync.", file_path);
                     } else {
                          // info!("RECOVERY: File verified: {:?}", file_path);
                     }
                 },
                 Err(e) => {
                     error!("RECOVERY: Failed to read file {:?}: {}", full_path, e);
                 }
             }
        }

        info!("Crash recovery check complete.");
    }

    fn build_expected_state(ledger: &Ledger) -> std::collections::HashMap<String, Vec<u8>> {
        let state = std::collections::HashMap::new();

        for entry in &ledger.entries {
            match &entry.event_type {
                ledger_core::EventType::FileUpdated {  .. } => {
                     // Warning: In the current Ledger event, we didn't store the file path inside the event explicitly
                     // in the simplified code above (it was in the payload or implied).
                     // This highlights a need to ensure path is in the event for proper recovery.
                     // For now, assuming we can't fully reconstruct without path.
                     // A robust implementation would store (Path, Hash) in the EventType.
                },
                _ => {}
            }
        }
        state
    }
}
