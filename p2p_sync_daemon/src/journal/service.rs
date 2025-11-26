use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

pub const JOURNAL_INTERVAL: Duration = Duration::from_secs(15);
const JOURNAL_FILENAME: &str = "journal.log";
const SYNC_DIR_INTERNAL: &str = ".sync";

#[derive(Error, Debug)]
pub enum JournalError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize, Debug)]
struct JournalEntry {
    in_use_paths: HashSet<PathBuf>,
}

/// Manages the crash recovery journal.
pub struct JournalService {
    journal_path: PathBuf,
}

impl JournalService {
    /// Creates a new JournalService.
    /// It ensures the `.sync` directory exists within the sync_dir.
    pub fn new(sync_dir: &Path) -> Result<Self, JournalError> {
        let internal_dir = sync_dir.join(SYNC_DIR_INTERNAL);
        fs::create_dir_all(&internal_dir)?;
        let journal_path = internal_dir.join(JOURNAL_FILENAME);
        Ok(Self { journal_path })
    }

    /// Logs the set of currently active/locked files to the journal.
    /// This method overwrites the journal file, treating it as a state snapshot.
    pub fn log_activity(&self, in_use_paths: &HashSet<PathBuf>) -> Result<(), JournalError> {
        let entry = JournalEntry {
            in_use_paths: in_use_paths.clone(),
        };

        // Write atomically by first writing to a temporary file.
        let temp_path = self.journal_path.with_extension("log.tmp");
        let file = File::create(&temp_path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &entry)?;
        writer.flush()?;

        // Rename the temporary file to the final journal file.
        fs::rename(&temp_path, &self.journal_path)?;
        Ok(())
    }

    /// Checks for a journal file on startup.
    /// The presence of the file indicates an abnormal shutdown.
    /// Returns the set of files that were in use and need recovery checks.
    pub fn check_for_recovery(&self) -> Result<HashSet<PathBuf>, JournalError> {
        if !self.journal_path.exists() {
            // No journal file, clean shutdown last time.
            return Ok(HashSet::new());
        }

        log::warn!("Journal file found - previous shutdown was abnormal.");
        let file = File::open(&self.journal_path)?;
        let reader = BufReader::new(file);
        let entry: JournalEntry = serde_json::from_reader(reader)?;

        log::info!(
            "Files needing recovery check: {:?}",
            entry.in_use_paths
        );
        Ok(entry.in_use_paths)
    }

    /// Clears the journal file. This should be called on a clean shutdown.
    pub fn clear(&self) -> Result<(), JournalError> {
        if self.journal_path.exists() {
            fs::remove_file(&self.journal_path)?;
            log::info!("Clean shutdown: Journal file cleared.");
        }
        Ok(())
    }
}
