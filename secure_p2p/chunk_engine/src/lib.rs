use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::{Read, Seek, SeekFrom};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crypto::hash_stream;

const CHUNK_SIZE: usize = 1_048_576; // 1MB

#[derive(Debug, Error)]
pub enum ChunkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileManifest {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub chunk_hashes: Vec<Vec<u8>>,
    pub total_hash: Vec<u8>,
}

pub fn create_file_manifest(file_path: &Path) -> Result<FileManifest, ChunkError> {
    let mut file = File::open(file_path)?;
    let file_size = file.metadata()?.len();
    let total_hash = hash_stream(&mut file)?;
    file.seek(SeekFrom::Start(0))?;
    let mut chunk_hashes = Vec::new();
    let mut buffer = vec![0; CHUNK_SIZE];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        let chunk_hash = hash_stream(std::io::Cursor::new(&buffer[..bytes_read]))?;
        chunk_hashes.push(chunk_hash);
    }
    Ok(FileManifest { file_path: file_path.to_path_buf(), file_size, chunk_hashes, total_hash })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_create_file_manifest_correctness() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let file_size = (CHUNK_SIZE as f64 * 1.5) as usize;
        let data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();
        temp_file.write_all(&data).unwrap();

        let manifest = create_file_manifest(temp_file.path()).unwrap();

        assert_eq!(manifest.file_size, file_size as u64);
        assert_eq!(manifest.chunk_hashes.len(), 2);

        let total_hash = hash_stream(File::open(temp_file.path()).unwrap()).unwrap();
        assert_eq!(manifest.total_hash, total_hash);
    }
}
