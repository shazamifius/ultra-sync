use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::{Read, Seek, SeekFrom, Write};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crypto::hash_stream;

const CHUNK_SIZE: usize = 1_048_576; // 1MB

#[derive(Debug, Error)]
pub enum ChunkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Manifest error: {0}")]
    Manifest(String),
    #[error("Compression error: {0}")]
    Compression(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileManifest {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub chunk_hashes: Vec<Vec<u8>>,
    pub total_hash: Vec<u8>,
}

/// Compress data using LZ4
pub fn compress_chunk(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress data using LZ4
pub fn decompress_chunk(data: &[u8]) -> Result<Vec<u8>, ChunkError> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| ChunkError::Compression(e.to_string()))
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

        // Hash is calculated on the ORIGINAL data, not compressed
        let chunk_hash = hash_stream(std::io::Cursor::new(&buffer[..bytes_read]))?;
        chunk_hashes.push(chunk_hash);
    }
    Ok(FileManifest { file_path: file_path.to_path_buf(), file_size, chunk_hashes, total_hash })
}

pub fn reconstruct_file(output_path: &Path, chunks: Vec<Vec<u8>>, manifest: &FileManifest) -> Result<(), ChunkError> {
    if chunks.len() != manifest.chunk_hashes.len() {
        return Err(ChunkError::Manifest(format!(
            "Chunk count mismatch: expected {}, got {}",
            manifest.chunk_hashes.len(),
            chunks.len()
        )));
    }

    // Write to a temporary file first to ensure atomicity
    let temp_path = output_path.with_extension("tmp");
    let mut file = File::create(&temp_path)?;

    for (i, chunk_data) in chunks.iter().enumerate() {
        let calculated_hash = hash_stream(std::io::Cursor::new(chunk_data))?;
        if calculated_hash != manifest.chunk_hashes[i] {
            // Clean up temp file
            let _ = std::fs::remove_file(&temp_path);
            return Err(ChunkError::Manifest(format!("Hash mismatch for chunk {}", i)));
        }
        file.write_all(chunk_data)?;
    }

    // Verify total hash
    file.sync_all()?;
    let mut file_read = File::open(&temp_path)?;
    let total_hash = hash_stream(&mut file_read)?;

    if total_hash != manifest.total_hash {
        let _ = std::fs::remove_file(&temp_path);
        return Err(ChunkError::Manifest("Total file hash mismatch after reconstruction".to_string()));
    }

    // Rename temp file to final destination
    // If output path exists, we must remove it first to support Windows
    if output_path.exists() {
        std::fs::remove_file(output_path)?;
    }
    std::fs::rename(temp_path, output_path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compression_decompression() {
        let data = b"Hello world, this is a test for compression. Hello world.";
        let compressed = compress_chunk(data);
        assert!(compressed.len() > 0);
        let decompressed = decompress_chunk(&compressed).unwrap();
        assert_eq!(data.to_vec(), decompressed);
    }

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

    #[test]
    fn test_reconstruct_file() {
        let mut source_file = NamedTempFile::new().unwrap();
        let file_size = (CHUNK_SIZE as f64 * 0.5) as usize; // Small file
        let data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();
        source_file.write_all(&data).unwrap();

        let manifest = create_file_manifest(source_file.path()).unwrap();
        let chunks = vec![data.clone()];

        let output_dir = tempfile::tempdir().unwrap();
        let output_path = output_dir.path().join("reconstructed.bin");

        reconstruct_file(&output_path, chunks, &manifest).unwrap();

        let mut reconstructed_file = File::open(output_path).unwrap();
        let mut reconstructed_data = Vec::new();
        reconstructed_file.read_to_end(&mut reconstructed_data).unwrap();

        assert_eq!(data, reconstructed_data);
    }
}
