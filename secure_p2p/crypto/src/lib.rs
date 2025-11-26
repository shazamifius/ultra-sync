use ed25519_dalek::{Signer, Signature, SigningKey, VerifyingKey, Verifier};
use rand::rngs::OsRng;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use thiserror::Error;
#[cfg(windows)]
use windows_dpapi::Scope;
use libp2p;
use rand::RngCore;
use sha2::{Digest, Sha256};

const CONFIG_DIR_NAME: &str = "secure_p2p";
const PUBLIC_KEY_FILE: &str = "peer_id.pub";
const SECRET_KEY_FILE: &str = "peer_id.priv";

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Cryptography error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),
    #[error("Configuration directory not found")]
    ConfigDirNotFound,
    #[error("Password hashing error: {0}")]
    PasswordHash(String),
    #[error("Argon2 error: {0}")]
    Argon2(String),
    #[error("AEAD encryption/decryption error")]
    Aead,
    #[error("Invalid key or data length: {0}")]
    InvalidLength(String),
    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Libp2p identity error: {0}")]
    Libp2pIdentity(#[from] libp2p::identity::DecodingError),
    #[error("Passphrases do not match")]
    PassphraseMismatch,
}

pub struct Keypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Keypair {
    pub fn to_libp2p_keypair(&self) -> Result<libp2p::identity::Keypair, CryptoError> {
        let mut secret_bytes = self.signing_key.to_bytes();
        Ok(libp2p::identity::Keypair::ed25519_from_bytes(&mut secret_bytes)?)
    }
}


pub fn generate_keypair() -> Keypair {
    let mut csprng = OsRng;
    let mut secret_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_bytes);

    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    Keypair { signing_key, verifying_key }
}

fn get_config_path() -> Result<PathBuf, CryptoError> {
    dirs::config_dir()
        .map(|p| p.join(CONFIG_DIR_NAME))
        .ok_or(CryptoError::ConfigDirNotFound)
}

#[cfg(windows)]
pub fn save_keypair(keypair: &Keypair, _passphrase: &str) -> Result<(), CryptoError> {
    let config_path = get_config_path()?;
    fs::create_dir_all(&config_path)?;

    let public_key_path = config_path.join(PUBLIC_KEY_FILE);
    fs::write(public_key_path, keypair.verifying_key.as_bytes())?;

    let secret_key_bytes = keypair.signing_key.to_bytes();
    let encrypted_secret_key = windows_dpapi::encrypt_data(&secret_key_bytes, Scope::User)
        .map_err(|_| CryptoError::Aead)?; // Re-using Aead for simplicity

    let secret_key_path = config_path.join(SECRET_KEY_FILE);
    fs::write(secret_key_path, encrypted_secret_key)?;

    Ok(())
}

#[cfg(windows)]
pub fn load_keypair(_passphrase: &str) -> Result<Keypair, CryptoError> {
    let config_path = get_config_path()?;

    let public_key_path = config_path.join(PUBLIC_KEY_FILE);
    let public_key_bytes: [u8; 32] = fs::read(public_key_path)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength("Invalid public key length".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;

    let secret_key_path = config_path.join(SECRET_KEY_FILE);
    let encrypted_secret_key = fs::read(secret_key_path)?;
    let secret_key_bytes = windows_dpapi::decrypt_data(&encrypted_secret_key, Scope::User)
        .map_err(|_| CryptoError::Aead)?; // Re-using Aead for simplicity

    let signing_key = SigningKey::from_bytes(
        &secret_key_bytes.try_into().map_err(|_| CryptoError::InvalidLength("Invalid secret key length".to_string()))?
    );

    Ok(Keypair { signing_key, verifying_key })
}

#[cfg(not(windows))]
pub fn save_keypair(keypair: &Keypair, _passphrase: &str) -> Result<(), CryptoError> {
    let config_path = get_config_path()?;
    fs::create_dir_all(&config_path)?;

    let public_key_path = config_path.join(PUBLIC_KEY_FILE);
    fs::write(public_key_path, keypair.verifying_key.as_bytes())?;

    let secret_key_path = config_path.join(SECRET_KEY_FILE);
    fs::write(secret_key_path, keypair.signing_key.as_bytes())?;

    Ok(())
}

#[cfg(not(windows))]
pub fn load_keypair(_passphrase: &str) -> Result<Keypair, CryptoError> {
    let config_path = get_config_path()?;

    let public_key_path = config_path.join(PUBLIC_KEY_FILE);
    let public_key_bytes: [u8; 32] = fs::read(public_key_path)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength("Invalid public key length".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;

    let secret_key_path = config_path.join(SECRET_KEY_FILE);
    let secret_key_bytes = fs::read(secret_key_path)?;
    let signing_key = SigningKey::from_bytes(
        &secret_key_bytes.try_into().map_err(|_| CryptoError::InvalidLength("Invalid secret key length".to_string()))?
    );

    Ok(Keypair { signing_key, verifying_key })
}

pub fn keypair_exists() -> bool {
    if let Ok(config_path) = get_config_path() {
        config_path.join(PUBLIC_KEY_FILE).exists() &&
        config_path.join(SECRET_KEY_FILE).exists()
    } else {
        false
    }
}

// --- New Functionality ---

/// Signs arbitrary data using the provided signing key.
pub fn sign_data(data: &[u8], signing_key: &SigningKey) -> Signature {
    signing_key.sign(data)
}

/// Verifies the signature of data using the provided verifying key.
pub fn verify_signature(data: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> bool {
    verifying_key.verify(data, signature).is_ok()
}

/// Hashes a data stream using SHA-256.
/// This is efficient for large files as it reads them in chunks.
pub fn hash_stream<R: Read>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192]; // 8KB chunks

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().to_vec())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Seek, SeekFrom, Write};
    use tempfile::NamedTempFile;

    #[test]
    fn test_sign_and_verify() {
        let keypair = generate_keypair();
        let data = b"this is a test message";

        // Test valid signature
        let signature = sign_data(data, &keypair.signing_key);
        assert!(verify_signature(data, &signature, &keypair.verifying_key));

        // Test invalid signature
        let wrong_data = b"this is not the original message";
        assert!(!verify_signature(wrong_data, &signature, &keypair.verifying_key));

        // Test signature with a different key
        let another_keypair = generate_keypair();
        assert!(!verify_signature(data, &signature, &another_keypair.verifying_key));
    }

    #[test]
    fn test_hash_stream() {
        let content = b"hello world";
        let cursor = Cursor::new(content);

        let hash = hash_stream(cursor).unwrap();

        // Pre-computed SHA-256 hash of "hello world"
        let expected_hash_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(hex::encode(hash), expected_hash_hex);
    }

    #[test]
    fn test_hash_large_stream() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let large_data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        temp_file.write_all(&large_data).unwrap();

        // Rewind the file cursor to the beginning
        temp_file.seek(SeekFrom::Start(0)).unwrap();

        // Hash from file
        let file_hash = hash_stream(temp_file.as_file()).unwrap();

        // Hash from memory
        let memory_hash = hash_stream(Cursor::new(&large_data)).unwrap();

        assert_eq!(file_hash, memory_hash);

        // Also hash the data directly to ensure correctness
        let mut hasher = Sha256::new();
        hasher.update(&large_data);
        let direct_hash = hasher.finalize().to_vec();
        assert_eq!(file_hash, direct_hash);
    }
}
