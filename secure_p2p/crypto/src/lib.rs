use ed25519_dalek::{Signer, Signature, SigningKey, VerifyingKey, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use thiserror::Error;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng as ArgonOsRng, SaltString},
    Argon2,
};
use libp2p;
use rand::RngCore;
use sha2::{Digest, Sha256};

const CONFIG_DIR_NAME: &str = "secure_p2p";
const PUBLIC_KEY_FILE: &str = "peer_id.pub";
const SECRET_KEY_FILE: &str = "peer_id.priv";
const AEAD_KEY_LENGTH: usize = 32;

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

#[derive(Serialize, Deserialize)]
struct EncryptedKeyFile {
    ciphertext_hex: String,
    nonce_hex: String,
    salt_str: String,
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

pub fn save_keypair(keypair: &Keypair, passphrase: &str) -> Result<(), CryptoError> {
    let config_path = get_config_path()?;
    fs::create_dir_all(&config_path)?;

    let public_key_path = config_path.join(PUBLIC_KEY_FILE);
    fs::write(public_key_path, keypair.verifying_key.as_bytes())?;

    let salt = SaltString::generate(&mut ArgonOsRng);
    let argon2 = Argon2::default();
    let mut key_material = [0u8; AEAD_KEY_LENGTH];
    argon2.hash_password_into(passphrase.as_bytes(), salt.as_str().as_bytes(), &mut key_material)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    let key = Key::from_slice(&key_material);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, keypair.signing_key.as_bytes().as_ref()).map_err(|_| CryptoError::Aead)?;

    let encrypted_file = EncryptedKeyFile {
        ciphertext_hex: hex::encode(ciphertext),
        nonce_hex: hex::encode(nonce_bytes),
        salt_str: salt.to_string(),
    };
    let json_content = serde_json::to_string_pretty(&encrypted_file)?;

    let secret_key_path = config_path.join(SECRET_KEY_FILE);
    fs::write(secret_key_path, json_content)?;

    Ok(())
}

pub fn load_keypair(passphrase: &str) -> Result<Keypair, CryptoError> {
    let config_path = get_config_path()?;

    let public_key_path = config_path.join(PUBLIC_KEY_FILE);
    let public_key_bytes: [u8; 32] = fs::read(public_key_path)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength("Invalid public key length".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;

    let secret_key_path = config_path.join(SECRET_KEY_FILE);
    let json_content = fs::read_to_string(secret_key_path)?;
    let encrypted_file: EncryptedKeyFile = serde_json::from_str(&json_content)?;

    let salt = SaltString::from_b64(&encrypted_file.salt_str)
         .map_err(|e| CryptoError::PasswordHash(e.to_string()))?;
    let argon2 = Argon2::default();
    let mut key_material = [0u8; AEAD_KEY_LENGTH];
    argon2.hash_password_into(passphrase.as_bytes(), salt.as_str().as_bytes(), &mut key_material)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    let key = Key::from_slice(&key_material);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_bytes = hex::decode(&encrypted_file.nonce_hex)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = hex::decode(&encrypted_file.ciphertext_hex)?;
    let secret_key_bytes = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| CryptoError::Aead)?;

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
