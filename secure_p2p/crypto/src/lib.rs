use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
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
    PasswordHash(String), // Wraps non-std::Error
    #[error("Argon2 error: {0}")]
    Argon2(String),
    #[error("AEAD encryption/decryption error")]
    Aead, // Wraps non-std::Error
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

    // 1. Save public key
    let public_key_path = config_path.join(PUBLIC_KEY_FILE);
    fs::write(public_key_path, keypair.verifying_key.as_bytes())?;

    // 2. Derive encryption key from passphrase
    let salt = SaltString::generate(&mut ArgonOsRng);
    let argon2 = Argon2::default();
    let mut key_material = [0u8; AEAD_KEY_LENGTH];
    argon2.hash_password_into(passphrase.as_bytes(), salt.as_str().as_bytes(), &mut key_material)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    // 3. Encrypt the secret key with a random nonce
    let key = Key::from_slice(&key_material);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, keypair.signing_key.as_bytes().as_ref()).map_err(|_| CryptoError::Aead)?;

    // 4. Serialize encrypted data
    let encrypted_file = EncryptedKeyFile {
        ciphertext_hex: hex::encode(ciphertext),
        nonce_hex: hex::encode(nonce_bytes),
        salt_str: salt.to_string(),
    };
    let json_content = serde_json::to_string_pretty(&encrypted_file)?;

    // 5. Save encrypted secret key
    let secret_key_path = config_path.join(SECRET_KEY_FILE);
    fs::write(secret_key_path, json_content)?;

    Ok(())
}

pub fn load_keypair(passphrase: &str) -> Result<Keypair, CryptoError> {
    let config_path = get_config_path()?;

    // 1. Load public key
    let public_key_path = config_path.join(PUBLIC_KEY_FILE);
    let public_key_bytes: [u8; 32] = fs::read(public_key_path)?
        .try_into()
        .map_err(|_| CryptoError::InvalidLength("Invalid public key length".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)?;

    // 2. Load encrypted secret key file
    let secret_key_path = config_path.join(SECRET_KEY_FILE);
    let json_content = fs::read_to_string(secret_key_path)?;
    let encrypted_file: EncryptedKeyFile = serde_json::from_str(&json_content)?;

    // 3. Derive key from passphrase and salt
    let salt = SaltString::from_b64(&encrypted_file.salt_str)
         .map_err(|e| CryptoError::PasswordHash(e.to_string()))?;
    let argon2 = Argon2::default();
    let mut key_material = [0u8; AEAD_KEY_LENGTH];
    argon2.hash_password_into(passphrase.as_bytes(), salt.as_str().as_bytes(), &mut key_material)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    // 4. Decrypt the secret key
    let key = Key::from_slice(&key_material);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_bytes = hex::decode(&encrypted_file.nonce_hex)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = hex::decode(&encrypted_file.ciphertext_hex)?;
    let secret_key_bytes = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| CryptoError::Aead)?;

    // 5. Reconstruct the keypair
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
