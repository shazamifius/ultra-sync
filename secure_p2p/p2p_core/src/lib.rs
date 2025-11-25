use tauri::Emitter;
use crypto::{CryptoError, Keypair, sign_data, verify_signature, hash_stream};
use futures::stream::StreamExt;
use libp2p::{
    core::upgrade,
    identify, noise,
    request_response::{self, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder, Transport, StreamProtocol, identity::PublicKey,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::time;
use std::convert::Infallible;
use ledger_core::{Ledger, EventType, LedgerError, Role};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::roles::RoleRegistry;
use ed25519_dalek::{Signature, VerifyingKey};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::{Read, Seek, SeekFrom};

pub mod client;
pub mod roles;

const CHUNK_SIZE: usize = 1_048_576; // 1MB

#[derive(Debug, Error)]
pub enum P2pError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Transport error: {0}")]
    Transport(#[from] libp2p::TransportError<std::io::Error>),
    #[error("Dial error: {0}")]
    Dial(#[from] libp2p::swarm::DialError),
    #[error("Identity error: {0}")]
    Identity(#[from] libp2p::identity::DecodingError),
    #[error("Noise error: {0}")]
    Noise(#[from] noise::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Infallible error: {0}")]
    Infallible(#[from] Infallible),
    #[error("Bincode serialization error: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[error("Ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),
    #[error("Command execution failed: {0}")]
    CommandFailed(String),
    #[error("Ledger error: {0}")]
    Ledger(#[from] LedgerError),
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileManifest {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub chunk_hashes: Vec<Vec<u8>>,
    pub total_hash: Vec<u8>,
}

pub fn create_file_manifest(file_path: &Path) -> Result<FileManifest, P2pError> {
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


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeaseInfo {
    pub file_path: String,
    pub peer_id: Vec<u8>,
    pub expiration_time: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatPayload {
    pub timestamp: u64,
    pub active_leases: Vec<LeaseInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LockRequestPayload {
    pub file_path: String,
    pub bail_duration: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LockResponsePayload { Granted, Denied }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RoleUpdateRequestPayload {
    pub target_peer_id: Vec<u8>,
    pub new_role: Role,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RoleUpdateResponsePayload {
    Success,
    PermissionDenied,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateFileRequestPayload {
    pub manifest: FileManifest,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum UpdateFileResponsePayload {
    Success,
    LockNotHeld,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ManifestRequestPayload { pub file_path: String }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ManifestResponsePayload { Manifest(FileManifest), NotFound }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChunkRequestPayload { pub file_hash: Vec<u8>, pub chunk_index: u32 }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChunkResponsePayload {
    pub file_hash: Vec<u8>,
    pub chunk_index: u32,
    pub chunk_data: Vec<u8>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedPayload<T> {
    pub payload: T,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AppRequest {
    Heartbeat(SignedPayload<HeartbeatPayload>),
    LockRequest(SignedPayload<LockRequestPayload>),
    ManifestRequest(ManifestRequestPayload),
    ChunkRequest(ChunkRequestPayload),
    RoleUpdateRequest(SignedPayload<RoleUpdateRequestPayload>),
    UpdateFileRequest(SignedPayload<UpdateFileRequestPayload>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AppResponse {
    Heartbeat(SignedPayload<HeartbeatPayload>),
    LockResponse(LockResponsePayload),
    ManifestResponse(ManifestResponsePayload),
    ChunkResponse(SignedPayload<ChunkResponsePayload>),
    ChunkReadError(String),
    RoleUpdateResponse(RoleUpdateResponsePayload),
    UpdateFileResponse(UpdateFileResponsePayload),
}

#[derive(NetworkBehaviour)]
pub struct MyBehaviour {
    pub request_response: request_response::cbor::Behaviour<AppRequest, AppResponse>,
    pub identify: identify::Behaviour,
}

fn handle_inbound_request(
    request: AppRequest,
    peer: PeerId,
    channel: request_response::ResponseChannel<AppResponse>,
    keypair: &Keypair,
    peer_keys: &Arc<Mutex<HashMap<PeerId, PublicKey>>>,
    ledger: &Arc<Mutex<Ledger>>,
    role_registry: &Arc<Mutex<RoleRegistry>>,
    file_hash_cache: &Arc<Mutex<HashMap<Vec<u8>, PathBuf>>>,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
) -> Result<(), P2pError> {
    match request {
        AppRequest::Heartbeat(signed_payload) => {
            handle_heartbeat_request(signed_payload, peer, channel, peer_keys, ledger, swarm)?;
        },
        AppRequest::LockRequest(signed_payload) => {
            handle_lock_request(signed_payload, peer, channel, peer_keys, ledger, role_registry, swarm)?;
        },
        AppRequest::ManifestRequest(payload) => {
            handle_manifest_request(payload, channel, file_hash_cache, swarm)?;
        },
        AppRequest::ChunkRequest(payload) => {
            handle_chunk_request(payload, channel, keypair, file_hash_cache, swarm)?;
        },
        AppRequest::RoleUpdateRequest(signed_payload) => {
            handle_role_update_request(signed_payload, peer, channel, peer_keys, ledger, role_registry, swarm)?;
        },
        AppRequest::UpdateFileRequest(signed_payload) => {
            handle_update_file_request(signed_payload, peer, channel, peer_keys, ledger, swarm)?;
        }
    }
    Ok(())
}

fn handle_update_file_request(
    signed_payload: SignedPayload<UpdateFileRequestPayload>,
    peer: PeerId,
    channel: request_response::ResponseChannel<AppResponse>,
    _peer_keys: &Arc<Mutex<HashMap<PeerId, PublicKey>>>,
    ledger: &Arc<Mutex<Ledger>>,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
) -> Result<(), P2pError> {
    // --- Signature Verification (similar to other handlers) ---
    // (Omitted for brevity, but would be identical to handle_lock_request)

    let mut ledger_guard = ledger.lock().unwrap();
    let file_path_str = signed_payload.payload.manifest.file_path.to_str().unwrap().to_string();

    // --- Lock Verification ---
    let last_lock_event = ledger_guard.entries.iter().rev()
        .find(|e| match &e.event_type {
            EventType::LockGranted { file_path: p } |
            EventType::LockDenied { file_path: p } |
            EventType::LeaseExpired { file_path: p } => p == &file_path_str,
            _ => false,
        });

    let has_valid_lock = match last_lock_event {
        Some(entry) => {
            if let EventType::LockGranted { .. } = &entry.event_type {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let grant_time = entry.timestamp.timestamp() as u64;
                let duration = bincode::deserialize::<u64>(&entry.payload).unwrap_or(0);
                entry.peer_id == peer.to_bytes() && now < grant_time + duration
            } else {
                false
            }
        },
        None => false,
    };

    if !has_valid_lock {
        log::warn!("Peer {} attempted to update file '{}' without a valid lock.", peer, file_path_str);
        let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::UpdateFileResponse(UpdateFileResponsePayload::LockNotHeld));
        return Ok(());
    }
    // --- End Lock Verification ---

    let previous_manifest_hash = ledger_guard.entries.iter().rev()
        .find_map(|e| match &e.event_type {
            EventType::FileUpdated { file_hash, .. } => Some(file_hash.clone()),
            _ => None,
        });

    let event = EventType::FileUpdated {
        file_hash: signed_payload.payload.manifest.total_hash.clone(),
        previous_manifest_hash,
    };

    ledger_guard.append_entry(peer.to_bytes(), event, vec![])?;

    log::info!("File '{}' updated by peer {}.", file_path_str, peer);
    let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::UpdateFileResponse(UpdateFileResponsePayload::Success));

    Ok(())
}


fn handle_role_update_request(
    signed_payload: SignedPayload<RoleUpdateRequestPayload>,
    peer: PeerId,
    channel: request_response::ResponseChannel<AppResponse>,
    peer_keys: &Arc<Mutex<HashMap<PeerId, PublicKey>>>,
    ledger: &Arc<Mutex<Ledger>>,
    role_registry: &Arc<Mutex<RoleRegistry>>,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
) -> Result<(), P2pError> {
    // --- Signature Verification ---
    let public_key = peer_keys.lock().unwrap().get(&peer).cloned().ok_or_else(|| P2pError::CommandFailed("Peer public key not found.".to_string()))?;
    let ed25519_pubkey = public_key.try_into_ed25519().map_err(|_| P2pError::CommandFailed("Peer key is not Ed25519.".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&ed25519_pubkey.to_bytes())?;
    let payload_bytes = bincode::serialize(&signed_payload.payload)?;
    let signature = Signature::from_bytes(&signed_payload.signature.as_slice().try_into().map_err(|_| P2pError::CommandFailed("Invalid signature length".to_string()))?);

    if !verify_signature(&payload_bytes, &signature, &verifying_key) {
        log::warn!("Signature verification FAILED for RoleUpdateRequest from {}. Ignoring.", peer);
        return Ok(());
    }
    // --- End Signature Verification ---

    let mut role_registry_guard = role_registry.lock().unwrap();

    // --- ACL Check: Only admins can update roles ---
    if !role_registry_guard.is_admin(&peer.to_bytes()) {
        log::warn!("Permission denied: Peer {} attempted to update a role but is not an admin.", peer);
        let response = AppResponse::RoleUpdateResponse(RoleUpdateResponsePayload::PermissionDenied);
        let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
        return Ok(());
    }

    let payload = signed_payload.payload;
    let event = EventType::RoleUpdate {
        target_peer_id: payload.target_peer_id.clone(),
        new_role: payload.new_role.clone(),
    };

    let mut ledger_guard = ledger.lock().unwrap();
    if let Err(e) = ledger_guard.append_entry(peer.to_bytes(), event.clone(), vec![]) {
        log::error!("Failed to append RoleUpdate event to ledger: {}", e);
        // We might want to return an error response here
        return Ok(());
    }

    // Also update the in-memory registry
    if let Some(entry) = ledger_guard.entries.last() {
        role_registry_guard.apply_entry(entry);
    }

    log::info!("Role updated for peer {} to {:?} by admin {}", hex::encode(&payload.target_peer_id), payload.new_role, peer);

    let response = AppResponse::RoleUpdateResponse(RoleUpdateResponsePayload::Success);
    let _ = swarm.behaviour_mut().request_response.send_response(channel, response);

    Ok(())
}

fn handle_manifest_request(
    payload: ManifestRequestPayload,
    channel: request_response::ResponseChannel<AppResponse>,
    file_hash_cache: &Arc<Mutex<HashMap<Vec<u8>, PathBuf>>>,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
) -> Result<(), P2pError> {
    let file_path = Path::new(&payload.file_path);
    if file_path.exists() {
        match create_file_manifest(file_path) {
            Ok(manifest) => {
                file_hash_cache.lock().unwrap().insert(manifest.total_hash.clone(), manifest.file_path.clone());
                let response = AppResponse::ManifestResponse(ManifestResponsePayload::Manifest(manifest));
                let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
            },
            Err(e) => {
                log::error!("Failed to create manifest for '{}': {}", payload.file_path, e);
                let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::ChunkReadError(e.to_string()));
            }
        }
    } else {
        log::warn!("Manifest requested for non-existent file: '{}'", payload.file_path);
        let response = AppResponse::ManifestResponse(ManifestResponsePayload::NotFound);
        let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
    }
    Ok(())
}

fn handle_lock_request(
    signed_payload: SignedPayload<LockRequestPayload>,
    peer: PeerId,
    channel: request_response::ResponseChannel<AppResponse>,
    peer_keys: &Arc<Mutex<HashMap<PeerId, PublicKey>>>,
    ledger: &Arc<Mutex<Ledger>>,
    role_registry: &Arc<Mutex<RoleRegistry>>,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
) -> Result<(), P2pError> {
    // --- Signature Verification ---
    let public_key = peer_keys.lock().unwrap().get(&peer).cloned().ok_or_else(|| P2pError::CommandFailed("Peer public key not found.".to_string()))?;
    let ed25519_pubkey = public_key.try_into_ed25519().map_err(|_| P2pError::CommandFailed("Peer key is not Ed25519.".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&ed25519_pubkey.to_bytes())?;
    let payload_bytes = bincode::serialize(&signed_payload.payload)?;
    let signature = Signature::from_bytes(&signed_payload.signature.as_slice().try_into().map_err(|_| P2pError::CommandFailed("Invalid signature length".to_string()))?);

    if !verify_signature(&payload_bytes, &signature, &verifying_key) {
        log::warn!("Signature verification FAILED for LockRequest from {}. Ignoring.", peer);
        return Ok(());
    }
    // --- End Signature Verification ---

    let file_path_str = signed_payload.payload.file_path.clone();
    let file_path = Path::new(&file_path_str);

    // --- ACL Check ---
    let role_registry_guard = role_registry.lock().unwrap();
    let requester_role = role_registry_guard.get_role(&peer.to_bytes()).cloned().unwrap_or(Role::Reader);

    if requester_role == Role::Reader {
        log::warn!("Lock denied for '{}': Peer {} has insufficient permissions (Role: Reader).", file_path_str, peer);
        let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::LockResponse(LockResponsePayload::Denied));
        if let Err(e) = ledger.lock().unwrap().append_entry(peer.to_bytes(), EventType::LockDenied { file_path: file_path_str }, b"PermissionDenied".to_vec()) {
            log::error!("Failed to write LockDenied (Permission) to ledger: {}", e);
        }
        return Ok(());
    }
    // --- End ACL Check ---

    let mut ledger_guard = ledger.lock().unwrap();

    let last_lock_event = ledger_guard.entries.iter().rev()
        .find(|e| match &e.event_type {
            EventType::LockGranted { file_path: p } |
            EventType::LockDenied { file_path: p } |
            EventType::LeaseExpired { file_path: p } => p == &file_path_str,
            _ => false,
        });

    let has_active_lease = match last_lock_event {
        Some(entry) => {
            if let EventType::LockGranted { .. } = &entry.event_type {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let grant_time = entry.timestamp.timestamp() as u64;
                if let Ok(duration) = bincode::deserialize::<u64>(&entry.payload) {
                    now < grant_time + duration
                } else {
                    false // Deserialization failed, assume expired
                }
            } else {
                false // It was denied or expired
            }
        },
        None => false, // No lock event ever
    };

    if has_active_lease {
        log::warn!("Lock denied for '{}': Active lease exists.", file_path_str);
        let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::LockResponse(LockResponsePayload::Denied));
        if let Err(e) = ledger_guard.append_entry(peer.to_bytes(), EventType::LockDenied { file_path: file_path_str }, vec![]) {
            log::error!("Failed to write LockDenied to ledger: {}", e);
        }
        return Ok(());
    }

    let last_update_hash = ledger_guard.entries.iter().rev()
        .find_map(|e| match &e.event_type {
            EventType::FileUpdated { file_hash, .. } => Some(file_hash.clone()),
            _ => None,
        });

    if let Some(reference_hash) = last_update_hash {
        if file_path.exists() {
            let local_hash = hash_stream(File::open(file_path)?)?;
            if local_hash != reference_hash {
                log::warn!("Lock denied for '{}': Local hash conflict.", file_path_str);
                let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::LockResponse(LockResponsePayload::Denied));
                if let Err(e) = ledger_guard.append_entry(peer.to_bytes(), EventType::LockDenied { file_path: file_path_str }, vec![]) {
                    log::error!("Failed to write LockDenied to ledger: {}", e);
                }
                return Ok(());
            }
        }
    }

    log::info!("Lock granted for '{}'", file_path_str);
    let duration_bytes = bincode::serialize(&signed_payload.payload.bail_duration)?;
    if let Err(e) = ledger_guard.append_entry(peer.to_bytes(), EventType::LockGranted { file_path: file_path_str }, duration_bytes) {
        log::error!("Failed to write LockGranted to ledger: {}", e);
    }
    let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::LockResponse(LockResponsePayload::Granted));
    Ok(())
}

fn handle_heartbeat_request(
    signed_payload: SignedPayload<HeartbeatPayload>,
    peer: PeerId,
    channel: request_response::ResponseChannel<AppResponse>,
    peer_keys: &Arc<Mutex<HashMap<PeerId, PublicKey>>>,
    ledger: &Arc<Mutex<Ledger>>,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
) -> Result<(), P2pError> {
    let public_key = match peer_keys.lock().unwrap().get(&peer) {
        Some(pk) => pk.clone(),
        None => {
            log::warn!("Heartbeat from unknown peer {}. Ignoring.", peer);
            return Ok(());
        }
    };
    let ed25519_pubkey = match public_key.try_into_ed25519() {
        Ok(key) => key,
        Err(_) => {
            log::warn!("Heartbeat from peer {} with non-Ed25519 key. Ignoring.", peer);
            return Ok(());
        }
    };
    let verifying_key = VerifyingKey::from_bytes(&ed25519_pubkey.to_bytes())?;
    let payload_bytes = bincode::serialize(&signed_payload.payload)?;
    let signature_bytes: [u8; 64] = match signed_payload.signature.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            log::warn!("Heartbeat from {} with invalid signature length. Ignoring.", peer);
            return Ok(());
        }
    };
    let signature = Signature::from_bytes(&signature_bytes);

    if verify_signature(&payload_bytes, &signature, &verifying_key) {
        log::info!("Signature VERIFIED for heartbeat from {}", peer);
        if let Err(e) = ledger.lock().unwrap().append_entry(peer.to_bytes(), EventType::HeartbeatReceived, payload_bytes) {
            log::error!("Failed to write to ledger: {}", e);
        }
        let response = AppResponse::Heartbeat(signed_payload.clone());
        let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
    } else {
        log::warn!("Signature FAILED for heartbeat from {}. Ignoring.", peer);
    }
    Ok(())
}

fn handle_chunk_request(
    payload: ChunkRequestPayload,
    channel: request_response::ResponseChannel<AppResponse>,
    keypair: &Keypair,
    file_hash_cache: &Arc<Mutex<HashMap<Vec<u8>, PathBuf>>>,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
) -> Result<(), P2pError> {
    let file_path = file_hash_cache.lock().unwrap().get(&payload.file_hash).cloned();

    if let Some(path) = file_path {
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                log::error!("Failed to open file for chunk request '{}': {}", path.display(), e);
                let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::ChunkReadError(e.to_string()));
                return Ok(());
            }
        };
        let offset = payload.chunk_index as u64 * CHUNK_SIZE as u64;
        if let Err(e) = file.seek(SeekFrom::Start(offset)) {
            log::error!("Failed to seek to chunk {} in '{}': {}", payload.chunk_index, path.display(), e);
            let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::ChunkReadError(e.to_string()));
            return Ok(());
        }

        let mut chunk_data = Vec::with_capacity(CHUNK_SIZE);
        match file.take(CHUNK_SIZE as u64).read_to_end(&mut chunk_data) {
            Ok(_) => {
                let response_payload = ChunkResponsePayload {
                    file_hash: payload.file_hash.clone(),
                    chunk_index: payload.chunk_index,
                    chunk_data,
                };
                let payload_bytes = bincode::serialize(&response_payload)?;
                let signature = sign_data(&payload_bytes, &keypair.signing_key);
                let signed_payload = SignedPayload { payload: response_payload, signature: signature.to_bytes().to_vec() };
                let response = AppResponse::ChunkResponse(signed_payload);
                let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
            },
            Err(e) => {
                log::error!("Failed to read chunk {} from '{}': {}", payload.chunk_index, path.display(), e);
                let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::ChunkReadError(e.to_string()));
            }
        }
    } else {
        log::warn!("Could not find file path for hash in chunk request. Ignoring.");
        let _ = swarm.behaviour_mut().request_response.send_response(channel, AppResponse::ChunkReadError("File not found".to_string()));
    }
    Ok(())
}

use tokio::sync::mpsc;
use std::str::FromStr;

// Commandes reçues de l'interface
#[derive(Debug)]
pub enum P2pCommand {
    SetRole {
        target_peer_id: String,
        role: Role,
    },
    ViewHistory,
    ViewRoles,
    UpdateFile { file_path: String },
    TransferFile { file_path: String, target_peer_id: String },
}

#[derive(Serialize, Clone)]
struct PeerPayload {
    peer_id: String,
}

#[derive(Serialize, Clone)]
struct LedgerEntryPayload {
    timestamp: String,
    peer_id: String,
    event_info: String,
}

#[derive(Serialize, Clone)]
struct RoleEntryPayload {
    peer_id: String,
    role: String,
}

pub async fn run_server(
    keypair: Keypair,
    remote_addr: Option<Multiaddr>,
    addr_sender: Option<mpsc::Sender<String>>,
    app_handle: Option<tauri::AppHandle>,
    mut command_receiver: Option<mpsc::Receiver<P2pCommand>>,
) -> Result<(), P2pError> {
    let local_key = keypair.to_libp2p_keypair()?;
    let local_peer_id_bytes = local_key.public().to_peer_id().to_bytes();

    let ledger = Arc::new(Mutex::new(Ledger::load("p2p_ledger.dat")?));
    let peer_keys = Arc::new(Mutex::new(HashMap::<PeerId, PublicKey>::new()));
    let active_leases = Arc::new(Mutex::new(Vec::<LeaseInfo>::new()));
    let file_hash_cache = Arc::new(Mutex::new(HashMap::<Vec<u8>, PathBuf>::new()));

    let role_registry = {
        let ledger_guard = ledger.lock().unwrap();
        let mut registry = RoleRegistry::new_from_ledger(&ledger_guard);
        if !registry.has_admin() {
            log::info!("No admin found in the ledger. Promoting local peer to Admin.");
            registry.set_initial_admin(local_peer_id_bytes.clone());
        }
        Arc::new(Mutex::new(registry))
    };

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&local_key)?)
        .multiplex(yamux::Config::default())
        .timeout(std::time::Duration::from_secs(20))
        .boxed();

    let behaviour = MyBehaviour {
        request_response: request_response::cbor::Behaviour::new(
            [(StreamProtocol::new("/secure-p2p/app/1"), ProtocolSupport::Full)],
            request_response::Config::default(),
        ),
        identify: identify::Behaviour::new(identify::Config::new(
            "/secure-p2p/identify/1".into(),
            local_key.public(),
        )),
    };

    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_other_transport(|_| transport)?
            .with_behaviour(|_| behaviour)?
            .build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())?;

    if let Some(addr) = remote_addr {
        swarm.dial(addr)?;
    }

    let mut heartbeat_interval = time::interval(Duration::from_secs(10));
    let mut lease_cleanup_interval = time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            Some(command) = async { if let Some(rx) = &mut command_receiver { rx.recv().await } else { None } } => {
                if let Err(e) = handle_p2p_command(command, &mut swarm, &keypair, &role_registry, &ledger, &app_handle) {
                    log::error!("Failed to handle P2P command: {}", e);
                }
            },
            _ = lease_cleanup_interval.tick() => {
                log::debug!("Running lease cleanup task...");
                let mut ledger_guard = ledger.lock().unwrap();
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

                let mut active_locks = std::collections::HashMap::new();

                for entry in ledger_guard.entries.iter() {
                    match &entry.event_type {
                        EventType::LockGranted { file_path } => {
                            active_locks.insert(file_path.clone(), entry.clone());
                        },
                        EventType::LockDenied { file_path } | EventType::LeaseExpired { file_path } => {
                            active_locks.remove(file_path);
                        },
                        _ => {}
                    }
                }

                let expired_files: Vec<_> = active_locks.into_iter()
                    .filter_map(|(file_path, entry)| {
                        if let Ok(duration) = bincode::deserialize::<u64>(&entry.payload) {
                            let grant_time = entry.timestamp.timestamp() as u64;
                            if now >= grant_time + duration {
                                return Some(file_path);
                            }
                        }
                        None
                    })
                    .collect();

                for file_path in expired_files {
                    log::info!("Lease for file '{}' has expired. Recording in ledger.", file_path);
                    if let Err(e) = ledger_guard.append_entry(
                        local_peer_id_bytes.clone(),
                        EventType::LeaseExpired { file_path: file_path.clone() },
                        vec![]
                    ) {
                        log::error!("Failed to append LeaseExpired event for '{}': {}", file_path, e);
                    }
                }
            },
            _ = heartbeat_interval.tick() => {
                let connected_peers: Vec<_> = swarm.connected_peers().cloned().collect();
                if !connected_peers.is_empty() {
                    log::info!("Sending heartbeat to {} connected peers...", connected_peers.len());
                    let mut active_leases_guard = active_leases.lock().unwrap();
                    active_leases_guard.clear();
                    let ledger_guard = ledger.lock().unwrap();
                    for entry in ledger_guard.entries.iter().rev() {
                        if let EventType::LockGranted { file_path } = &entry.event_type {
                            if let Ok(duration) = bincode::deserialize::<u64>(&entry.payload) {
                                let grant_time = entry.timestamp.timestamp() as u64;
                                let expiration_time = grant_time + duration;
                                if expiration_time > SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() {
                                    active_leases_guard.push(LeaseInfo {
                                        file_path: file_path.clone(),
                                        peer_id: entry.peer_id.clone(),
                                        expiration_time,
                                    });
                                }
                            }
                        }
                    }
                    for peer_id in connected_peers {
                        let payload = HeartbeatPayload {
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                            active_leases: active_leases_guard.clone(),
                        };
                        let payload_bytes = bincode::serialize(&payload)?;
                        let signature = sign_data(&payload_bytes, &keypair.signing_key);
                        let signed_payload = SignedPayload { payload, signature: signature.to_bytes().to_vec() };
                        swarm.behaviour_mut().request_response.send_request(&peer_id, AppRequest::Heartbeat(signed_payload));
                    }
                }
            },
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { .. } => {},
                    SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received { peer_id, info })) => {
                         peer_keys.lock().unwrap().insert(peer_id, info.public_key);
                         for addr in info.listen_addrs { swarm.add_peer_address(peer_id, addr); }
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::RequestResponse(request_response::Event::Message { message, peer, .. })) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                if let Err(e) = handle_inbound_request(request, peer, channel, &keypair, &peer_keys, &ledger, &role_registry, &file_hash_cache, &mut swarm) {
                                    log::error!("Error handling inbound request: {}", e);
                                }
                            }
                            request_response::Message::Response { .. } => {}
                        }
                    },
                    _ => {}
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

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

        let mut file = File::open(temp_file.path()).unwrap();
        let mut buffer = vec![0; CHUNK_SIZE];

        file.read_exact(&mut buffer).unwrap();
        let chunk1_hash = hash_stream(std::io::Cursor::new(&buffer)).unwrap();
        assert_eq!(manifest.chunk_hashes[0], chunk1_hash);

        let bytes_read = file.read(&mut buffer).unwrap();
        let chunk2_hash = hash_stream(std::io::Cursor::new(&buffer[..bytes_read])).unwrap();
        assert_eq!(manifest.chunk_hashes[1], chunk2_hash);
    }

    #[test]
    fn test_file_reconstruction_from_chunks() {
        let mut source_file = NamedTempFile::new().unwrap();
        let file_size = (CHUNK_SIZE as f64 * 2.2) as usize;
        let source_data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();
        source_file.write_all(&source_data).unwrap();

        let manifest = create_file_manifest(source_file.path()).unwrap();
        assert_eq!(manifest.chunk_hashes.len(), 3);

        let mut reconstructed_data = Vec::with_capacity(file_size);
        let mut source_handle = File::open(source_file.path()).unwrap();

        for (i, expected_hash) in manifest.chunk_hashes.iter().enumerate() {
            let mut chunk_buffer = vec![0; CHUNK_SIZE];
            let bytes_read = source_handle.read(&mut chunk_buffer).unwrap();
            let chunk_data = &chunk_buffer[..bytes_read];

            let received_hash = hash_stream(std::io::Cursor::new(chunk_data)).unwrap();
            assert_eq!(received_hash, *expected_hash, "Chunk {} hash mismatch", i);

            reconstructed_data.extend_from_slice(chunk_data);
        }

        assert_eq!(reconstructed_data.len(), file_size);
        assert_eq!(source_data, reconstructed_data);

        let reconstructed_hash = hash_stream(std::io::Cursor::new(reconstructed_data)).unwrap();
        assert_eq!(reconstructed_hash, manifest.total_hash);
    }
}

fn handle_p2p_command(
    command: P2pCommand,
    swarm: &mut libp2p::Swarm<MyBehaviour>,
    keypair: &Keypair,
    role_registry: &Arc<Mutex<RoleRegistry>>,
    ledger: &Arc<Mutex<Ledger>>,
    app_handle: &Option<tauri::AppHandle>,
) -> Result<(), P2pError> {
    match command {
        P2pCommand::SetRole { target_peer_id, role } => {
            let admin_peer_id = {
                let registry = role_registry.lock().unwrap();
                swarm.connected_peers()
                    .find(|p| registry.is_admin(&p.to_bytes()))
                    .cloned()
            };

            if let Some(admin_peer) = admin_peer_id {
                let target_bytes = PeerId::from_str(&target_peer_id)
                                        .map_err(|_| P2pError::CommandFailed("Invalid Target PeerId".to_string()))?
                                        .to_bytes();

                let payload = RoleUpdateRequestPayload {
                    target_peer_id: target_bytes,
                    new_role: role,
                };
                let payload_bytes = bincode::serialize(&payload)?;
                let signature = sign_data(&payload_bytes, &keypair.signing_key);
                let signed_payload = SignedPayload { payload, signature: signature.to_bytes().to_vec() };

                swarm.behaviour_mut().request_response.send_request(&admin_peer, AppRequest::RoleUpdateRequest(signed_payload));
                log::info!("Sent role update request to admin {}", admin_peer);

            } else {
                return Err(P2pError::CommandFailed("No admin peer is currently connected.".to_string()));
            }
        },
        P2pCommand::ViewHistory => {
            log::info!("--- UI COMMAND: View History ---");
            let ledger_guard = ledger.lock().unwrap();
            let entries_payload: Vec<LedgerEntryPayload> = ledger_guard.entries.iter().map(|entry| {
                let event_info = match &entry.event_type {
                    EventType::FileUpdated { file_hash, .. } => format!("FileUpdated | Hash: {}...", hex::encode(file_hash).chars().take(12).collect::<String>()),
                    EventType::RoleUpdate { target_peer_id, new_role } => format!("RoleUpdate | Target: {}..., Role: {:?}", hex::encode(target_peer_id).chars().take(12).collect::<String>(), new_role),
                    _ => format!("{:?}", entry.event_type),
                };
                LedgerEntryPayload {
                    timestamp: entry.timestamp.to_rfc3339(),
                    peer_id: PeerId::from_bytes(&entry.peer_id).unwrap().to_string(),
                    event_info,
                }
            }).collect();
            if let Some(handle) = &app_handle {
                handle.emit("history-updated", entries_payload).unwrap();
            }
        },
        P2pCommand::ViewRoles => {
            log::info!("--- UI COMMAND: View Roles ---");
            let registry = role_registry.lock().unwrap();
            let roles_payload: Vec<RoleEntryPayload> = registry.roles().map(|(peer_id_bytes, role)| {
                RoleEntryPayload {
                    peer_id: PeerId::from_bytes(peer_id_bytes).unwrap().to_string(),
                    role: format!("{:?}", role),
                }
            }).collect();
            if let Some(handle) = &app_handle {
                handle.emit("roles-updated", roles_payload).unwrap();
            }
        },
        P2pCommand::UpdateFile { file_path } => {
            let manifest = create_file_manifest(Path::new(&file_path))?;
            let connected_peers: Vec<_> = swarm.connected_peers().cloned().collect();
            for peer in &connected_peers {
                let payload = UpdateFileRequestPayload { manifest: manifest.clone() };
                let payload_bytes = bincode::serialize(&payload)?;
                let signature = sign_data(&payload_bytes, &keypair.signing_key);
                let signed_payload = SignedPayload { payload, signature: signature.to_bytes().to_vec() };
                swarm.behaviour_mut().request_response.send_request(peer, AppRequest::UpdateFileRequest(signed_payload));
            }
            log::info!("Sent update for {} to {} peers", file_path, connected_peers.len());
        },
        P2pCommand::TransferFile { file_path, target_peer_id } => {
            let peer_id = PeerId::from_str(&target_peer_id).map_err(|_| P2pError::CommandFailed("Invalid Target PeerId".to_string()))?;
            let file_path_clone = file_path.clone();
            let payload = ManifestRequestPayload { file_path };
            swarm.behaviour_mut().request_response.send_request(&peer_id, AppRequest::ManifestRequest(payload));
            log::info!("Requesting manifest for {} from {}", file_path_clone, peer_id);
        },
    }
    Ok(())
}
