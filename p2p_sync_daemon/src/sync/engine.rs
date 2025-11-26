use super::super::{
    lock::manager::LockManager,
    network::{
        protocol::{BlockRequest, BlockResponse, FileManifest, GossipMessage},
        service::{NetworkCommand, NetworkEvent},
    },
};
use libp2p::{PeerId, request_response};
use std::{
    collections::HashMap,
    fs,
    path::{PathBuf},
    time::UNIX_EPOCH,
};
use tokio::sync::mpsc;

/// The central coordinator for file synchronization.
pub struct SyncEngine {
    /// The root directory being synced.
    pub sync_dir: PathBuf,
    /// The channel for sending commands to the network service.
    network_command_sender: mpsc::Sender<NetworkCommand>,
    /// Manages file locks.
    pub lock_manager: LockManager,
    /// Stores the latest known manifest for each file, keyed by relative path.
    manifests: HashMap<PathBuf, FileManifest>,
}

impl SyncEngine {
    /// Creates a new SyncEngine.
    pub fn new(
        sync_dir: PathBuf,
        network_command_sender: mpsc::Sender<NetworkCommand>,
    ) -> Self {
        let lock_manager = LockManager::new(sync_dir.clone());
        Self {
            sync_dir,
            network_command_sender,
            lock_manager,
            manifests: HashMap::new(),
        }
    }

    /// Handles a file system event from the watcher.
    pub async fn handle_fs_event(&mut self, path: PathBuf) {
        log::info!("Handling FS event for: {:?}", path);
        if self.lock_manager.is_locked_by_peer(&path) {
            log::warn!(
                "File {:?} is locked by a peer, ignoring local change.",
                path
            );
            // Optionally, create a conflict copy here.
            return;
        }

        let full_path = self.sync_dir.join(&path);
        if !full_path.exists() {
            // This case should be handled by a specific `Deleted` event if needed.
            return;
        }

        let content = match fs::read(&full_path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to read file {:?}: {}", path, e);
                return;
            }
        };

        let modified_ts = fs::metadata(&full_path).unwrap().modified().unwrap();
        let modified_ts_unix = modified_ts.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let manifest = FileManifest::from_bytes(
            path.to_string_lossy().to_string(),
            &content,
            modified_ts_unix,
        );

        self.update_manifest_and_gossip(manifest).await;
    }

    /// Handles an event from the network service.
    pub async fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::GossipMessage(message) => self.handle_gossip_message(message).await,
            NetworkEvent::InboundRequest {
                peer_id,
                request,
                channel,
            } => {
                self.handle_block_request(peer_id, request, channel).await;
            }
            NetworkEvent::BlockResponse { peer_id, response } => {
                self.handle_block_response(peer_id, response).await;
            }
        }
    }

    /// Handles an incoming gossip message.
    async fn handle_gossip_message(&mut self, message: GossipMessage) {
        match message {
            GossipMessage::ManifestUpdated(remote_manifest) => {
                let path = PathBuf::from(&remote_manifest.path);
                let current_manifest = self.manifests.get(&path);

                // Only sync if the remote manifest is newer.
                if current_manifest.map_or(true, |m| remote_manifest.modified_ts > m.modified_ts) {
                    log::info!("Received a newer manifest for {:?}, syncing...", path);
                    self.request_missing_blocks(remote_manifest).await;
                }
            }
            GossipMessage::LockStateChanged { path, state } => {
                self.lock_manager.handle_peer_lock_state(&path, &state);
            }
        }
    }

    /// Compares a remote manifest with the local one and requests missing blocks.
    async fn request_missing_blocks(&mut self, remote_manifest: FileManifest) {
        let path = PathBuf::from(&remote_manifest.path);
        let local_manifest = self.manifests.get(&path);

        for remote_block in &remote_manifest.blocks {
            let is_missing = local_manifest.map_or(true, |m| {
                m.blocks
                    .get(remote_block.index as usize)
                    .map_or(true, |b| b.hash != remote_block.hash)
            });

            if is_missing {
                // For simplicity, we just request from any peer.
                // A real implementation would need to know which peer has the manifest.
                // We'll need to solve this in the main loop by tracking peers.
                log::info!("Requesting missing block {} for {:?}", remote_block.index, path);
                // This is a placeholder for now.
                // We need a peer_id to send a request.
            }
        }
    }

    /// Handles a request from a peer for a specific block.
    async fn handle_block_request(
        &self,
        peer_id: PeerId,
        request: BlockRequest,
        channel: request_response::ResponseChannel<BlockResponse>,
    ) {
        log::debug!(
            "Received block request from {:?} for file {:?} block {}",
            peer_id,
            request.path,
            request.block_index
        );
        let full_path = self.sync_dir.join(&request.path);
        let response = match fs::read(&full_path) {
            Ok(content) => {
                let start = request.block_index as usize * crate::network::protocol::BLOCK_SIZE;
                let end = (start + crate::network::protocol::BLOCK_SIZE).min(content.len());
                let data = content.get(start..end).unwrap_or_default().to_vec();
                BlockResponse { data }
            }
            Err(e) => {
                log::error!(
                    "Failed to read file for block request {:?}: {}",
                    request.path,
                    e
                );
                // Send an empty response on error.
                BlockResponse { data: vec![] }
            }
        };

        self.network_command_sender
            .send(NetworkCommand::SendResponse { channel, response })
            .await
            .unwrap();
    }

    /// Handles a response from a peer containing a block's data.
    async fn handle_block_response(&mut self, peer_id: PeerId, response: BlockResponse) {
        log::info!(
            "Received block response from {:?} with {} bytes",
            peer_id,
            response.data.len()
        );
        // Here, we would find the pending request, verify the block hash,
        // and write the data to the correct file offset.
        // This requires more state management in the SyncEngine.
    }

    /// Updates the local manifest for a file and broadcasts it to the network.
    async fn update_manifest_and_gossip(&mut self, manifest: FileManifest) {
        let path = PathBuf::from(&manifest.path);
        self.manifests.insert(path, manifest.clone());

        let gossip_message = GossipMessage::ManifestUpdated(manifest);
        if let Err(e) = self.network_command_sender.send(NetworkCommand::Publish(gossip_message)).await {
            log::error!("Failed to send publish command: {}", e);
        }
    }
}
