use super::{P2pError, AppRequest, AppResponse, MyBehaviour, SignedPayload, ManifestRequestPayload, ChunkRequestPayload, ManifestResponsePayload, RoleUpdateRequestPayload, RoleUpdateResponsePayload, UpdateFileRequestPayload, UpdateFileResponsePayload};
use crypto::{Keypair, sign_data, verify_signature};
use ledger_core::Role;
use libp2p::{
    core::upgrade,
    noise,
    request_response::{self, ProtocolSupport},
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, SwarmBuilder, Transport, StreamProtocol, PeerId,
};
use futures::StreamExt;
use ed25519_dalek::Signature;
use chunk_engine::{create_file_manifest, decompress_chunk, reconstruct_file, FileManifest};

#[derive(Debug, Clone)]
pub enum ClientCommand {
    TransferFile {
        file_path: String,
        remote_addr: Multiaddr,
    },
    SetRole {
        target_peer_id: Vec<u8>,
        role: Role,
        admin_peer: Multiaddr,
    },
    UpdateFile {
        file_path: String,
        peers: Vec<Multiaddr>,
    },
}

pub async fn run_client(keypair: Keypair, command: ClientCommand) -> Result<(), P2pError> {
    let local_key = keypair.to_libp2p_keypair()?;

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&local_key)?)
        .multiplex(yamux::Config::default())
        .timeout(std::time::Duration::from_secs(20))
        .boxed();

    let mdns = libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), local_key.public().to_peer_id())?;
    let behaviour = MyBehaviour {
        request_response: request_response::cbor::Behaviour::new(
            [(StreamProtocol::new("/secure-p2p/app/1"), ProtocolSupport::Full)],
            request_response::Config::default(),
        ),
        identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
            "/secure-p2p/identify/1".into(),
            local_key.public(),
        )),
        mdns,
    };

    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_other_transport(|_| transport)?
        .with_behaviour(|_| behaviour)?
        .build();

    match command {
        ClientCommand::TransferFile { file_path, remote_addr } => {
            swarm.dial(remote_addr)?;
            let mut _peer_id: Option<PeerId> = None;
            let mut active_manifest: Option<FileManifest> = None;
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            let mut received_count = 0;
            let mut total_chunks = 0;

            let timeout = tokio::time::timeout(std::time::Duration::from_secs(60), async {
                loop {
                    match swarm.select_next_some().await {
                        SwarmEvent::ConnectionEstablished { peer_id: established_peer_id, .. } => {
                            _peer_id = Some(established_peer_id);
                            let payload = ManifestRequestPayload { file_path: file_path.clone() };
                            swarm.behaviour_mut().request_response.send_request(&established_peer_id, AppRequest::ManifestRequest(payload));
                        },
                        SwarmEvent::Behaviour(super::MyBehaviourEvent::RequestResponse(request_response::Event::Message {
                            message: request_response::Message::Response { response, .. },
                            peer,
                        })) => {
                            match response {
                                AppResponse::ManifestResponse(ManifestResponsePayload::Manifest(manifest)) => {
                                    total_chunks = manifest.chunk_hashes.len();
                                    chunks = vec![Vec::new(); total_chunks];
                                    active_manifest = Some(manifest.clone());

                                    for i in 0..total_chunks {
                                        let payload = ChunkRequestPayload { file_hash: manifest.total_hash.clone(), chunk_index: i as u32 };
                                        swarm.behaviour_mut().request_response.send_request(&peer, AppRequest::ChunkRequest(payload));
                                    }
                                },
                                AppResponse::ChunkResponse(signed_payload) => {
                                    if let Some(manifest) = &active_manifest {
                                        let payload_bytes = bincode::serialize(&signed_payload.payload)?;
                                        let signature = Signature::from_bytes(match signed_payload.signature.as_slice().try_into() {
                                            Ok(bytes) => bytes,
                                            Err(_) => return Err(P2pError::CommandFailed("Invalid signature length".to_string())),
                                        });
                                        let verifying_key = keypair.verifying_key;

                                        if verify_signature(&payload_bytes, &signature, &verifying_key) {
                                            let chunk_data = match decompress_chunk(&signed_payload.payload.chunk_data) {
                                                Ok(data) => data,
                                                Err(e) => return Err(P2pError::CommandFailed(format!("Decompression error: {}", e))),
                                            };

                                            let index = signed_payload.payload.chunk_index as usize;
                                            if index >= total_chunks {
                                                 return Err(P2pError::CommandFailed("Invalid chunk index".to_string()));
                                            }

                                            if chunks[index].is_empty() {
                                                chunks[index] = chunk_data;
                                                received_count += 1;
                                            }

                                            if received_count == total_chunks {
                                                log::info!("All chunks received. Reconstructing file...");
                                                match reconstruct_file(std::path::Path::new(&file_path), chunks.clone(), manifest) {
                                                    Ok(_) => {
                                                        log::info!("File transfer and reconstruction complete.");
                                                        return Ok(());
                                                    },
                                                    Err(e) => return Err(P2pError::CommandFailed(format!("Reconstruction failed: {}", e))),
                                                }
                                            }
                                        } else {
                                            return Err(P2pError::CommandFailed("Chunk signature verification failed".to_string()));
                                        }
                                    }
                                },
                                AppResponse::ManifestResponse(ManifestResponsePayload::NotFound) => {
                                     return Err(P2pError::CommandFailed("File not found on remote peer.".to_string()));
                                }
                                _ => {}
                            }
                        },
                        _ => {}
                    }
                }
            }).await;

            if let Err(_) = timeout {
                return Err(P2pError::CommandFailed("Timeout waiting for file transfer".to_string()));
            } else {
                Ok(())
            }
        },
        ClientCommand::SetRole { target_peer_id, role, admin_peer } => {
            swarm.dial(admin_peer)?;

            let timeout = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    match swarm.select_next_some().await {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            let payload = RoleUpdateRequestPayload { target_peer_id: target_peer_id.clone(), new_role: role };
                            let payload_bytes = bincode::serialize(&payload)?;
                            let signature = sign_data(&payload_bytes, &keypair.signing_key);
                            let signed_payload = SignedPayload { payload, signature: signature.to_bytes().to_vec() };
                            swarm.behaviour_mut().request_response.send_request(&peer_id, AppRequest::RoleUpdateRequest(signed_payload));
                        },
                        SwarmEvent::Behaviour(super::MyBehaviourEvent::RequestResponse(request_response::Event::Message {
                            message: request_response::Message::Response { response, .. },
                            ..
                        })) => {
                            return match response {
                                AppResponse::RoleUpdateResponse(RoleUpdateResponsePayload::Success) => {
                                    log::info!("Role updated successfully!");
                                    Ok(())
                                },
                                AppResponse::RoleUpdateResponse(RoleUpdateResponsePayload::PermissionDenied) => {
                                    Err(P2pError::CommandFailed("Permission denied by admin peer.".to_string()))
                                },
                                _ => Err(P2pError::CommandFailed("Unexpected response from peer.".to_string())),
                            };
                        },
                        _ => {}
                    }
                }
            }).await;

            if let Err(_) = timeout {
                return Err(P2pError::CommandFailed("Timeout waiting for role update response".to_string()));
            } else {
                Ok(())
            }
        },
        ClientCommand::UpdateFile { file_path, peers } => {
            let manifest = create_file_manifest(std::path::Path::new(&file_path))?;
            for addr in &peers {
                swarm.dial(addr.clone())?;
            }

            let mut pending_dials = peers.len();
            let mut connected_peers = std::collections::HashSet::new();
            let mut pending_update_responses = 0;
            let mut update_success_count = 0;

            let timeout = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    match swarm.select_next_some().await {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            pending_dials -= 1;
                            connected_peers.insert(peer_id);
                            if pending_dials == 0 {
                                pending_update_responses = connected_peers.len();
                                for peer in &connected_peers {
                                    let payload = UpdateFileRequestPayload { manifest: manifest.clone() };
                                    let payload_bytes = bincode::serialize(&payload)?;
                                    let signature = sign_data(&payload_bytes, &keypair.signing_key);
                                    let signed_payload = SignedPayload { payload, signature: signature.to_bytes().to_vec() };
                                    swarm.behaviour_mut().request_response.send_request(peer, AppRequest::UpdateFileRequest(signed_payload));
                                }
                            }
                        },
                        SwarmEvent::Behaviour(super::MyBehaviourEvent::RequestResponse(request_response::Event::Message {
                            message: request_response::Message::Response { response, .. },
                            ..
                        })) => {
                            match response {
                                AppResponse::UpdateFileResponse(UpdateFileResponsePayload::Success) => {
                                    update_success_count += 1;
                                    pending_update_responses -= 1;
                                    log::info!("Update successful with one peer.");
                                },
                                AppResponse::UpdateFileResponse(UpdateFileResponsePayload::ConflictDetected) => {
                                    pending_update_responses -= 1;
                                    log::error!("Update failed: Conflict detected.");
                                },
                                _ => {}
                            }
                            if pending_update_responses == 0 {
                                return if update_success_count == connected_peers.len() {
                                    log::info!("All peers acknowledged the file update! Command successful.");
                                    Ok(())
                                } else {
                                    Err(P2pError::CommandFailed("Failed to update file on all peers.".to_string()))
                                }
                            }
                        },
                        _ => {}
                    }
                }
            }).await;

            if let Err(_) = timeout {
                return Err(P2pError::CommandFailed("Timeout waiting for file update responses".to_string()));
            } else {
                Ok(())
            }
        }
    }
}
