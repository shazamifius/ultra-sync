use super::{P2pError, AppRequest, AppResponse, MyBehaviour, LockRequestPayload, SignedPayload, ManifestRequestPayload, ChunkRequestPayload, ManifestResponsePayload};
use crypto::{Keypair, sign_data, hash_stream, verify_signature};
use libp2p::{
    core::upgrade,
    noise,
    request_response::{self, ProtocolSupport},
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, SwarmBuilder, Transport, StreamProtocol, PeerId,
};
use futures::StreamExt;
use std::fs::File;
use std::io::Write;
use ed25519_dalek::Signature;

#[derive(Debug, Clone)]
pub enum ClientCommand {
    RequestLock {
        file_path: String,
        peers: Vec<Multiaddr>,
        bail_duration: u64,
    },
    TransferFile {
        file_path: String,
        remote_addr: Multiaddr,
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

    let behaviour = MyBehaviour {
        request_response: request_response::cbor::Behaviour::new(
            [(StreamProtocol::new("/secure-p2p/app/1"), ProtocolSupport::Full)],
            request_response::Config::default(),
        ),
        identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
            "/secure-p2p/identify/1".into(),
            local_key.public(),
        )),
    };

    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_other_transport(|_| transport)?
        .with_behaviour(|_| behaviour)?
        .build();

    match command {
        ClientCommand::RequestLock { file_path, peers, bail_duration } => {
            for addr in &peers {
                swarm.dial(addr.clone())?;
            }

            let mut pending_dials = peers.len();
            let mut connected_peers = std::collections::HashSet::new();
            let mut pending_lock_responses = 0;
            let mut lock_granted_count = 0;

            let timeout = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    match swarm.select_next_some().await {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            pending_dials -= 1;
                            connected_peers.insert(peer_id);
                            if pending_dials == 0 {
                                pending_lock_responses = connected_peers.len();
                                for peer in &connected_peers {
                                    let payload = LockRequestPayload { file_path: file_path.clone(), bail_duration };
                                    let payload_bytes = bincode::serialize(&payload)?;
                                    let signature = sign_data(&payload_bytes, &keypair.signing_key);
                                    let signed_payload = SignedPayload { payload, signature: signature.to_bytes().to_vec() };
                                    swarm.behaviour_mut().request_response.send_request(peer, AppRequest::LockRequest(signed_payload));
                                }
                            }
                        },
                        SwarmEvent::Behaviour(super::MyBehaviourEvent::RequestResponse(request_response::Event::Message {
                            message: request_response::Message::Response { response, .. },
                            ..
                        })) => {
                            match response {
                                AppResponse::LockResponse(super::LockResponsePayload::Granted) => {
                                    lock_granted_count += 1;
                                    pending_lock_responses -= 1;
                                    log::info!("Lock GRANTED received ({}/{})", lock_granted_count, pending_lock_responses + lock_granted_count);
                                },
                                AppResponse::LockResponse(super::LockResponsePayload::Denied) => {
                                    pending_lock_responses -= 1;
                                    log::error!("Lock DENIED received.");
                                },
                                _ => {}
                            }
                            if pending_lock_responses == 0 {
                                return if lock_granted_count == connected_peers.len() {
                                    log::info!("All peers granted the lock! Command successful.");
                                    Ok(())
                                } else {
                                    Err(P2pError::CommandFailed("Failed to acquire lock from all peers.".to_string()))
                                }
                            }
                        },
                        _ => {}
                    }
                }
            }).await;

            if let Err(_) = timeout {
                return Err(P2pError::CommandFailed("Timeout waiting for lock responses".to_string()));
            } else {
                Ok(())
            }
        }
        ClientCommand::TransferFile { file_path, remote_addr } => {
            swarm.dial(remote_addr)?;
            let mut peer_id: Option<PeerId> = None;

            let timeout = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    match swarm.select_next_some().await {
                        SwarmEvent::ConnectionEstablished { peer_id: established_peer_id, .. } => {
                            peer_id = Some(established_peer_id);
                            let payload = ManifestRequestPayload { file_path: file_path.clone() };
                            swarm.behaviour_mut().request_response.send_request(&established_peer_id, AppRequest::ManifestRequest(payload));
                        },
                        SwarmEvent::Behaviour(super::MyBehaviourEvent::RequestResponse(request_response::Event::Message {
                            message: request_response::Message::Response { response, .. },
                            peer,
                        })) => {
                            match response {
                                AppResponse::ManifestResponse(ManifestResponsePayload::Manifest(manifest)) => {
                                    let mut file = File::create(&file_path)?;
                                    let mut received_chunks = 0;
                                    for i in 0..manifest.chunk_hashes.len() {
                                        let payload = ChunkRequestPayload { file_hash: manifest.total_hash.clone(), chunk_index: i as u32 };
                                        swarm.behaviour_mut().request_response.send_request(&peer, AppRequest::ChunkRequest(payload));
                                    }

                                    loop {
                                        match swarm.select_next_some().await {
                                            SwarmEvent::Behaviour(super::MyBehaviourEvent::RequestResponse(request_response::Event::Message {
                                                message: request_response::Message::Response { response, .. },
                                                ..
                                            })) => {
                                                match response {
                                                    AppResponse::ChunkResponse(signed_payload) => {
                                                        let payload_bytes = bincode::serialize(&signed_payload.payload)?;
                                                        let signature = Signature::from_bytes(match signed_payload.signature.as_slice().try_into() {
                                                            Ok(bytes) => bytes,
                                                            Err(_) => return Err(P2pError::CommandFailed("Invalid signature length".to_string())),
                                                        });
                                                        let verifying_key = keypair.verifying_key;

                                                        if verify_signature(&payload_bytes, &signature, &verifying_key) {
                                                            let chunk_hash = hash_stream(std::io::Cursor::new(&signed_payload.payload.chunk_data))?;
                                                            if chunk_hash == manifest.chunk_hashes[signed_payload.payload.chunk_index as usize] {
                                                                file.write_all(&signed_payload.payload.chunk_data)?;
                                                                received_chunks += 1;
                                                                if received_chunks == manifest.chunk_hashes.len() {
                                                                    log::info!("File transfer complete.");
                                                                    return Ok(());
                                                                }
                                                            } else {
                                                                return Err(P2pError::CommandFailed("Chunk hash mismatch".to_string()));
                                                            }
                                                        } else {
                                                            return Err(P2pError::CommandFailed("Chunk signature verification failed".to_string()));
                                                        }
                                                    },
                                                    _ => {}
                                                }
                                            },
                                            _ => {}
                                        }
                                    }
                                },
                                _ => {
                                    return Err(P2pError::CommandFailed("Failed to get manifest".to_string()));
                                }
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
        }
    }
}
