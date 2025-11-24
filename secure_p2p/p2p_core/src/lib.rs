use crypto::{CryptoError, Keypair, sign_data, verify_signature};
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
use tokio::time::{self, Interval};
use std::convert::Infallible;
use ledger_core::{Ledger, EventType};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use ed25519_dalek::{Signature, VerifyingKey};

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
    #[error("Invalid signature length")]
    InvalidSignatureLength,
    #[error("Unsupported public key type")]
    UnsupportedPublicKey,
}

/// The content of the heartbeat that gets signed.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatPayload {
    pub r#type: String,
    pub timestamp: u64,
}

/// The full Heartbeat message, including the signature.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Heartbeat {
    pub payload: HeartbeatPayload,
    pub signature: Vec<u8>,
}

#[derive(NetworkBehaviour)]
pub struct MyBehaviour {
    pub request_response: request_response::cbor::Behaviour<Heartbeat, Heartbeat>,
    pub identify: identify::Behaviour,
}

pub async fn run_swarm(keypair: Keypair, remote_addr: Option<Multiaddr>) -> Result<(), P2pError> {
    let local_key = keypair.to_libp2p_keypair()?;
    let local_peer_id = PeerId::from(local_key.public());
    log::info!("Local peer id: {}", local_peer_id);

    let ledger = Arc::new(Mutex::new(Ledger::load("p2p_ledger.dat")?));
    let peer_keys = Arc::new(Mutex::new(HashMap::<PeerId, PublicKey>::new()));

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&local_key)?)
        .multiplex(yamux::Config::default())
        .timeout(std::time::Duration::from_secs(20))
        .boxed();

    let behaviour = MyBehaviour {
        request_response: request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new("/secure-p2p/heartbeat/1"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        ),
        identify: identify::Behaviour::new(identify::Config::new(
            "/secure-p2p/identify/1".into(),
            local_key.public(),
        )),
    };

    let mut swarm =
        SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_other_transport(|_| transport)?
            .with_behaviour(|_| behaviour)?
            .build();


    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())?;

    if let Some(addr) = remote_addr {
        swarm.dial(addr)?;
        log::info!("Dialing remote peer...");
    }

    let mut heartbeat_interval: Interval = time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = heartbeat_interval.tick() => {
                let connected_peers: Vec<_> = swarm.connected_peers().cloned().collect();
                if !connected_peers.is_empty() {
                    log::info!("Sending heartbeat to {} connected peers...", connected_peers.len());
                    for peer_id in connected_peers {
                        let payload = HeartbeatPayload {
                            r#type: "HEARTBEAT_ECHO".to_string(),
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                        };

                        let payload_bytes = bincode::serialize(&payload)?;
                        let signature = sign_data(&payload_bytes, &keypair.signing_key);

                        let heartbeat = Heartbeat {
                            payload,
                            signature: signature.to_bytes().to_vec(),
                        };

                        swarm.behaviour_mut().request_response.send_request(&peer_id, heartbeat);
                    }
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        log::info!("Listening on {}", address);
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received {
                        peer_id,
                        info,
                    })) => {
                        log::info!("Received identify info from {}: listen_addrs={:?}, public_key available", peer_id, info.listen_addrs);
                        peer_keys.lock().unwrap().insert(peer_id, info.public_key);
                        for addr in info.listen_addrs {
                             swarm.add_peer_address(peer_id, addr);
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::RequestResponse(request_response::Event::Message {
                        peer,
                        message,
                    })) => {
                        match message {
                            request_response::Message::Request { request, channel,.. } => {
                                let public_key = match peer_keys.lock().unwrap().get(&peer) {
                                    Some(pk) => pk.clone(),
                                    None => {
                                        log::warn!("Received heartbeat from peer {} without a stored public key. Ignoring.", peer);
                                        continue;
                                    }
                                };

                                let ed25519_pubkey = match public_key.try_into_ed25519() {
                                    Ok(key) => key,
                                    Err(_) => {
                                        log::warn!("Received heartbeat from peer {} with a non-Ed25519 key. Ignoring.", peer);
                                        continue;
                                    }
                                };

                                let verifying_key = VerifyingKey::from_bytes(&ed25519_pubkey.to_bytes())?;
                                let payload_bytes = bincode::serialize(&request.payload)?;
                                let signature_bytes: [u8; 64] = match request.signature.as_slice().try_into() {
                                    Ok(bytes) => bytes,
                                    Err(_) => {
                                        log::warn!("Received heartbeat from {} with an invalid signature length. Ignoring.", peer);
                                        continue;
                                    }
                                };
                                let signature = Signature::from_bytes(&signature_bytes);

                                if verify_signature(&payload_bytes, &signature, &verifying_key) {
                                    log::info!("Signature VERIFIED for heartbeat from {}", peer);

                                    if let Err(e) = ledger.lock().unwrap().append_entry(peer.to_bytes(), EventType::HeartbeatReceived, payload_bytes) {
                                        log::error!("Failed to write to ledger: {}", e);
                                    }

                                    swarm.behaviour_mut().request_response.send_response(channel, request.clone()).unwrap();
                                } else {
                                    log::warn!("Signature FAILED for heartbeat from {}. Ignoring.", peer);
                                }
                            }
                            request_response::Message::Response { response, .. } => {
                                log::info!("Received heartbeat response from peer: {:?}", response.payload);
                            }
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        log::info!("Connection established with {}", peer_id);
                        if let Err(e) = ledger.lock().unwrap().append_entry(peer_id.to_bytes(), EventType::ConnectionEstablished, vec![]) {
                            log::error!("Failed to write to ledger: {}", e);
                        }
                    }
                     SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        log::info!("Connection to {} closed: {:?}", peer_id, cause);
                        if let Err(e) = ledger.lock().unwrap().append_entry(peer_id.to_bytes(), EventType::ConnectionLost, vec![]) {
                            log::error!("Failed to write to ledger: {}", e);
                        }
                    }
                    SwarmEvent::Dialing{ peer_id: Some(peer_id), ..} => {
                        log::info!("Dialing {}", peer_id);
                    }
                    _ => {
                        log::debug!("Unhandled swarm event: {:?}", event);
                    }
                }
            }
        }
    }
}
