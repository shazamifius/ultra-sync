use crypto::{CryptoError, Keypair};
use futures::stream::StreamExt;
use libp2p::{
    core::upgrade,
    identify, noise,
    request_response::{self, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder, Transport, StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tokio::time::{self, Interval};
use std::convert::Infallible;

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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Heartbeat {
    pub r#type: String,
    pub timestamp: u64,
    pub peer_id: String,
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
                        let heartbeat = Heartbeat {
                            r#type: "HEARTBEAT_ECHO".to_string(),
                            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                            peer_id: local_peer_id.to_string(),
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
                        log::info!("Received identify info from {}: {:?}", peer_id, info.listen_addrs);
                        for addr in info.listen_addrs {
                             swarm.behaviour_mut().request_response.add_address(&peer_id, addr);
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::RequestResponse(request_response::Event::Message {
                        peer,
                        message,
                    })) => {
                        match message {
                            request_response::Message::Request { request, channel,.. } => {
                                log::info!("Received heartbeat request from {}: {:?}", peer, request);
                                swarm.behaviour_mut().request_response.send_response(channel, request.clone()).unwrap();
                            }
                            request_response::Message::Response { response, .. } => {
                                log::info!("Received heartbeat response from peer: {:?}", response);
                            }
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        log::info!("Connection established with {}", peer_id);
                    }
                     SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        log::info!("Connection to {} closed: {:?}", peer_id, cause);
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
