use libp2p::{
    gossipsub,
    mdns,
    request_response::{self, Codec},
    swarm::NetworkBehaviour,
};
use futures::prelude::*;
use futures::io::{AsyncRead, AsyncWrite};
use async_trait::async_trait;
use std::io;

use super::protocol::{BlockRequest, BlockResponse};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "AppBehaviourEvent")]
pub struct AppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub request_response: request_response::Behaviour<JsonRequestResponseCodec>,
}

// --- Custom Codec for Request-Response ---
#[derive(Debug, Clone, Default)]
pub struct JsonRequestResponseCodec;

#[async_trait]
impl Codec for JsonRequestResponseCodec {
    type Protocol = &'static str;
    type Request = BlockRequest;
    type Response = BlockResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&req).unwrap();
        io.write_all(&buf).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let buf = serde_json::to_vec(&res).unwrap();
        io.write_all(&buf).await?;
        io.close().await?;
        Ok(())
    }
}


/// Events emitted by the AppBehaviour to be handled in the main event loop.
#[derive(Debug)]
pub enum AppBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
    RequestResponse(request_response::Event<BlockRequest, BlockResponse>),
}

impl From<gossipsub::Event> for AppBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        AppBehaviourEvent::Gossipsub(event)
    }
}

impl From<mdns::Event> for AppBehaviourEvent {
    fn from(event: mdns::Event) -> Self {
        AppBehaviourEvent::Mdns(event)
    }
}

impl From<request_response::Event<BlockRequest, BlockResponse>> for AppBehaviourEvent {
    fn from(event: request_response::Event<BlockRequest, BlockResponse>) -> Self {
        AppBehaviourEvent::RequestResponse(event)
    }
}
