use std::net::SocketAddr;

use tokio::net::TcpStream;

use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_client::rr::{DNSClass, Name, RData, RecordType};
use trust_dns_client::tcp::TcpClientStream;

use super::{Probe, ProbeCheckFuture, ProbeStatus};

pub struct DnsProbe;

macro_rules! proto_error_to_unknown {
    ($e:expr) => {{
        match $e {
            Ok(val) => val,
            Err(_) => {
                return Ok(ProbeStatus::Unknown);
            }
        }
    }};
}

impl Probe for DnsProbe {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn is_prefered_port(&self, port: u16) -> bool {
        match port {
            53 | 5353 => true,
            _ => false,
        }
    }

    fn check(&self, peer_addr: SocketAddr) -> ProbeCheckFuture {
        Box::pin(async move {
            let (stream, sender) =
                TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::new(peer_addr.clone());

            let client = AsyncClient::new(stream, sender, None);

            let (mut client, bg) = proto_error_to_unknown!(client.await);

            // Make sur to run the background task
            tokio::spawn(bg);

            let name = Name::from(peer_addr.ip());
            let response =
                proto_error_to_unknown!(client.query(name, DNSClass::IN, RecordType::PTR,).await);

            if let Some(RData::PTR(name)) = response.answers().first().and_then(|a| a.data()) {
                println!("      - PTR({}) = {}", peer_addr.ip(), name.to_utf8());
            }

            Ok(ProbeStatus::Recognized)
        })
    }
}
