use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::defaults::READ_TIMEOUT;
use crate::utils::run_with_timeout;

mod dns;
mod http;

#[derive(Debug, PartialEq, Eq)]
pub enum ProbeStatus {
    Recognized,
    Unknown,
}

/// Probe a probe to recognize protocol
pub trait Probe {
    /// protocol's name
    fn name(&self) -> &'static str;

    /// protocol's favorite ports
    fn is_prefered_port(&self, port: u16) -> bool;

    /// Retrieve a buffer to send
    fn get_request(&self, peer_addr: &SocketAddr, buffer: &mut [u8]) -> usize;

    /// Checks if the response is recognized
    fn recognized(&self, data: &[u8]) -> ProbeStatus;
}

lazy_static::lazy_static! {
    static ref PROBES: Vec<Box<dyn Probe + Send + Sync>> = vec![
        Box::new(http::HttpProbe) as Box<dyn Probe + Send + Sync>,
        Box::new(dns::DnsProbe::new()) as Box<dyn Probe + Send + Sync>,
    ];
}

async fn check_probe(peer_addr: &SocketAddr, probe: &dyn Probe) -> io::Result<ProbeStatus> {
    let mut buffer = [0u8; 8192];

    let request_size = probe.get_request(peer_addr, &mut buffer[..]);

    let mut stream = TcpStream::connect(peer_addr.clone()).await?;
    stream.write_all(&buffer[..request_size]).await?;

    match run_with_timeout(unsafe { READ_TIMEOUT }, stream.read(&mut buffer[..])).await {
        Some(val) => {
            let response_size = val?;
            Ok(probe.recognized(&buffer[..response_size]))
        }
        None => Ok(ProbeStatus::Unknown),
    }
}

pub async fn check_probes(peer_addr: &SocketAddr) -> io::Result<()> {
    // First pass, only check favorite ports
    for probe in PROBES.iter() {
        if probe.is_prefered_port(peer_addr.port()) {
            if check_probe(&peer_addr, probe.as_ref()).await? == ProbeStatus::Recognized {
                // eprintln!(
                //     "Found protocol {} for port {}",
                //     probe.name(),
                //     peer_addr.port()
                // );
                return Ok(());
            }
        }
    }

    // Second pass, only check non-favorite ports
    for probe in PROBES.iter() {
        if !probe.is_prefered_port(peer_addr.port()) {
            if check_probe(&peer_addr, probe.as_ref()).await? == ProbeStatus::Recognized {
                // eprintln!(
                //     "Found protocol {} for port {}",
                //     probe.name(),
                //     peer_addr.port()
                // );
                return Ok(());
            }
        }
    }

    Ok(())
}
