use std::io;
use std::net::SocketAddr;

use crate::defaults::READ_TIMEOUT;
use crate::utils::run_with_timeout;

mod dns;
mod http;
mod tls;

#[derive(Debug, PartialEq, Eq)]
pub enum ProbeStatus {
    Recognized,
    Unknown,
}

/// Probe a probe to recognize protocol
#[async_trait::async_trait]
pub trait Probe {
    /// protocol's name
    fn name(&self) -> &'static str;

    /// protocol's favorite ports
    fn is_prefered_port(&self, port: u16) -> bool;

    /// Checks the remote connection
    async fn check(&self, peer_addr: SocketAddr) -> io::Result<ProbeStatus>;
}

lazy_static::lazy_static! {
    static ref PROBES: Vec<Box<dyn Probe + Send + Sync>> = vec![
        Box::new(http::HttpProbe) as Box<dyn Probe + Send + Sync>,
        Box::new(dns::DnsProbe) as Box<dyn Probe + Send + Sync>,
        Box::new(tls::TlsProbe) as Box<dyn Probe + Send + Sync>,
    ];
}

async fn check_probe(peer_addr: &SocketAddr, probe: &dyn Probe) -> io::Result<ProbeStatus> {
    run_with_timeout(unsafe { READ_TIMEOUT }, probe.check(peer_addr.clone()))
        .await
        .unwrap_or(Ok(ProbeStatus::Unknown))
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
