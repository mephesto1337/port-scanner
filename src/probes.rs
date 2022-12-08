use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

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

pub type ProbeCheckFuture = Pin<Box<dyn Future<Output = io::Result<ProbeStatus>> + Send>>;

/// Probe a probe to recognize protocol
pub trait Probe {
    /// protocol's name
    fn name(&self) -> &'static str;

    /// protocol's favorite ports
    fn is_prefered_port(&self, port: u16) -> bool;

    /// Checks the remote connection
    fn check(&self, peer_addr: SocketAddr) -> ProbeCheckFuture;
}

type BoxedProbe = Box<dyn Probe + Send + Sync>;
static PROBES: AtomicPtr<Vec<BoxedProbe>> = AtomicPtr::new(ptr::null_mut());

fn get_probes() -> &'static [BoxedProbe] {
    let probes_ptr = PROBES.load(Ordering::Relaxed);
    if probes_ptr.is_null() {
        let probes = Box::new(vec![
            Box::new(http::HttpProbe) as BoxedProbe,
            Box::new(dns::DnsProbe) as BoxedProbe,
            Box::new(tls::TlsProbe) as BoxedProbe,
        ]);

        PROBES.store(Box::leak(probes), Ordering::Relaxed);
    }
    let probes_ptr = PROBES.load(Ordering::Relaxed);

    unsafe { probes_ptr.as_ref() }
        .expect("Probes should be initiated")
        .as_slice()
}

async fn check_probe(peer_addr: &SocketAddr, probe: &dyn Probe) -> ProbeStatus {
    match run_with_timeout(unsafe { READ_TIMEOUT }, probe.check(peer_addr.clone())).await {
        Some(Ok(s)) => s,
        Some(Err(_)) => ProbeStatus::Unknown,
        None => ProbeStatus::Unknown,
    }
}

pub async fn check_probes(peer_addr: &SocketAddr) {
    // First pass, only check favorite ports
    for probe in get_probes() {
        if probe.is_prefered_port(peer_addr.port()) {
            if check_probe(&peer_addr, probe.as_ref()).await == ProbeStatus::Recognized {
                return;
            }
        }
    }

    // Second pass, only check non-favorite ports
    for probe in get_probes() {
        if !probe.is_prefered_port(peer_addr.port()) {
            if check_probe(&peer_addr, probe.as_ref()).await == ProbeStatus::Recognized {
                return;
            }
        }
    }
}
