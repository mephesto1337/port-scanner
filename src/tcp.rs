use std::io;
use std::net::IpAddr;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::defaults::{CONNECT_TIMEOUT, READ_TIMEOUT};
use crate::port::{Port, PortStatus, PortsList};
use crate::utils::{run_with_timeout, Semaphore};

#[derive(Debug)]
pub struct TcpScanner {
    ports: PortsList,
}

impl TcpScanner {
    pub fn new(ports: PortsList) -> Self {
        Self { ports }
    }

    pub async fn scan(&self, ip: IpAddr) -> io::Result<Vec<Port>> {
        // TODO: shuffle array
        let semaphore = Semaphore::new(512);
        let mut results = Vec::with_capacity(self.ports.len());

        for port in self.ports.iter() {
            let ticket = semaphore.acquire().await;
            results.push(tokio::spawn(async move {
                let port = test_port(ip.clone(), port).await;
                drop(ticket);
                port
            }));
        }
        let mut results = futures::future::join_all(results).await;

        Ok(results.drain(..).filter_map(|j| j.ok()).collect::<Vec<_>>())
    }
}

async fn test_port(ip: IpAddr, port: u16) -> Port {
    let connect_timeout = unsafe { CONNECT_TIMEOUT };
    let read_timeout = unsafe { READ_TIMEOUT };

    let status = match run_with_timeout(connect_timeout, TcpStream::connect((ip, port))).await {
        Some(Ok(mut s)) => {
            let mut buf = Vec::with_capacity(1024);
            let banner = match run_with_timeout(read_timeout, s.read_buf(&mut buf)).await {
                Some(Ok(n)) if n > 0 => Some(buf),
                _ => None,
            };
            PortStatus::Opened { banner }
        }
        Some(Err(ref e)) => {
            if e.kind() == io::ErrorKind::ConnectionRefused {
                PortStatus::Closed
            } else {
                eprintln!("Got {} from {}:{}", e, &ip, port);
                PortStatus::Filtered
            }
        }
        None => PortStatus::Filtered,
    };

    Port { num: port, status }
}
