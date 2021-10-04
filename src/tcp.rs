use std::io;
use std::net::IpAddr;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time;

use crate::defaults::{CONNECT_TIMEOUT, READ_TIMEOUT};
use crate::port::{Port, PortStatus, PortsList};

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
        let mut results = futures::future::join_all(
            self.ports
                .iter()
                .map(|p| tokio::spawn(test_port(ip.clone(), p))),
        )
        .await;

        Ok(results.drain(..).filter_map(|j| j.ok()).collect::<Vec<_>>())
    }
}

async fn run_with_timeout<O>(
    timeout: Duration,
    fut: impl std::future::Future<Output = O>,
) -> Option<O> {
    let sleep = time::sleep(timeout);
    tokio::pin!(sleep);

    tokio::select! {
        ready = fut => {
            Some(ready)
        }
        _ = &mut sleep => {
            None
        }
    }
}

async fn test_port(ip: IpAddr, port: u16) -> Port {
    let connect_timeout = CONNECT_TIMEOUT.get();
    let read_timeout = READ_TIMEOUT.get();

    let status = match run_with_timeout(connect_timeout, TcpStream::connect((ip, port))).await {
        Some(Ok(mut s)) => {
            let mut buf = Vec::with_capacity(1024);
            let got_banner = run_with_timeout(read_timeout, s.read_buf(&mut buf)).await;
            PortStatus::Opened {
                banner: got_banner.map(|_| buf),
            }
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
