use std::io;
use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::{Probe, ProbeStatus};

pub struct HttpProbe;

impl HttpProbe {
    fn search_interesting_headers(&self, headers: &str) {
        const INTERESTING_HEADERS: [&'static str; 2] = ["Server: ", "X-Powered-By: "];
        for interesting_header in INTERESTING_HEADERS.iter() {
            if let Some(start_index) = headers.find(interesting_header) {
                let start = start_index + interesting_header.len();
                let end_index = start
                    + headers[start..]
                        .find("\r\n")
                        .expect("\\r\\n  should be present");
                println!("      - {}", &headers[start_index..end_index]);
            }
        }
    }
}

#[async_trait::async_trait]
impl Probe for HttpProbe {
    fn name(&self) -> &'static str {
        "http"
    }

    fn is_prefered_port(&self, port: u16) -> bool {
        match port {
            80 | 81 | 3128 | 8000 | 8080 => true,
            _ => false,
        }
    }

    async fn check(&self, peer_addr: SocketAddr) -> io::Result<ProbeStatus> {
        const HTTP_PREFIX: &'static [u8] = b"HTTP/1.1 ";

        let mut stream = TcpStream::connect(&peer_addr).await?;
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: {}\r\nConnection: Close\r\n\r\n",
            peer_addr.ip(),
            peer_addr.port(),
            unsafe { crate::defaults::USER_AGENT }
        );

        stream.write_all(request.as_bytes()).await?;
        let mut buffer = [0u8; 8192];

        let size = stream.read(&mut buffer[..]).await?;
        let data = &buffer[..size];

        if data.len() <= HTTP_PREFIX.len() + 10 {
            return Ok(ProbeStatus::Unknown);
        }
        if !data.starts_with(HTTP_PREFIX) {
            return Ok(ProbeStatus::Unknown);
        }
        if !&data[HTTP_PREFIX.len()..][..3]
            .iter()
            .all(|c| c.is_ascii_digit())
        {
            return Ok(ProbeStatus::Unknown);
        }
        let needle = &b"\r\n\r\n"[..];
        let index = match data
            .windows(needle.len())
            .position(|window| window == needle)
        {
            Some(index) => index,
            None => {
                return Ok(ProbeStatus::Unknown);
            }
        };
        let headers = match std::str::from_utf8(&data[..(index + needle.len())]) {
            Ok(headers) => headers,
            Err(_) => {
                return Ok(ProbeStatus::Unknown);
            }
        };

        println!("      Found protocol HTTP");
        println!("      Interesting headers:");
        self.search_interesting_headers(headers);

        Ok(ProbeStatus::Recognized)
    }
}
