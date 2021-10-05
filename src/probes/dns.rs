use std::{io::Write, net::SocketAddr};

use super::{Probe, ProbeStatus};

use trust_dns_proto::op::{Message, Query};
use trust_dns_proto::rr::RecordType;
use trust_dns_proto::serialize::binary::BinDecodable;

pub struct DnsProbe {
    id: u16,
}

impl DnsProbe {
    pub fn new() -> Self {
        Self { id: rand::random() }
    }
}

impl Probe for DnsProbe {
    fn get_request(&self, peer_addr: &SocketAddr, mut buffer: &mut [u8]) -> usize {
        let mut message = Message::new();
        message.set_id(self.id);

        let query = Query::query(peer_addr.ip().into(), RecordType::PTR);
        message.add_query(query);
        let bytes = message.to_vec().expect("Malformed DNS message");
        let size = (bytes.len() as u16).to_be_bytes();
        buffer.write_all(&size[..]).expect("Buffer too small?!");
        buffer.write_all(&bytes[..]).expect("Buffer too small?!");

        bytes.len() + 2
    }

    fn recognized(&self, data: &[u8]) -> ProbeStatus {
        if data.len() < 2 {
            return ProbeStatus::Unknown;
        }
        let size = u16::from_be_bytes([data[0], data[1]]);
        if data.len() < size as usize + 2 {
            eprintln!("Message truncated");
        }
        let message = match Message::from_bytes(&data[2..]) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("DNS: {}", e);
                return ProbeStatus::Unknown;
            }
        };
        if message.id() != self.id {
            eprintln!("Got answer with different ID");
        }
        if let Some(record) = message.answers().first() {
            println!(
                "      - PTR({}) = {}",
                record.name().to_utf8(),
                record.rdata().to_string()
            );
        } else {
            eprintln!("No answers");
        }
        ProbeStatus::Recognized
    }

    fn name(&self) -> &'static str {
        "dns"
    }

    fn is_prefered_port(&self, port: u16) -> bool {
        match port {
            53 | 5353 => true,
            _ => false,
        }
    }
}
