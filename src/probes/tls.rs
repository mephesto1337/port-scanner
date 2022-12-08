use std::net::SocketAddr;

use super::{Probe, ProbeCheckFuture, ProbeStatus};

use tokio::net::TcpStream;

use tokio_native_tls::{native_tls::TlsConnector as NativeTlsConnector, TlsConnector};

pub struct TlsProbe;

impl TlsProbe {
    fn show_cert(der: &[u8]) {
        let cert = match x509_parser::parse_x509_certificate(der) {
            Ok((_rest, value)) => value,
            Err(_) => {
                return;
            }
        };
        let time_format = time::format_description::parse(
            "[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour sign:mandatory]:[offset_minute]",
        )
        .unwrap();
        println!("      - issuer : {}", cert.issuer());
        println!("      - subject: {}", cert.subject());
        println!(
            "      - dates  : between {} and {} ({})",
            cert.validity()
                .not_before
                .to_datetime()
                .format(&time_format)
                .unwrap(),
            cert.validity()
                .not_after
                .to_datetime()
                .format(&time_format)
                .unwrap(),
            if cert.validity().is_valid() {
                "valid"
            } else {
                "invalid"
            }
        );
    }
}

impl Probe for TlsProbe {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn is_prefered_port(&self, port: u16) -> bool {
        match port {
            443 | 465 | 636 | 993 | 995 | 8443 => true,
            _ => false,
        }
    }

    fn check(&self, peer_addr: SocketAddr) -> ProbeCheckFuture {
        Box::pin(async move {
            let connector: TlsConnector = NativeTlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
                .expect("Cannot build TLS connector")
                .into();

            let stream = TcpStream::connect(&peer_addr).await?;
            Ok(match connector.connect("localhost", stream).await {
                Ok(stream) => {
                    if let Some(cert) = stream.get_ref().peer_certificate().ok().flatten() {
                        if let Ok(der) = cert.to_der() {
                            Self::show_cert(&der[..]);
                        }
                    }
                    ProbeStatus::Recognized
                }
                Err(_) => ProbeStatus::Unknown,
            })
        })
    }
}
