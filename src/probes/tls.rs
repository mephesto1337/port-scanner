use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Arc;

use super::{Probe, ProbeCheckFuture, ProbeStatus};

use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::{
        self,
        client::{ServerCertVerified, ServerCertVerifier},
        Certificate, ServerName,
    },
    TlsConnector,
};

pub struct TlsProbe;

struct YoloServerCertVerifier;

impl ServerCertVerifier for YoloServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = match x509_parser::parse_x509_certificate(end_entity.0.as_slice()) {
            Ok((_rest, value)) => value,
            Err(e) => {
                eprintln!("Got error: {}", e);
                return Ok(rustls::client::ServerCertVerified::assertion());
            }
        };
        println!("      - issuer : {}", cert.issuer());
        println!("      - subject: {}", cert.subject());
        println!(
            "      - dates  : between {} and {} ({})",
            cert.validity().not_before.to_string(),
            cert.validity().not_after.to_string(),
            if cert.validity().is_valid() {
                "valid"
            } else {
                "invalid"
            }
        );
        return Ok(rustls::client::ServerCertVerified::assertion());
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
            let config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(YoloServerCertVerifier))
                .with_no_client_auth();

            let connector: TlsConnector = Arc::new(config).into();
            let stream = TcpStream::connect(&peer_addr).await?;
            Ok(
                match connector
                    .connect(
                        rustls::ServerName::try_from("test-name.tld").unwrap(),
                        stream,
                    )
                    .await
                {
                    Ok(_) => ProbeStatus::Recognized,
                    Err(_) => ProbeStatus::Unknown,
                },
            )
        })
    }
}
