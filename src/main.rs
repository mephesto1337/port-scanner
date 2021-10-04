use std::time::Duration;

use structopt::StructOpt;

mod defaults;
mod port;
mod tcp;

use defaults::*;

#[derive(Debug, StructOpt)]
#[structopt(name = "tcp-scanner", about = "TCP scanner in async Rust")]
struct Opt {
    /// Host to scan
    #[structopt(short = "H", long, parse(try_from_str))]
    host: std::net::IpAddr,

    /// Port range
    #[structopt(short, long)]
    port: Option<String>,

    /// Exclude theses ports
    #[structopt(short, long, parse(try_from_str))]
    exclude_ports: Vec<u16>,

    /// Hide filtered ports
    #[structopt(short, long)]
    hide_filtered: bool,

    /// Sets connect timeout (in milliseconds)
    #[structopt(short, long, parse(try_from_str), default_value = "5000")]
    connect_timeout: u64,

    /// Sets read timeout (in milliseconds) for banner
    #[structopt(short, long, parse(try_from_str), default_value = "2000")]
    read_timeout: u64,
}

#[tokio::main]
async fn main() {
    let opts = Opt::from_args();

    let ports_spec = opts.port.unwrap_or_default();
    let mut ports = port::PortsList::new();

    if ports_spec.is_empty() {
        ports.add_ports(&TOP_TCP_PORTS[..])
    } else {
        for ps in ports_spec.split(',') {
            match ps.split_once('-') {
                None => {
                    let port = ps.parse::<u16>().expect(&format!("Invalid port {:?}", ps));
                    ports.add_port(port);
                }
                Some((lower, "")) => {
                    let port = lower
                        .parse::<u16>()
                        .expect(&format!("Invalid port {:?}", lower));
                    for p in port..=65535 {
                        ports.add_port(p);
                    }
                }
                Some(("", upper)) => {
                    let port = upper
                        .parse::<u16>()
                        .expect(&format!("Invalid port {:?}", upper));
                    for p in 1..=port {
                        ports.add_port(p);
                    }
                }
                Some((lower, upper)) => {
                    let lower_port = lower
                        .parse::<u16>()
                        .expect(&format!("Invalid port {:?}", upper));
                    let upper_port = upper
                        .parse::<u16>()
                        .expect(&format!("Invalid port {:?}", upper));
                    for p in lower_port..=upper_port {
                        ports.add_port(p);
                    }
                }
            }
        }
    }

    ports.remove_ports(&opts.exclude_ports[..]);

    if opts.connect_timeout > 0 {
        CONNECT_TIMEOUT.set(Duration::from_millis(opts.connect_timeout));
    }
    if opts.read_timeout > 0 {
        READ_TIMEOUT.set(Duration::from_millis(opts.read_timeout));
    }

    eprintln!("Got {} ports to scan from {}", ports.len(), &opts.host);

    let scanner = tcp::TcpScanner::new(ports);
    let results = scanner.scan(opts.host).await.expect("Cannot scan IP");
    for p in &results {
        if p.status == port::PortStatus::Closed {
            continue;
        }
        if opts.hide_filtered && p.status == port::PortStatus::Filtered {
            continue;
        }
        println!("{}", p);
    }
}