use clap::Parser;
use dns::{
    context::{ResolveStrategy, ServerContext},
    handle_query,
    protocol::{DnsRecord, TransientTtl},
    server::{DnsServer, DnsTcpServer, DnsUdpServer},
};
use tokio::time::interval;
use tracing::{info, error, warn, debug};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, UdpSocket},
    sync::Arc,
    time::Duration,
};

mod dns;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    forward: String,

    #[arg(short, long)]
    authority: bool,

    #[arg(short, long, default_value_t = 5353)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing for structured logging
    tracing_subscriber::fmt::init();

    info!("Starting my-cli");

    // let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // loop {
    //     match handle_query(&socket).await {
    //         Ok(_) => {}
    //         Err(e) => eprintln!("An error occurred: {}", e),
    //     }
    // }

    let args = Args::parse();
    let mut context = Arc::new(ServerContext::new().await);

    if let Some(ctx) = Arc::get_mut(&mut context) {
        let mut index_rootservers = true;
        match args.forward.parse::<Ipv4Addr>().ok() {
                Some(ip) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                    host: IpAddr::V4(ip),
                    port: 53,
                };
                index_rootservers = false;
                    info!(%ip, "Running as forwarder");
            }
            None => {
                    error!("Forward parameter must be a valid Ipv4 address");
                return Ok(());
            }
        }

        if args.authority {
            ctx.allow_recursive = false;
        }

        ctx.dns_port = args.port;

        match ctx.initialize().await {
            Ok(_) => {
                info!("Server initialized successfully");
            }
            Err(e) => {
                error!(?e, "Server failed to initialize");
                return Ok(());
            }
        }

        if index_rootservers {
            let _ = ctx.cache.store(&get_rootservers());
        }
    };

    // Start DNS servers
    if context.enable_udp {
        let udp_server = DnsUdpServer::new(context.clone());
        if let Err(e) = udp_server.run_server().await {
            error!(?e, "Failed to bind UDP listener");
        }
    };

    if context.enable_tcp {
        let tcp_server = DnsTcpServer::new(context.clone());
        if let Err(e) = tcp_server.run_server().await {
            error!(?e, "Failed to bind TCP listener");
        }
    };

    info!(port = context.dns_port, "Listening on port");

    let mut interval = interval(Duration::from_mins(10));

    loop {
        interval.tick().await;
        debug!("10 minutes passed");
    }

    // Ok(())
}

fn get_rootservers() -> Vec<DnsRecord> {
    let mut rootservers = Vec::new();

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "a.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "a.root-servers.net".to_string(),
        addr: "198.41.0.4".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "a.root-servers.net".to_string(),
        addr: "2001:503:ba3e::2:30".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "b.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "b.root-servers.net".to_string(),
        addr: "192.228.79.201".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "b.root-servers.net".to_string(),
        addr: "2001:500:84::b".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "c.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "c.root-servers.net".to_string(),
        addr: "192.33.4.12".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "c.root-servers.net".to_string(),
        addr: "2001:500:2::c".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "d.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "d.root-servers.net".to_string(),
        addr: "199.7.91.13".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "d.root-servers.net".to_string(),
        addr: "2001:500:2d::d".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "e.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "e.root-servers.net".to_string(),
        addr: "192.203.230.10".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "f.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "f.root-servers.net".to_string(),
        addr: "192.5.5.241".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "f.root-servers.net".to_string(),
        addr: "2001:500:2f::f".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "g.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "g.root-servers.net".to_string(),
        addr: "192.112.36.4".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "h.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "h.root-servers.net".to_string(),
        addr: "198.97.190.53".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "h.root-servers.net".to_string(),
        addr: "2001:500:1::53".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "i.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "i.root-servers.net".to_string(),
        addr: "192.36.148.17".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "i.root-servers.net".to_string(),
        addr: "2001:7fe::53".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "j.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "j.root-servers.net".to_string(),
        addr: "192.58.128.30".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "j.root-servers.net".to_string(),
        addr: "2001:503:c27::2:30".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "k.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "k.root-servers.net".to_string(),
        addr: "193.0.14.129".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "k.root-servers.net".to_string(),
        addr: "2001:7fd::1".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "l.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "l.root-servers.net".to_string(),
        addr: "199.7.83.42".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "l.root-servers.net".to_string(),
        addr: "2001:500:3::42".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers.push(DnsRecord::NS {
        domain: "".to_string(),
        host: "m.root-servers.net".to_string(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::A {
        domain: "m.root-servers.net".to_string(),
        addr: "202.12.27.33".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });
    rootservers.push(DnsRecord::AAAA {
        domain: "m.root-servers.net".to_string(),
        addr: "2001:dc3::35".parse().unwrap(),
        ttl: TransientTtl(3600000),
    });

    rootservers
}
