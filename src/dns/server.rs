//! UDP and TCP server implementations for DNS

use std::sync::Arc;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::dns::buffer::{BytePacketBuffer, PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};
use crate::dns::context::ServerContext;
use crate::dns::netutil::{read_packet_length, write_packet_length};
use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode};
use crate::dns::resolve::DnsResolver;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, ServerError>;

macro_rules! return_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(res) => res,
            Err(_) => {
                error!("{}", $message);
                return;
            }
        }
    };
}

macro_rules! ignore_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(_) => {}
            Err(_) => {
                error!("{}", $message);
                return;
            }
        };
    };
}

/// Common trait for DNS servers
#[async_trait]
pub trait DnsServer {
    /// Initialize the server and start listenening
    ///
    /// This method should _NOT_ block. Rather, servers are expected to spawn a new
    /// thread to handle requests and return immediately.
    async fn run_server(self) -> Result<()>;
}

/// Utility function for resolving domains referenced in for example CNAME or SRV
/// records. This usually spares the client from having to perform additional
/// lookups.
async fn resolve_cnames(
    lookup_list: &[DnsRecord],
    results: &mut Vec<DnsPacket>,
    resolver: &mut Box<dyn DnsResolver>,
    depth: u16,
) {
    if depth > 10 {
        return;
    }

    for ref rec in lookup_list {
        match **rec {
            DnsRecord::CNAME { ref host, .. } | DnsRecord::SRV { ref host, .. } => {
                if let Ok(result2) = resolver.resolve(host, QueryType::A, true).await {
                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2);

                    let feature = resolve_cnames(&new_unmatched, results, resolver, depth + 1);
                    Box::pin(feature).await;
                }
            }
            _ => {}
        }
    }
}

/// Perform the actual work for a query
///
/// Incoming requests are validated to make sure they are well formed and adhere
/// active resolver and a query will be performed. It will also resolve some
/// possible references within the query, such as CNAME hosts.
///
/// This function will always return a valid packet, even if the request could not
/// be performed, since we still want to send something back to the client.
pub async fn execute_query(context: Arc<ServerContext>, request: &DnsPacket) -> DnsPacket {
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_available = context.allow_recursive;
    packet.header.response = true;

    if request.header.recursion_desired && !context.allow_recursive {
        packet.header.rescode = ResultCode::REFUSED;
    } else if request.questions.is_empty() {
        packet.header.rescode = ResultCode::FORMERR;
    } else {
        let mut results = Vec::new();

        debug!("Executing query: {:?}", request);

        let question = &request.questions[0];
        packet.questions.push(question.clone());
        info!(domain = %question.name, "Processing question");

        let mut resolver = context.create_resolver(context.clone());
        info!("Created resolver");
        let rescode = match resolver
            .resolve(
                &question.name,
                question.qtype,
                request.header.recursion_desired,
            )
            .await
        {
            Ok(result) => {
                debug!(qtype = ?question.qtype, qname = %question.name, result = ?result, "Successfully resolved");

                info!(qtype = ?question.qtype, qname = %question.name, "Successfully resolved");
                let rescode = result.header.rescode;

                let unmatched = result.get_unresolved_cnames();
                results.push(result);

                resolve_cnames(&unmatched, &mut results, &mut resolver, 0).await;

                rescode
            }
            Err(err) => {
                warn!(qtype = ?question.qtype, qname = %question.name, error = ?err, "Failed to resolve");
                ResultCode::SERVFAIL
            }
        };

        packet.header.rescode = rescode;

        for result in results {
            for rec in result.answers {
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                packet.resources.push(rec);
            }
        }
    }

    packet
}

/// The UDP server
///
/// Accepts DNS queries through UDP, and uses the `ServerContext` to determine
/// how to service the request. Packets are read on a single thread, after which
/// a new thread is spawned to service the request asynchronously.
pub struct DnsUdpServer {
    context: Arc<ServerContext>,
}

impl DnsUdpServer {
    pub fn new(context: Arc<ServerContext>) -> DnsUdpServer {
        DnsUdpServer { context: context }
    }
}
#[async_trait]
impl DnsServer for DnsUdpServer {
    /// Launch the server
    ///
    /// This method takes ownership of the server, preventing the method from
    /// being called multiple times.
    async fn run_server(self) -> Result<()> {
        // Bind the socket

        info!(port = self.context.dns_port, "Listening on UDP port");
        let socket = Arc::new(UdpSocket::bind(("0.0.0.0", self.context.dns_port)).await?);

        tokio::spawn(async move {
            loop {
                let _ = self
                    .context
                    .statistics
                    .udp_query_count
                    .fetch_add(1, Ordering::Release);

                // Read a query packet
                let mut req_buffer = BytePacketBuffer::new();
                let (_, src) = match socket.recv_from(&mut req_buffer.buf).await {
                    Ok(x) => x,
                    Err(e) => {
                        error!(?e, "Failed to read from UDP socket");
                        continue;
                    }
                };

                let ctx = self.context.clone();
                // Spawn threads for handling requests
                let socket_clone = socket.clone();

                tokio::spawn(async move {
                    // Parse it
                    if let Ok(request) = DnsPacket::from_buffer(&mut req_buffer).await {
                        let mut size_limit = 512;

                        // Check for EDNS
                        if request.resources.len() == 1 {
                            if let DnsRecord::OPT { packet_len, .. } = request.resources[0] {
                                size_limit = packet_len as usize;
                            }
                        }

                        // Create a response buffer, and ask the context for an appropriate
                        // resolver
                        let mut res_buffer = VectorPacketBuffer::new();

                        let mut packet = execute_query(ctx, &request).await;
                        let _ = packet.write(&mut res_buffer, size_limit);

                        // Fire off the response
                        let len = res_buffer.pos();
                        let data = return_or_report!(
                            res_buffer.get_range(0, len).await,
                            "Failed to get buffer data"
                        );
                        ignore_or_report!(
                            socket_clone.send_to(data, src).await,
                            "Failed to send response packet"
                        );
                    } else {
                        warn!("Failed to parse UDP query packet");
                    }
                });
            }
        });
        Ok(())
    }
}

/// TCP DNS server
pub struct DnsTcpServer {
    context: Arc<ServerContext>,
}

impl DnsTcpServer {
    pub fn new(context: Arc<ServerContext>) -> DnsTcpServer {
        DnsTcpServer { context }
    }
}

async fn handle_tcp_stream(context: Arc<ServerContext>, mut stream: TcpStream) {
    // Read and parse
    if read_packet_length(&mut stream).await.is_err() {
        error!("Failed to read query packet length");
        return;
    }

    let request = {
        let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
        match DnsPacket::from_buffer(&mut stream_buffer).await {
            Ok(pkt) => pkt,
            Err(_) => {
                error!("Failed to read query packet");
                return;
            }
        }
    };

    let mut res_buffer = VectorPacketBuffer::new();

    let mut packet = execute_query(context.clone(), &request).await;
    if packet.write(&mut res_buffer, 0xFFFF).is_err() {
        error!("Failed to write packet to buffer");
        return;
    }

    let len = res_buffer.pos();
    if write_packet_length(&mut stream, len).await.is_err() {
        error!("Failed to write packet size");
        return;
    }

    let data = match res_buffer.get_range(0, len).await {
        Ok(d) => d,
        Err(_) => {
            error!("Failed to get packet data");
            return;
        }
    };

    if stream.write(data).await.is_err() {
        error!("Failed to write response packet");
    }

    let _ = stream.shutdown().await;
}

#[async_trait]
impl DnsServer for DnsTcpServer {
    async fn run_server(self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.context.dns_port)).await?;

        info!(port = self.context.dns_port, "Listening on TCP port");

        // Limit concurrent handlers to avoid resource exhaustion (configurable)
        let limit = self.context.tcp_concurrency_limit;
        let sem = Arc::new(Semaphore::new(limit));
        let context = self.context.clone();

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        error!(?e, "Failed to accept TCP connection");
                        continue;
                    }
                };

                let permit = sem.clone().acquire_owned().await.unwrap();
                let ctx = context.clone();

                tokio::spawn(async move {
                    // hold permit for duration of task
                    let _permit = permit;
                    let _ = ctx
                        .statistics
                        .tcp_query_count
                        .fetch_add(1, Ordering::Release);
                    handle_tcp_stream(ctx, stream).await;
                });
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use crate::dns::protocol::{
        DnsPacket, DnsQuestion, DnsRecord, QueryType, ResultCode, TransientTtl,
    };

    use super::*;

    use crate::dns::context::ResolveStrategy;
    use crate::dns::context::tests::create_test_context;

    fn build_query(qname: &str, qtype: QueryType) -> DnsPacket {
        let mut query_packet = DnsPacket::new();
        query_packet.header.recursion_desired = true;

        query_packet
            .questions
            .push(DnsQuestion::new(qname.into(), qtype));

        query_packet
    }

    #[tokio::test]
    async fn test_execute_query() {
        // Construct a context to execute some queries successfully
        let mut context = create_test_context(Box::new(|qname, qtype, _, _| {
            let mut packet = DnsPacket::new();

            if qname == "google.com" {
                packet.answers.push(DnsRecord::A {
                    domain: "google.com".to_string(),
                    addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else if qname == "www.facebook.com" && qtype == QueryType::CNAME {
                packet.answers.push(DnsRecord::CNAME {
                    domain: "www.facebook.com".to_string(),
                    host: "cdn.facebook.com".to_string(),
                    ttl: TransientTtl(3600),
                });
                packet.answers.push(DnsRecord::A {
                    domain: "cdn.facebook.com".to_string(),
                    addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else if qname == "www.microsoft.com" && qtype == QueryType::CNAME {
                packet.answers.push(DnsRecord::CNAME {
                    domain: "www.microsoft.com".to_string(),
                    host: "cdn.microsoft.com".to_string(),
                    ttl: TransientTtl(3600),
                });
            } else if qname == "cdn.microsoft.com" && qtype == QueryType::A {
                packet.answers.push(DnsRecord::A {
                    domain: "cdn.microsoft.com".to_string(),
                    addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else {
                packet.header.rescode = ResultCode::NXDOMAIN;
            }

            Ok(packet)
        }));

        match Arc::get_mut(&mut context) {
            Some(ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                    host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port: 53,
                };
            }
            None => panic!(),
        }

        // A successful resolve
        {
            let res =
                execute_query(context.clone(), &build_query("google.com", QueryType::A)).await;
            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                }
                _ => panic!(),
            }
        };

        // A successful resolve, that also resolves a CNAME without recursive lookup
        {
            let res = execute_query(
                context.clone(),
                &build_query("www.facebook.com", QueryType::CNAME),
            )
            .await;
            assert_eq!(2, res.answers.len());

            match res.answers[0] {
                DnsRecord::CNAME { ref domain, .. } => {
                    assert_eq!("www.facebook.com", domain);
                }
                _ => panic!(),
            }

            match res.answers[1] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("cdn.facebook.com", domain);
                }
                _ => panic!(),
            }
        };

        // A successful resolve, that also resolves a CNAME through recursive lookup
        {
            let res = execute_query(
                context.clone(),
                &build_query("www.microsoft.com", QueryType::CNAME),
            )
            .await;
            assert_eq!(2, res.answers.len());

            match res.answers[0] {
                DnsRecord::CNAME { ref domain, .. } => {
                    assert_eq!("www.microsoft.com", domain);
                }
                _ => panic!(),
            }

            match res.answers[1] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("cdn.microsoft.com", domain);
                }
                _ => panic!(),
            }
        };

        // An unsuccessful resolve, but without any error
        {
            let res = execute_query(context.clone(), &build_query("yahoo.com", QueryType::A)).await;
            assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };

        // Disable recursive resolves to generate a failure
        match Arc::get_mut(&mut context) {
            Some(ctx) => {
                ctx.allow_recursive = false;
            }
            None => panic!(),
        }

        // This should generate an error code, since recursive resolves are
        // no longer allowed
        {
            let res = execute_query(context.clone(), &build_query("yahoo.com", QueryType::A)).await;
            assert_eq!(ResultCode::REFUSED, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };

        // Send a query without a question, which should fail with an error code
        {
            let query_packet = DnsPacket::new();
            let res = execute_query(context.clone(), &query_packet).await;
            assert_eq!(ResultCode::FORMERR, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };

        // Now construct a context where the dns client will return a failure
        let mut context2 = create_test_context(Box::new(|_, _, _, _| {
            Err(crate::dns::client::ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Fail",
            )))
        }));

        match Arc::get_mut(&mut context2) {
            Some(ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                    host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port: 53,
                };
            }
            None => panic!(),
        }

        // We expect this to set the server failure rescode
        {
            let res =
                execute_query(context2.clone(), &build_query("yahoo.com", QueryType::A)).await;
            assert_eq!(ResultCode::SERVFAIL, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };
    }
}
