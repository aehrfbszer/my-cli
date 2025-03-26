//! UDP and TCP server implementations for DNS

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::{Sender, channel};

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
                println!($message);
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
                println!($message);
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

                    resolve_cnames(&new_unmatched, results, resolver, depth + 1);
                }
            }
            _ => {}
        }
    }
}

/// Perform the actual work for a query
///
/// Incoming requests are validated to make sure they are well formed and adhere
/// to the server configuration. If so, the request will be passed on to the
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

        let question = &request.questions[0];
        packet.questions.push(question.clone());

        let mut resolver = context.create_resolver(context.clone());
        let rescode = match resolver
            .resolve(
                &question.name,
                question.qtype,
                request.header.recursion_desired,
            )
            .await
        {
            Ok(result) => {
                let rescode = result.header.rescode;

                let unmatched = result.get_unresolved_cnames();
                results.push(result);

                resolve_cnames(&unmatched, &mut results, &mut resolver, 0).await;

                rescode
            }
            Err(err) => {
                println!(
                    "Failed to resolve {:?} {}: {:?}",
                    question.qtype, question.name, err
                );
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
    request_queue: Arc<Mutex<VecDeque<(SocketAddr, DnsPacket)>>>,
    request_cond: Arc<Condvar>,
}

impl DnsUdpServer {
    pub fn new(context: Arc<ServerContext>) -> DnsUdpServer {
        DnsUdpServer {
            context: context,
            request_queue: Arc::new(Mutex::new(VecDeque::new())),
            request_cond: Arc::new(Condvar::new()),
        }
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

        println!("Listening on UDP port {}", self.context.dns_port);

        let socket = Arc::new(UdpSocket::bind(("0.0.0.0", self.context.dns_port)).await?);

        // Spawn threads for handling requests
        let socket_clone = socket.clone();

        let context = self.context.clone();
        let request_cond = self.request_cond.clone();
        let request_queue = self.request_queue.clone();

        tokio::spawn(async move {
            loop {
                // Acquire lock, and wait on the condition until data is
                // available. Then proceed with popping an entry of the queue.
                let (src, request) = match request_queue
                    .lock()
                    .ok()
                    .and_then(|x| request_cond.wait(x).ok())
                    .and_then(|mut x| x.pop_front())
                {
                    Some(x) => {
                        println!("Received query: {:?}", x.1);
                        x
                    }
                    None => {
                        println!("Not expected to happen!");
                        continue;
                    }
                };

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

                let mut packet = execute_query(context.clone(), &request).await;
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
            }
        });

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
                        println!("Failed to read from UDP socket: {:?}", e);
                        continue;
                    }
                };

                // Parse it
                let request = match DnsPacket::from_buffer(&mut req_buffer).await {
                    Ok(x) => x,
                    Err(e) => {
                        println!("Failed to parse UDP query packet: {:?}", e);
                        continue;
                    }
                };

                // Acquire lock, add request to queue, and notify waiting threads
                // using the condition.
                match self.request_queue.lock() {
                    Ok(mut queue) => {
                        queue.push_back((src, request));
                        self.request_cond.notify_one();
                    }
                    Err(e) => {
                        println!("Failed to send UDP request for processing: {}", e);
                    }
                }
            }
        });
        Ok(())
    }
}

/// TCP DNS server
pub struct DnsTcpServer {
    context: Arc<ServerContext>,
    sender: Option<Sender<TcpStream>>,
}

impl DnsTcpServer {
    pub fn new(context: Arc<ServerContext>) -> DnsTcpServer {
        DnsTcpServer {
            context: context,
            sender: None,
        }
    }
}
#[async_trait]
impl DnsServer for DnsTcpServer {
    async fn run_server(mut self) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.context.dns_port)).await?;

        // Spawn threads for handling requests, and create the channels
        let (tx, mut rx) = channel(100);
        self.sender = Some(tx);

        let context = self.context.clone();

        tokio::spawn(async move {
            while let Some(mut stream) = rx.recv().await {
                let _ = context
                    .statistics
                    .tcp_query_count
                    .fetch_add(1, Ordering::Release);

                // When DNS packets are sent over TCP, they're prefixed with a two byte
                // length. We don't really need to know the length in advance, so we
                // just move past it and continue reading as usual
                ignore_or_report!(
                    read_packet_length(&mut stream).await,
                    "Failed to read query packet length"
                );

                let request = {
                    let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
                    return_or_report!(
                        DnsPacket::from_buffer(&mut stream_buffer).await,
                        "Failed to read query packet"
                    )
                };

                let mut res_buffer = VectorPacketBuffer::new();

                let mut packet = execute_query(context.clone(), &request).await;
                ignore_or_report!(
                    packet.write(&mut res_buffer, 0xFFFF),
                    "Failed to write packet to buffer"
                );

                // As is the case for incoming queries, we need to send a 2 byte length
                // value before handing of the actual packet.
                let len = res_buffer.pos();
                ignore_or_report!(
                    write_packet_length(&mut stream, len).await,
                    "Failed to write packet size"
                );

                // Now we can go ahead and write the actual packet
                let data = return_or_report!(
                    res_buffer.get_range(0, len).await,
                    "Failed to get packet data"
                );

                ignore_or_report!(stream.write(data).await, "Failed to write response packet");

                ignore_or_report!(stream.shutdown().await, "Failed to shutdown socket");
            }
        });

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                // Hand it off to a worker thread
                if let Some(ref tx) = self.sender {
                    let tx1 = tx.clone();
                    tokio::spawn(async move {
                        let _ = tx1.send(stream).await;
                    });
                }
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
