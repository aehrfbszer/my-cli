use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::{Sender, channel},
    },
    time::Duration,
};

use chrono::{DateTime, Local};
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    time::sleep,
};

use super::{
    buffer::{BytePacketBuffer, PacketBuffer, PacketBufferOpError, StreamPacketBuffer},
    netutil::{read_packet_length, write_packet_length},
    protocol::{DnsPacket, DnsQuestion, QueryType},
};

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    Protocol(#[from] PacketBufferOpError),
    #[error("io err")]
    Io(#[from] std::io::Error),
    #[error("PoisonedLock")]
    PoisonedLock,
    #[error("LookupFailed")]
    LookupFailed,
    #[error("TimeOut")]
    TimeOut,
}

type Result<T> = std::result::Result<T, ClientError>;

pub trait DnsClient {
    fn get_sent_count(&self) -> usize;
    fn get_failed_count(&self) -> usize;

    async fn run(&self) -> Result<()>;
    async fn send_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket>;
}

/// The UDP client
///
/// This includes a fair bit of synchronization due to the stateless nature of UDP.
/// When many queries are sent in parallell, the response packets can come back
/// in any order. For that reason, we fire off replies on the sending thread, but
/// handle replies on a single thread. A channel is created for every response,
/// and the caller will block on the channel until the a response is received.
pub struct DnsNetworkClient {
    total_sent: AtomicUsize,
    total_failed: AtomicUsize,

    /// Counter for assigning packet ids
    seq: AtomicUsize,

    /// The listener socket
    socket: Arc<Mutex<UdpSocket>>,

    /// Queries in progress
    pending_queries: Arc<Mutex<Vec<PendingQuery>>>,
}

/// A query in progress. This struct holds the `id` if the request, and a channel
/// endpoint for returning a response back to the thread from which the query
/// was posed.
struct PendingQuery {
    seq: u16,
    timestamp: DateTime<Local>,
    tx: Sender<Option<DnsPacket>>,
}

impl DnsNetworkClient {
    pub async fn new(port: u16) -> DnsNetworkClient {
        DnsNetworkClient {
            total_sent: AtomicUsize::new(0),
            total_failed: AtomicUsize::new(0),
            seq: AtomicUsize::new(0),
            socket: Arc::new(Mutex::new(
                UdpSocket::bind(("0.0.0.0", port)).await.unwrap(),
            )),
            pending_queries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Send a DNS query using TCP transport
    ///
    /// This is much simpler than using UDP, since the kernel will take care of
    /// packet ordering, connection state, timeouts etc.
    pub async fn send_tcp_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let _ = self.total_sent.fetch_add(1, Ordering::Release);

        // Prepare request
        let mut packet = DnsPacket::new();

        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        if packet.header.id + 1 == 0xFFFF {
            let _ = self
                .seq
                .compare_exchange_weak(0xffff, 0, Ordering::SeqCst, Ordering::SeqCst);
        }

        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;

        packet.questions.push(DnsQuestion::new(qname.into(), qtype));

        // Send query
        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer, 0xFFFF)?;

        let mut socket = TcpStream::connect(server).await?;

        write_packet_length(&mut socket, req_buffer.pos()).await?;
        socket.write(&req_buffer.buf[0..req_buffer.pos]).await?;
        socket.flush().await?;

        let _ = read_packet_length(&mut socket).await?;

        let mut stream_buffer = StreamPacketBuffer::new(&mut socket);
        let packet = DnsPacket::from_buffer(&mut stream_buffer).await?;

        Ok(packet)
    }

    /// Send a DNS query using UDP transport
    ///
    /// This will construct a query packet, and fire it off to the specified server.
    /// The query is sent from the callee thread, but responses are read on a
    /// worker thread, and returned to this thread through a channel. Thus this
    /// method is thread safe, and can be used from any number of threads in
    /// parallell.
    pub async fn send_udp_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let _ = self.total_sent.fetch_add(1, Ordering::Release);

        // Prepare request
        let mut packet = DnsPacket::new();

        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        if packet.header.id + 1 == 0xFFFF {
            let _ = self
                .seq
                .compare_exchange(0xffff, 0, Ordering::SeqCst, Ordering::SeqCst);
        }

        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;

        packet
            .questions
            .push(DnsQuestion::new(qname.to_string(), qtype));

        // Create a return channel, and add a `PendingQuery` to the list of lookups
        // in progress
        let (tx, rx) = channel();
        {
            let mut pending_queries = self
                .pending_queries
                .lock()
                .map_err(|_| ClientError::PoisonedLock)?;
            pending_queries.push(PendingQuery {
                seq: packet.header.id,
                timestamp: Local::now(),
                tx: tx,
            });
        }

        // Send query
        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer, 512)?;
        self.socket
            .lock()
            .unwrap()
            .send_to(&req_buffer.buf[0..req_buffer.pos], server)
            .await?;

        // Wait for response
        match rx.recv() {
            Ok(Some(qr)) => Ok(qr),
            Ok(None) => {
                let _ = self.total_failed.fetch_add(1, Ordering::Release);
                Err(ClientError::TimeOut)
            }
            Err(_) => {
                let _ = self.total_failed.fetch_add(1, Ordering::Release);
                Err(ClientError::LookupFailed)
            }
        }
    }
}

impl DnsClient for DnsNetworkClient {
    fn get_sent_count(&self) -> usize {
        self.total_sent.load(Ordering::Acquire)
    }

    fn get_failed_count(&self) -> usize {
        self.total_failed.load(Ordering::Acquire)
    }

    /// The run method launches a worker thread. Unless this thread is running, no
    /// responses will ever be generated, and clients will just block indefinitely.
    async fn run(&self) -> Result<()> {
        // Start the thread for handling incoming responses
        {
            let pending_queries_lock = self.pending_queries.clone();

            tokio::spawn(async move {
                let timeout = Duration::from_secs(1);
                loop {
                    if let Ok(mut pending_queries) = pending_queries_lock.lock() {
                        let mut finished_queries = Vec::new();
                        for (i, pending_query) in pending_queries.iter().enumerate() {
                            let expires = pending_query.timestamp + timeout;
                            if expires < Local::now() {
                                let _ = pending_query.tx.send(None);
                                finished_queries.push(i);
                            }
                        }

                        // Remove `PendingQuery` objects from the list, in reverse order
                        for idx in finished_queries.iter().rev() {
                            pending_queries.remove(*idx);
                        }
                    }

                    sleep(Duration::from_millis(100)).await;
                }
            });
        }

        let pending_queries_lock = self.pending_queries.clone();
        let socket_copy = self.socket.clone();

        tokio::spawn(async move {
            let mut res_buffer = BytePacketBuffer::new();
            loop {
                let ss = socket_copy.lock().unwrap();
                if let Ok(_) = ss.recv_from(&mut res_buffer.buf).await {
                    match DnsPacket::from_buffer(&mut res_buffer).await {
                        Ok(packet) => {
                            // Acquire a lock on the pending_queries list, and search for a
                            // matching PendingQuery to which to deliver the response.
                            if let Ok(mut pending_queries) = pending_queries_lock.lock() {
                                let mut matched_query = None;
                                for (i, pending_query) in pending_queries.iter().enumerate() {
                                    if pending_query.seq == packet.header.id {
                                        // Matching query found, send the response
                                        let _ = pending_query.tx.send(Some(packet.clone()));

                                        // Mark this index for removal from list
                                        matched_query = Some(i);

                                        break;
                                    }
                                }

                                if let Some(idx) = matched_query {
                                    pending_queries.remove(idx);
                                } else {
                                    println!("Discarding response for: {:?}", packet.questions[0]);
                                }
                            }
                        }
                        Err(err) => {
                            println!(
                                "DnsNetworkClient failed to parse packet with error: {}",
                                err
                            );
                            continue;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn send_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let packet = self.send_udp_query(qname, qtype, server, recursive).await?;
        if !packet.header.truncated_message {
            return Ok(packet);
        }

        println!("Truncated response - resending as TCP");
        self.send_tcp_query(qname, qtype, server, recursive).await
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType};

    pub type StubCallback = dyn Fn(&str, QueryType, (&str, u16), bool) -> Result<DnsPacket>;

    pub struct DnsStubClient {
        callback: Box<StubCallback>,
    }

    impl<'a> DnsStubClient {
        pub fn new(callback: Box<StubCallback>) -> DnsStubClient {
            DnsStubClient { callback: callback }
        }
    }

    unsafe impl Send for DnsStubClient {}
    unsafe impl Sync for DnsStubClient {}

    impl DnsClient for DnsStubClient {
        fn get_sent_count(&self) -> usize {
            0
        }

        fn get_failed_count(&self) -> usize {
            0
        }

        async fn run(&self) -> Result<()> {
            Ok(())
        }

        async fn send_query(
            &self,
            qname: &str,
            qtype: QueryType,
            server: (&str, u16),
            recursive: bool,
        ) -> Result<DnsPacket> {
            (self.callback)(qname, qtype, server, recursive)
        }
    }

    #[tokio::test]
    pub async fn test_udp_client() {
        let client = DnsNetworkClient::new(31456).await;
        client.run().await.unwrap();

        let res = client
            .send_udp_query("google.com", QueryType::A, ("8.8.8.8", 53), true)
            .await
            .unwrap();

        assert_eq!(res.questions[0].name, "google.com");
        assert!(res.answers.len() > 0);

        match res.answers[0] {
            DnsRecord::A { ref domain, .. } => {
                assert_eq!("google.com", domain);
            }
            _ => panic!(),
        }
    }

    #[tokio::test]
    pub async fn test_tcp_client() {
        let client = DnsNetworkClient::new(31457).await;
        let res = client
            .send_tcp_query("google.com", QueryType::A, ("8.8.8.8", 53), true)
            .await
            .unwrap();

        assert_eq!(res.questions[0].name, "google.com");
        assert!(res.answers.len() > 0);

        match res.answers[0] {
            DnsRecord::A { ref domain, .. } => {
                assert_eq!("google.com", domain);
            }
            _ => panic!(),
        }
    }
}
