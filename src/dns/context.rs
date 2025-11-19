//! The `ServerContext in this thread holds the common state across the server

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use thiserror::Error;

use crate::dns::authority::Authority;
use crate::dns::cache::SynchronizedCache;
use crate::dns::client::{DnsClient, DnsNetworkClient};

use super::resolve::{DnsResolver, ForwardingDnsResolver, RecursiveDnsResolver};

#[derive(Debug, Error)]
pub enum ContextError {
    #[error(transparent)]
    Authority(#[from] crate::dns::authority::AuthorityError),
    #[error(transparent)]
    Client(#[from] crate::dns::client::ClientError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, ContextError>;

pub struct ServerStatistics {
    pub tcp_query_count: AtomicUsize,
    pub udp_query_count: AtomicUsize,
}

impl ServerStatistics {
    pub fn get_tcp_query_count(&self) -> usize {
        self.tcp_query_count.load(Ordering::Acquire)
    }

    pub fn get_udp_query_count(&self) -> usize {
        self.udp_query_count.load(Ordering::Acquire)
    }
}
#[derive(Clone)]
pub enum ResolveStrategy {
    Recursive,
    Forward { host: IpAddr, port: u16 },
}

pub struct ServerContext {
    pub authority: Authority,
    pub cache: SynchronizedCache,
    pub client: Box<dyn DnsClient>,
    pub dns_port: u16,
    pub api_port: u16,
    pub resolve_strategy: ResolveStrategy,
    pub allow_recursive: bool,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub enable_api: bool,
    pub statistics: ServerStatistics,
    pub zones_dir: &'static str,
}

impl ServerContext {
    pub async fn new() -> ServerContext {
        ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            client: Box::new(DnsNetworkClient::new(34255).await),
            dns_port: 5351,
            api_port: 5380,
            resolve_strategy: ResolveStrategy::Forward {
                host: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                port: 53,
            },
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: true,
            statistics: ServerStatistics {
                tcp_query_count: AtomicUsize::new(0),
                udp_query_count: AtomicUsize::new(0),
            },
            zones_dir: "zones",
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        // Create zones directory if it doesn't exist
        fs::create_dir_all(self.zones_dir)?;

        // Start UDP client thread

        // Load authority data
        // self.authority.load().await?;

        self.client.run().await?;
        Ok(())
    }

    pub fn create_resolver(&self, ptr: Arc<ServerContext>) -> Box<dyn DnsResolver> {
        match self.resolve_strategy {
            ResolveStrategy::Recursive => Box::new(RecursiveDnsResolver::new(ptr)),
            ResolveStrategy::Forward { host, port } => {
                Box::new(ForwardingDnsResolver::new(ptr, (host, port)))
            }
        }
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use crate::dns::authority::Authority;
    use crate::dns::cache::SynchronizedCache;

    use crate::dns::client::tests::{DnsStubClient, StubCallback};

    use super::*;

    pub fn create_test_context(callback: Box<StubCallback>) -> Arc<ServerContext> {
        Arc::new(ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            client: Box::new(DnsStubClient::new(callback)),
            dns_port: 53,
            api_port: 5380,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: true,
            statistics: ServerStatistics {
                tcp_query_count: AtomicUsize::new(0),
                udp_query_count: AtomicUsize::new(0),
            },
            zones_dir: "zones",
        })
    }
}
