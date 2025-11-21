//! resolver implementations implementing different strategies for answering
//! incoming queries

use std::net::IpAddr;
use std::sync::Arc;
use std::vec::Vec;

use async_trait::async_trait;
use thiserror::Error;
use tracing::{debug, info};

use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsPacket, QueryType, ResultCode};

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error(transparent)]
    Client(#[from] crate::dns::client::ClientError),
    #[error(transparent)]
    Cache(#[from] crate::dns::cache::CacheError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("No server found")]
    NoServerFound,
}

type Result<T> = std::result::Result<T, ResolveError>;

#[async_trait]
pub trait DnsResolver: Send + Sync {
    fn get_context(&self) -> Arc<ServerContext>;

    async fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket>;

    async fn resolve(
        &mut self,
        qname: &str,
        qtype: QueryType,
        recursive: bool,
    ) -> Result<DnsPacket> {
        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }

        let context = self.get_context();

        if let Some(qr) = context.authority.query(qname, qtype) {
            return Ok(qr);
        }

        if !recursive || !context.allow_recursive {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::REFUSED;
            return Ok(packet);
        }

        if let Some(qr) = context.cache.lookup(qname, qtype) {
            debug!(?qtype, qname = %qname, "Cache hit");
            return Ok(qr);
        }

        if qtype == QueryType::A || qtype == QueryType::AAAA {
            if let Some(qr) = context.cache.lookup(qname, QueryType::CNAME) {
                debug!(?qtype, qname = %qname, "CNAME Cache hit");
                return Ok(qr);
            }
        }

        debug!(?qtype, qname = %qname, "Cache miss, performing resolution");

        self.perform(qname, qtype).await
    }
}

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query
pub struct ForwardingDnsResolver {
    context: Arc<ServerContext>,
    server: (IpAddr, u16),
}

impl ForwardingDnsResolver {
    pub fn new(context: Arc<ServerContext>, server: (IpAddr, u16)) -> ForwardingDnsResolver {
        ForwardingDnsResolver { context, server }
    }
}

#[async_trait]
impl DnsResolver for ForwardingDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    async fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        let (host, port) = self.server;
        tracing::debug!(?qtype, qname = %qname, host = %host, port = %port, "Forwarding query to upstream");
        let result = self
            .context
            .client
            .send_query(qname, qtype, (host, port), true)
            .await?;

        tracing::debug!(?qtype, qname = %qname, result = ?result, "Received forwarded response");

        self.context.cache.store(&result.answers)?;

        Ok(result)
    }
}

/// A Recursive DNS resolver
///
/// This resolver can answer any request using the root servers of the internet
pub struct RecursiveDnsResolver {
    context: Arc<ServerContext>,
}

impl RecursiveDnsResolver {
    pub fn new(context: Arc<ServerContext>) -> RecursiveDnsResolver {
        RecursiveDnsResolver { context: context }
    }
}

#[async_trait]
impl DnsResolver for RecursiveDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    async fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        // Find the closest name server by splitting the label and progessively
        // moving towards the root servers. I.e. check "google.com", then "com",
        // and finally "".

        info!(?qtype, qname = %qname, "Searching for closest nameserver in cache");

        let mut tentative_ns = None;

        let labels = qname.split('.').collect::<Vec<&str>>();

        debug!(?qtype, qname = %qname, labels = ?labels, "Split qname into labels");
        for lbl_idx in 0..=labels.len() {
            let domain = labels[lbl_idx..].join(".");

            debug!(?qtype, qname = %qname, domain = %domain, "Looking for NS record for domain");

            match self
                .context
                .cache
                .lookup(&domain, QueryType::NS)
                .and_then(|qr| qr.get_unresolved_ns(&domain))
                .and_then(|ns| self.context.cache.lookup(&ns, QueryType::A))
                .and_then(|qr| qr.get_random_ip())
            {
                Some(addr) => {
                    tentative_ns = Some(addr);
                    break;
                }
                None => continue,
            }
        }
        info!(?qtype, qname = %qname, tentative_ns = ?tentative_ns, "Found tentative nameserver in cache");
        let mut ns = tentative_ns.ok_or_else(|| ResolveError::NoServerFound)?;

        // Start querying name servers
        loop {
            debug!(?qtype, qname = %qname, ns = %ns, "attempting lookup with nameserver");

            let ns_copy = ns.clone();

            let server = (ns_copy, 53);
            let response = self
                .context
                .client
                .send_query(qname, qtype.clone(), server, false)
                .await?;

            // If we've got an actual answer, we're done!
            if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
                // 这里说明已经找到对应的ns服务器，并通过它成功解析出了结果
                // 如果ns服务器是属于上级的，它的answers是空，不会进入这里（但是AUTHORITY SECTION， ADDITIONAL SECTION会有下一级的信息）
                let _ = self.context.cache.store(&response.answers);
                let _ = self.context.cache.store(&response.authorities);
                let _ = self.context.cache.store(&response.resources);
                return Ok(response.clone());
            }

            if response.header.rescode == ResultCode::NXDOMAIN {
                // 进入这里，说明已经确定域名不存在(类似于查 fsdf.gderg.df ,可能在根服务器就发现 df不存在 ，就是 NXDOMAIN 了)
                if let Some(ttl) = response.get_ttl_from_soa() {
                    let _ = self.context.cache.store_nxdomain(qname, qtype, ttl);
                }
                return Ok(response.clone());
            }

            // Otherwise, try to find a new nameserver based on NS and a
            // corresponding A record in the additional section
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                // If there is such a record, we can retry the loop with that NS
                ns = new_ns.clone();
                let _ = self.context.cache.store(&response.answers);
                let _ = self.context.cache.store(&response.authorities);
                let _ = self.context.cache.store(&response.resources);

                continue;
            }

            // If not, we'll have to resolve the ip of a NS record
            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(x) => x,
                None => return Ok(response.clone()),
            };

            // Recursively resolve the NS
            let recursive_response = self.resolve(&new_ns_name, QueryType::A, true).await?;

            // Pick a random IP and restart
            if let Some(new_ns) = recursive_response.get_random_ip() {
                ns = new_ns.clone();
            } else {
                return Ok(response.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode, TransientTtl};

    use super::*;

    use crate::dns::context::ResolveStrategy;
    use crate::dns::context::tests::create_test_context;

    #[tokio::test]
    async fn test_forwarding_resolver() {
        let mut context = create_test_context(Box::new(|qname, _, _, _| {
            let mut packet = DnsPacket::new();

            if qname == "google.com" {
                packet.answers.push(DnsRecord::A {
                    domain: "google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else {
                packet.header.rescode = ResultCode::NXDOMAIN;
            }

            Ok(packet)
        }));

        match Arc::get_mut(&mut context) {
            Some(mut ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                    host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port: 53,
                };
            }
            None => panic!(),
        }

        let mut resolver = context.create_resolver(context.clone());

        // First verify that we get a match back
        {
            let res = match resolver.resolve("google.com", QueryType::A, true).await {
                Ok(x) => x,
                Err(_) => panic!(),
            };

            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                }
                _ => panic!(),
            }
        };

        // Do the same lookup again, and verify that it's present in the cache
        // and that the counter has been updated
        {
            let res = match resolver.resolve("google.com", QueryType::A, true).await {
                Ok(x) => x,
                Err(_) => panic!(),
            };

            assert_eq!(1, res.answers.len());

            let list = match context.cache.list() {
                Ok(x) => x,
                Err(_) => panic!(),
            };

            assert_eq!(1, list.len());

            assert_eq!("google.com", list[0].0);
            assert_eq!(1, list[0].1.record_types.len());
            assert_eq!(1, list[0].1.hits);
        };

        // Do a failed lookup
        {
            let res = match resolver.resolve("yahoo.com", QueryType::A, true).await {
                Ok(x) => x,
                Err(_) => panic!(),
            };

            assert_eq!(0, res.answers.len());
            assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
        };
    }

    #[tokio::test]
    async fn test_recursive_resolver_with_no_nameserver() {
        let context = create_test_context(Box::new(|_, _, _, _| {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NXDOMAIN;
            Ok(packet)
        }));

        let mut resolver = context.create_resolver(context.clone());

        // Expect failure when no name servers are available
        if let Ok(_) = resolver.resolve("google.com", QueryType::A, true).await {
            panic!();
        }
    }

    #[tokio::test]
    async fn test_recursive_resolver_with_missing_a_record() {
        let context = create_test_context(Box::new(|_, _, _, _| {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NXDOMAIN;
            Ok(packet)
        }));

        let mut resolver = context.create_resolver(context.clone());

        // Expect failure when no name servers are available
        if let Ok(_) = resolver.resolve("google.com", QueryType::A, true).await {
            panic!();
        }

        // Insert name server, but no corresponding A record
        let mut nameservers = Vec::new();
        nameservers.push(DnsRecord::NS {
            domain: "".to_string(),
            host: "a.myroot.net".to_string(),
            ttl: TransientTtl(3600),
        });

        let _ = context.cache.store(&nameservers);

        if let Ok(_) = resolver.resolve("google.com", QueryType::A, true).await {
            panic!();
        }
    }

    #[tokio::test]
    async fn test_recursive_resolver_match_order() {
        let context = create_test_context(Box::new(|_, _, (server, _), _| {
            let mut packet = DnsPacket::new();

            if server == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) {
                packet.header.id = 1;

                packet.answers.push(DnsRecord::A {
                    domain: "a.google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });

                return Ok(packet);
            } else if server == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)) {
                packet.header.id = 2;

                packet.answers.push(DnsRecord::A {
                    domain: "b.google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });

                return Ok(packet);
            } else if server == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)) {
                packet.header.id = 3;

                packet.answers.push(DnsRecord::A {
                    domain: "c.google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });

                return Ok(packet);
            }

            packet.header.id = 999;
            packet.header.rescode = ResultCode::NXDOMAIN;
            Ok(packet)
        }));

        let mut resolver = context.create_resolver(context.clone());

        // Expect failure when no name servers are available
        if let Ok(_) = resolver.resolve("google.com", QueryType::A, true).await {
            panic!();
        }

        // Insert root servers
        {
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::NS {
                domain: "".to_string(),
                host: "a.myroot.net".to_string(),
                ttl: TransientTtl(3600),
            });
            nameservers.push(DnsRecord::A {
                domain: "a.myroot.net".to_string(),
                addr: "127.0.0.1".parse().unwrap(),
                ttl: TransientTtl(3600),
            });

            let _ = context.cache.store(&nameservers);
        }

        match resolver.resolve("google.com", QueryType::A, true).await {
            Ok(packet) => {
                assert_eq!(1, packet.header.id);
            }
            Err(_) => panic!(),
        }

        // Insert TLD servers
        {
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::NS {
                domain: "com".to_string(),
                host: "a.mytld.net".to_string(),
                ttl: TransientTtl(3600),
            });
            nameservers.push(DnsRecord::A {
                domain: "a.mytld.net".to_string(),
                addr: "127.0.0.2".parse().unwrap(),
                ttl: TransientTtl(3600),
            });

            let _ = context.cache.store(&nameservers);
        }

        match resolver.resolve("google.com", QueryType::A, true).await {
            Ok(packet) => {
                assert_eq!(2, packet.header.id);
            }
            Err(_) => panic!(),
        }

        // Insert authoritative servers
        {
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::NS {
                domain: "google.com".to_string(),
                host: "ns1.google.com".to_string(),
                ttl: TransientTtl(3600),
            });
            nameservers.push(DnsRecord::A {
                domain: "ns1.google.com".to_string(),
                addr: "127.0.0.3".parse().unwrap(),
                ttl: TransientTtl(3600),
            });

            let _ = context.cache.store(&nameservers);
        }

        match resolver.resolve("google.com", QueryType::A, true).await {
            Ok(packet) => {
                assert_eq!(3, packet.header.id);
            }
            Err(_) => panic!(),
        }
    }

    #[tokio::test]
    async fn test_recursive_resolver_successfully() {
        let context = create_test_context(Box::new(|qname, _, _, _| {
            let mut packet = DnsPacket::new();

            if qname == "google.com" {
                packet.answers.push(DnsRecord::A {
                    domain: "google.com".to_string(),
                    addr: "127.0.0.1".parse().unwrap(),
                    ttl: TransientTtl(3600),
                });
            } else {
                packet.header.rescode = ResultCode::NXDOMAIN;

                packet.authorities.push(DnsRecord::SOA {
                    domain: "google.com".to_string(),
                    r_name: "google.com".to_string(),
                    m_name: "google.com".to_string(),
                    serial: 0,
                    refresh: 3600,
                    retry: 3600,
                    expire: 3600,
                    minimum: 3600,
                    ttl: TransientTtl(3600),
                });
            }

            Ok(packet)
        }));

        let mut resolver = context.create_resolver(context.clone());

        // Insert name servers
        let mut nameservers = Vec::new();
        nameservers.push(DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: TransientTtl(3600),
        });
        nameservers.push(DnsRecord::A {
            domain: "ns1.google.com".to_string(),
            addr: "127.0.0.1".parse().unwrap(),
            ttl: TransientTtl(3600),
        });

        let _ = context.cache.store(&nameservers);

        // Check that we can successfully resolve
        {
            let res = match resolver.resolve("google.com", QueryType::A, true).await {
                Ok(x) => x,
                Err(_) => panic!(),
            };

            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                }
                _ => panic!(),
            }
        };

        // And that we won't find anything for a domain that isn't present
        {
            let res = match resolver
                .resolve("foobar.google.com", QueryType::A, true)
                .await
            {
                Ok(x) => x,
                Err(_) => panic!(),
            };

            assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
            assert_eq!(0, res.answers.len());
        };

        // Perform another successful query, that should hit the cache
        {
            let res = match resolver.resolve("google.com", QueryType::A, true).await {
                Ok(x) => x,
                Err(_) => panic!(),
            };

            assert_eq!(1, res.answers.len());
        };

        // Now check that the cache is used, and that the statistics is correct
        {
            let list = match context.cache.list() {
                Ok(x) => x,
                Err(_) => panic!(),
            };

            assert_eq!(3, list.len());

            // Check statistics for google entry
            assert_eq!("google.com", list[1].0);

            // Should have a NS record and an A record for a total of 2 record types
            assert_eq!(2, list[1].1.record_types.len());

            // Should have been hit two times for NS google.com and once for
            // A google.com
            assert_eq!(3, list[1].1.hits);

            assert_eq!("ns1.google.com", list[2].0);
            assert_eq!(1, list[2].1.record_types.len());
            assert_eq!(2, list[2].1.hits);
        };
    }
}
