use std::{
    cmp::Ordering,
    fmt::{self, Display},
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};

use super::{
    DISABLE_V6, PERFER_V6,
    buffer::{PacketBuffer, Result, VectorPacketBuffer},
};

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, Serialize, Deserialize)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    SOA,   // 6
    MX,    // 15
    TXT,   // 16
    AAAA,  // 28
    SRV,   // 33
    OPT,   // 41
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::MX => 15,
            QueryType::TXT => 16,
            QueryType::AAAA => 28,
            QueryType::SRV => 33,
            QueryType::OPT => 41,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            28 => QueryType::AAAA,
            33 => QueryType::SRV,
            41 => QueryType::OPT,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, Ord, Serialize, Deserialize)]
pub struct TransientTtl(pub u32);

impl PartialEq<TransientTtl> for TransientTtl {
    fn eq(&self, _: &TransientTtl) -> bool {
        true
    }
}

impl PartialOrd<TransientTtl> for TransientTtl {
    fn partial_cmp(&self, _: &TransientTtl) -> Option<Ordering> {
        Some(Ordering::Equal)
    }
}

impl Hash for TransientTtl {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {
        // purposely left empty
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: TransientTtl,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: TransientTtl,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: TransientTtl,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: TransientTtl,
    }, // 5
    SOA {
        domain: String,
        m_name: String,
        r_name: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: TransientTtl,
    }, // 6
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: TransientTtl,
    }, // 15
    TXT {
        domain: String,
        data: String,
        ttl: TransientTtl,
    }, // 16
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: TransientTtl,
    }, // 28
    SRV {
        domain: String,
        priority: u16,
        weight: u16,
        port: u16,
        host: String,
        ttl: TransientTtl,
    }, // 33
    OPT {
        packet_len: u16,
        flags: u32,
        data: String,
    }, // 41
}

impl DnsRecord {
    pub async fn read<T: PacketBuffer>(buffer: &mut T) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain).await?;

        let qtype_num = buffer.read_u16().await?;
        let qtype = QueryType::from_num(qtype_num);
        let class = buffer.read_u16().await?;
        let ttl = buffer.read_u32().await?;
        let data_len = buffer.read_u16().await?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32().await?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32().await?;
                let raw_addr2 = buffer.read_u32().await?;
                let raw_addr3 = buffer.read_u32().await?;
                let raw_addr4 = buffer.read_u32().await?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns).await?;

                Ok(DnsRecord::NS {
                    domain: domain,
                    host: ns,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname).await?;

                Ok(DnsRecord::CNAME {
                    domain: domain,
                    host: cname,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::SRV => {
                let priority = buffer.read_u16().await?;
                let weight = buffer.read_u16().await?;
                let port = buffer.read_u16().await?;

                let mut srv = String::new();
                buffer.read_qname(&mut srv).await?;

                Ok(DnsRecord::SRV {
                    domain: domain,
                    priority: priority,
                    weight: weight,
                    port: port,
                    host: srv,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16().await?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx).await?;

                Ok(DnsRecord::MX {
                    domain: domain,
                    priority: priority,
                    host: mx,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::SOA => {
                let mut m_name = String::new();
                buffer.read_qname(&mut m_name).await?;

                let mut r_name = String::new();
                buffer.read_qname(&mut r_name).await?;

                let serial = buffer.read_u32().await?;
                let refresh = buffer.read_u32().await?;
                let retry = buffer.read_u32().await?;
                let expire = buffer.read_u32().await?;
                let minimum = buffer.read_u32().await?;

                Ok(DnsRecord::SOA {
                    domain: domain,
                    m_name: m_name,
                    r_name: r_name,
                    serial: serial,
                    refresh: refresh,
                    retry: retry,
                    expire: expire,
                    minimum: minimum,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::TXT => {
                let mut txt = String::new();

                let cur_pos = buffer.pos();
                txt.push_str(&String::from_utf8_lossy(
                    buffer.get_range(cur_pos, data_len as usize).await?,
                ));

                buffer.step(data_len as usize)?;

                Ok(DnsRecord::TXT {
                    domain: domain,
                    data: txt,
                    ttl: TransientTtl(ttl),
                })
            }
            QueryType::OPT => {
                let mut data = String::new();

                let cur_pos = buffer.pos();
                data.push_str(&String::from_utf8_lossy(
                    buffer.get_range(cur_pos, data_len as usize).await?,
                ));
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::OPT {
                    packet_len: class,
                    flags: ttl,
                    data: data,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl: TransientTtl(ttl),
                })
            }
        }
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::SRV {
                ref domain,
                priority,
                weight,
                port,
                ref host,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::SRV.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_u16(weight)?;
                buffer.write_u16(port)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::SOA {
                ref domain,
                ref m_name,
                ref r_name,
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::SOA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(m_name)?;
                buffer.write_qname(r_name)?;
                buffer.write_u32(serial)?;
                buffer.write_u32(refresh)?;
                buffer.write_u32(retry)?;
                buffer.write_u32(expire)?;
                buffer.write_u32(minimum)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::TXT {
                ref domain,
                ref data,
                ttl: TransientTtl(ttl),
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::TXT.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(data.len() as u16)?;

                for b in data.as_bytes() {
                    buffer.write_u8(*b)?;
                }
            }
            DnsRecord::OPT { .. } => {}
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }

    pub fn get_querytype(&self) -> QueryType {
        match *self {
            DnsRecord::A { .. } => QueryType::A,
            DnsRecord::AAAA { .. } => QueryType::AAAA,
            DnsRecord::NS { .. } => QueryType::NS,
            DnsRecord::CNAME { .. } => QueryType::CNAME,
            DnsRecord::SRV { .. } => QueryType::SRV,
            DnsRecord::MX { .. } => QueryType::MX,
            DnsRecord::UNKNOWN { qtype, .. } => QueryType::UNKNOWN(qtype),
            DnsRecord::SOA { .. } => QueryType::SOA,
            DnsRecord::TXT { .. } => QueryType::TXT,
            DnsRecord::OPT { .. } => QueryType::OPT,
        }
    }

    pub fn get_domain(&self) -> Option<String> {
        match *self {
            DnsRecord::A { ref domain, .. }
            | DnsRecord::AAAA { ref domain, .. }
            | DnsRecord::NS { ref domain, .. }
            | DnsRecord::CNAME { ref domain, .. }
            | DnsRecord::SRV { ref domain, .. }
            | DnsRecord::MX { ref domain, .. }
            | DnsRecord::UNKNOWN { ref domain, .. }
            | DnsRecord::SOA { ref domain, .. }
            | DnsRecord::TXT { ref domain, .. } => Some(domain.clone()),
            DnsRecord::OPT { .. } => None,
        }
    }

    pub fn get_ttl(&self) -> u32 {
        match *self {
            DnsRecord::A {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::AAAA {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::NS {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::CNAME {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::SRV {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::MX {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::UNKNOWN {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::SOA {
                ttl: TransientTtl(ttl),
                ..
            }
            | DnsRecord::TXT {
                ttl: TransientTtl(ttl),
                ..
            } => ttl,
            DnsRecord::OPT { .. } => 0,
        }
    }
}

/// The result code for a DNS query, as described in the specification
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl Default for ResultCode {
    fn default() -> Self {
        ResultCode::NOERROR
    }
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub response: bool,             // 1 bit
    pub opcode: u8,                 // 4 bits
    pub authoritative_answer: bool, // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub recursion_desired: bool,    // 1 bit

    pub recursion_available: bool, // 1 bit
    pub z: bool,                   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub checking_disabled: bool,   // 1 bit
    pub rescode: ResultCode,       // 4 bits

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: false,

            recursion_available: false,
            z: false,
            authed_data: false,
            checking_disabled: false,
            rescode: ResultCode::NOERROR,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub async fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        self.id = buffer.read_u16().await?;

        let flags = buffer.read_u16().await?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        self.response = (a & (1 << 7)) > 0; // 按位与运算，2的8次，即保留最高位的1bit
        self.opcode = (a >> 3) & 0x0F; // a是8位，右移3位，留下高5位，按位与0x0F，得到这高5位的低4位
        self.authoritative_answer = (a & (1 << 2)) > 0; // 按位与2的3次，得到a的从左往右数第6位 
        self.truncated_message = (a & (1 << 1)) > 0; // 按位与2的2次，得到a的从左往右数第7位
        self.recursion_desired = (a & (1 << 0)) > 0; // 按位与2的0次，得到a的从左往右数第8位

        self.recursion_available = (b & (1 << 7)) > 0; // b的最高位
        self.z = (b & (1 << 6)) > 0; // b的从左到右第2位
        self.authed_data = (b & (1 << 5)) > 0; // b的从左到右第3位
        self.checking_disabled = (b & (1 << 4)) > 0; // b的从左到右第4位
        self.rescode = ResultCode::from_num(b & 0x0F); // b按位与0x0F，得到这4位的低4位

        self.questions = buffer.read_u16().await?;
        self.answers = buffer.read_u16().await?;
        self.authoritative_entries = buffer.read_u16().await?;
        self.resource_entries = buffer.read_u16().await?;

        Ok(())
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }

    pub fn binary_len(&self) -> usize {
        12
    }
}

impl Display for DnsHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsHeader:\n")?;
        write!(f, "\tid: {0}\n", self.id)?;

        write!(f, "\trecursion_desired: {0}\n", self.recursion_desired)?;
        write!(f, "\ttruncated_message: {0}\n", self.truncated_message)?;
        write!(
            f,
            "\tauthoritative_answer: {0}\n",
            self.authoritative_answer
        )?;
        write!(f, "\topcode: {0}\n", self.opcode)?;
        write!(f, "\tresponse: {0}\n", self.response)?;

        write!(f, "\trescode: {:?}\n", self.rescode)?;
        write!(f, "\tchecking_disabled: {0}\n", self.checking_disabled)?;
        write!(f, "\tauthed_data: {0}\n", self.authed_data)?;
        write!(f, "\tz: {0}\n", self.z)?;
        write!(f, "\trecursion_available: {0}\n", self.recursion_available)?;

        write!(f, "\tquestions: {0}\n", self.questions)?;
        write!(f, "\tanswers: {0}\n", self.answers)?;
        write!(
            f,
            "\tauthoritative_entries: {0}\n",
            self.authoritative_entries
        )?;
        write!(f, "\tresource_entries: {0}\n", self.resource_entries)?;

        Ok(())
    }
}

/// Representation of a DNS question
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }

    // 域名最后有一个点
    pub fn binary_len(&self) -> usize {
        self.name
            .split('.')
            .map(|x| x.len() + 1)
            .fold(1, |x, y| x + y)
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }

    pub async fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        buffer.read_qname(&mut self.name).await?;
        self.qtype = QueryType::from_num(buffer.read_u16().await?); // qtype
        let _ = buffer.read_u16().await?; // class

        Ok(())
    }
}

impl Display for DnsQuestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsQuestion:\n")?;
        write!(f, "\tname: {0}\n", self.name)?;
        write!(f, "\trecord type: {:?}\n", self.qtype)?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub async fn from_buffer<T: PacketBuffer>(buffer: &mut T) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer).await?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer).await?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer).await?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer).await?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer).await?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        println!("{}", self.header);

        println!("questions:");
        for x in &self.questions {
            println!("\t{:?}", x);
        }

        println!("answers:");
        for x in &self.answers {
            println!("\t{:?}", x);
        }

        println!("authorities:");
        for x in &self.authorities {
            println!("\t{:?}", x);
        }

        println!("resources:");
        for x in &self.resources {
            println!("\t{:?}", x);
        }
    }

    pub fn get_ttl_from_soa(&self) -> Option<u32> {
        for answer in &self.authorities {
            if let DnsRecord::SOA { minimum, .. } = *answer {
                return Some(minimum);
            }
        }

        None
    }
    pub fn write<T: PacketBuffer>(&mut self, buffer: &mut T, max_size: usize) -> Result<()> {
        let mut test_buffer = VectorPacketBuffer::new();

        let mut size = self.header.binary_len();
        for ref question in &self.questions {
            size += question.binary_len();
            question.write(&mut test_buffer)?;
        }

        let mut record_count = self.answers.len() + self.authorities.len() + self.resources.len();

        for (i, rec) in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.resources.iter())
            .enumerate()
        {
            size += rec.write(&mut test_buffer)?;
            if size > max_size {
                record_count = i;
                self.header.truncated_message = true;
                break;
            } else if i < self.answers.len() {
                self.header.answers += 1;
            } else if i < self.answers.len() + self.authorities.len() {
                self.header.authoritative_entries += 1;
            } else {
                self.header.resource_entries += 1;
            }
        }

        self.header.questions = self.questions.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for rec in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.resources.iter())
            .take(record_count)
        {
            rec.write(buffer)?;
        }

        Ok(())
    }
    /// It's useful to be able to pick a random A record from a packet. When we
    /// get multiple IP's for a single name, it doesn't matter which one we
    /// choose, so in those cases we can now pick one at random.
    pub fn get_random_ip(&self) -> Option<IpAddr> {
        let perfer_v6 = PERFER_V6.get_or_init(|| false);
        let disable_v6 = DISABLE_V6.get_or_init(|| false);

        let vec = self
            .answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { addr, .. } => {
                    if *perfer_v6 {
                        None
                    } else {
                        Some(IpAddr::V4(*addr))
                    }
                }
                DnsRecord::AAAA { addr, .. } => {
                    if *disable_v6 {
                        None
                    } else {
                        Some(IpAddr::V6(*addr))
                    }
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if vec.is_empty() {
            None
        } else {
            Some(vec.choose(&mut rand::rng()).unwrap().clone())
        }
    }

    pub fn get_unresolved_cnames(&self) -> Vec<DnsRecord> {
        let mut unresolved = Vec::new();
        for answer in &self.answers {
            let mut matched = false;
            if let DnsRecord::CNAME { ref host, .. } = *answer {
                for answer2 in &self.answers {
                    if let DnsRecord::A { ref domain, .. } = *answer2 {
                        if domain == host {
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if !matched {
                unresolved.push(answer.clone());
            }
        }

        unresolved
    }

    /// A helper function which returns an iterator over all name servers in
    /// the authorities section, represented as (domain, host) tuples
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            // In practice, these are always NS records in well formed packages.
            // Convert the NS records to a tuple which has only the data we need
            // to make it easy to work with.
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            // Discard servers which aren't authoritative to our query
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    /// We'll use the fact that name servers often bundle the corresponding
    /// A records when replying to an NS query to implement a function that
    /// returns the actual IP for an NS record if possible.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<IpAddr> {
        let perfer_v6 = PERFER_V6.get_or_init(|| false);
        let disable_v6 = DISABLE_V6.get_or_init(|| false);
        // Get an iterator over the nameservers in the authorities section
        let vec = self
            .get_ns(qname)
            // Now we need to look for a matching A record in the additional
            // section. Since we just want the first valid record, we can just
            // build a stream of matching records.
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    // Filter for A records where the domain match the host
                    // of the NS record that we are currently processing
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => {
                            if *perfer_v6 {
                                None
                            } else {
                                Some(IpAddr::V4(*addr))
                            }
                        }
                        DnsRecord::AAAA { domain, addr, .. } if domain == host => {
                            if *disable_v6 {
                                None
                            } else {
                                Some(IpAddr::V6(*addr))
                            }
                        }
                        _ => None,
                    })
            })
            // Finally, pick the first valid entry
            .collect::<Vec<_>>();
        if vec.is_empty() {
            None
        } else {
            Some(vec.choose(&mut rand::rng()).unwrap().clone())
        }
    }

    /// However, not all name servers are as that nice. In certain cases there won't
    /// be any A records in the additional section, and we'll have to perform *another*
    /// lookup in the midst. For this, we introduce a method for returning the host
    /// name of an appropriate name server.
    pub fn get_unresolved_ns(&self, qname: &str) -> Option<String> {
        // Get an iterator over the nameservers in the authorities section
        let vec = self
            .get_ns(qname)
            .map(|(_, host)| host)
            // Finally, pick the first valid entry
            .collect::<Vec<_>>();
        if vec.is_empty() {
            None
        } else {
            Some(vec.choose(&mut rand::rng()).unwrap().to_string())
        }
    }
}
