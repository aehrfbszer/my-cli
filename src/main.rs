use dns::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType};
use std::{fs::File, io::Read, net::UdpSocket};

mod dns;
mod ipstring;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, world!");
    println!("Hello, world!");
    // Perform an A query for google.com
    let qname = "www.baidu.com";
    let qtype = QueryType::A;

    // Using googles public DNS server
    let server = ("8.8.8.8", 53);

    // Bind a UDP socket to an arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    // Use our new write method to write the packet to a buffer...
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // ...and send it off to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // As per the previous section, `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.
    let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }
    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ipstring::ip_to_buffer;

    #[test]
    fn test_ip_to_buffer() {
        let ip = "192.168.1.1";
        let ip6 = "2001:0db8:85a3::8a2e:0370:7334";
        let buffer = ip_to_buffer(ip, None, 0);
        println!("{:?}  ipv4", buffer); // 输出结果
        let buffer = ip_to_buffer(ip6, None, 0);
        println!("{:0>2x?}  ipv6", buffer);
        let vv6 = buffer
            .chunks(2)
            .map(|s| {
                let ss = s.iter().map(|n| format!("{:0>2x?}", n)).collect::<String>();
                ss
            })
            .collect::<Vec<String>>();

        println!("IP v 6：{}", vv6.join(":"));
    }
}
