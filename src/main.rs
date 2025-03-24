use dns::handle_query;
use std::net::UdpSocket;

mod dns;
mod ipstring;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, world!");
    println!("Hello, world!");

    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match handle_query(&socket) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }

    // Ok(())
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
