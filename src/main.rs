use regex::Regex;
use std::sync::LazyLock;

static RE_IPV4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$").unwrap());
static RE_IPV6: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[\da-fA-F]{0,4}:){1,7}[\da-fA-F]{1,4}$").unwrap());

fn main() {
    println!("Hello, world!");
    println!("Hello, world!");

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
#[derive(Debug, PartialEq)]
enum IpType {
    IPv4,
    IPv6,
}

fn ip_to_buffer(ip: &str, buff: Option<Vec<u8>>, offset: usize) -> Vec<u8> {
    // let mut buff = buff.get_or_insert_default();

    let (kind, size) = if RE_IPV6.is_match(ip) {
        (IpType::IPv6, 16)
    } else if RE_IPV4.is_match(ip) {
        (IpType::IPv4, 4)
    } else {
        panic!("Invalid IP address format");
    };

    // 如果缓冲区未提供，则创建一个新的缓冲区
    let mut buffer = buff.to_owned();
    let mut buffer = buffer
        .get_or_insert_with(|| vec![0; size + offset])
        .to_owned();

    if kind == IpType::IPv4 {
        // 解析 IP 地址的每个部分并填充到缓冲区
        let octets: Vec<&str> = ip.split('.').collect();
        for (i, octet) in octets.iter().enumerate() {
            if let Ok(byte) = octet.parse::<u8>() {
                buffer[offset + i] = byte;
            } else {
                panic!("IP segment out of range");
            }
        }
    } else if kind == IpType::IPv6 {
        // 解析 IP 地址的每个部分并填充到缓冲区
        let octets: Vec<&str> = ip.split(':').collect();

        if octets.len() > 8 {
            panic!("IPv6 address too long");
        }

        let mut zero_index = None;

        for (i, octet) in octets.iter().enumerate() {
            if octet.is_empty() {
                if let Some(_index) = zero_index {
                    panic!("IPv6 address contains multiple empty segments");
                } else {
                    zero_index = Some(i + offset);
                }
            }
            if let Ok(byte) = u16::from_str_radix(octet, 16) {
                buffer[offset + i * 2] = (byte >> 8) as u8;
                buffer[offset + i * 2 + 1] = byte as u8;
            }
        }
        println!("{:?}", buffer);
        if let Some(index) = zero_index {
            let insert_index = index * 2;
            let data_len = octets.len() * 2;
            let zeros = vec![0; 16 - data_len + 2];
            let other_part = buffer.split_off(size + offset);
            let drop_part = buffer.split_off(data_len + offset);
            let center_drop_part: Vec<_> = buffer
                .splice(insert_index..insert_index + 2, zeros)
                .collect();
            println!("drop: {:?}  {:?}", drop_part, center_drop_part);
            buffer.extend(other_part);
        }
    }

    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_valid() {
        let ip = "192.168.1.1";
        let buffer = ip_to_buffer(ip, None, 0);
        assert_eq!(buffer, vec![192, 168, 1, 1]);
    }

    #[test]
    fn test_ipv4_invalid() {
        let ip = "256.256.256.256";
        let result = std::panic::catch_unwind(|| ip_to_buffer(ip, None, 0));
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_valid() {
        let ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let buffer = ip_to_buffer(ip, None, 0);
        assert_eq!(
            buffer,
            vec![
                0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
                0x73, 0x34
            ]
        );
    }

    #[test]
    fn test_ipv6_valid_zero_compression() {
        let ip = "2001:0db8:85a3::8a2e:0370:7334";
        let buffer = ip_to_buffer(ip, None, 0);
        assert_eq!(
            buffer,
            vec![
                0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
                0x73, 0x34
            ]
        );
    }

    #[test]
    fn test_ipv6_invalid_multiple_empty_segments() {
        let ip = "2001:0db8:85a3::8a2e::7334";
        let result = std::panic::catch_unwind(|| ip_to_buffer(ip, None, 0));
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_invalid_too_long() {
        let ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234";
        let result = std::panic::catch_unwind(|| ip_to_buffer(ip, None, 0));
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_invalid_invalid_segment() {
        let ip = "2001:0db8:85a3:0000:0000:8a2g:0370:7334";
        let result = std::panic::catch_unwind(|| ip_to_buffer(ip, None, 0));
        assert!(result.is_err());
    }

    #[test]
    fn test_buffer_offset() {
        let ip = "192.168.1.1";
        let buffer = ip_to_buffer(ip, None, 2);
        assert_eq!(buffer, vec![0, 0, 192, 168, 1, 1]);
    }

    #[test]
    fn test_existing_buffer_ipv4() {
        let ip = "192.168.1.1";
        let existing_buffer = vec![0, 0, 0, 0, 0];
        let buffer = ip_to_buffer(ip, Some(existing_buffer), 0);
        assert_eq!(buffer, vec![192, 168, 1, 1, 0]);
    }

    #[test]
    fn test_existing_buffer_ipv6() {
        let ip = "2001:0db8:85a3::8a2e:0370:7334";
        let existing_buffer = vec![0; 20];
        let buffer = ip_to_buffer(ip, Some(existing_buffer), 0);
        assert_eq!(
            buffer,
            vec![
                0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
                0x73, 0x34, 0, 0, 0, 0
            ]
        );
    }
}
