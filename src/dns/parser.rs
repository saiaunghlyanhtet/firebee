use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub query_name: String,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    #[allow(dead_code)]
    pub name: String,
    pub ip: DnsIp,
    pub ttl: u32,
}

#[derive(Debug, Clone)]
pub enum DnsIp {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_CNAME: u16 = 5;

/// Parse a raw DNS response packet (starting from the DNS header, no UDP/IP headers).
/// Returns None if the packet is malformed or not a response.
pub fn parse_dns_response(data: &[u8]) -> Option<DnsResponse> {
    if data.len() < 12 {
        return None;
    }

    // Check QR bit (bit 15 of flags) — must be 1 for response
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }

    // Check RCODE (bits 0-3 of flags) — must be 0 (no error)
    if flags & 0x000F != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    if qdcount == 0 || ancount == 0 {
        return None;
    }

    let mut offset = 12;

    let query_name = read_name(data, &mut offset)?;
    // Skip QTYPE (2) + QCLASS (2)
    offset = offset.checked_add(4)?;
    if offset > data.len() {
        return None;
    }

    // Skip remaining questions
    for _ in 1..qdcount {
        skip_name(data, &mut offset)?;
        offset = offset.checked_add(4)?;
        if offset > data.len() {
            return None;
        }
    }

    // Parse answer section
    let mut answers = Vec::new();
    for _ in 0..ancount {
        if offset >= data.len() {
            break;
        }

        let name = read_name(data, &mut offset)?;

        if offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        // Skip RCLASS
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            break;
        }

        match rtype {
            TYPE_A if rdlength == 4 => {
                let ip = Ipv4Addr::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                );
                answers.push(DnsAnswer {
                    name: name.clone(),
                    ip: DnsIp::V4(ip),
                    ttl,
                });
            }
            TYPE_AAAA if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[offset..offset + 16]);
                let ip = Ipv6Addr::from(octets);
                answers.push(DnsAnswer {
                    name: name.clone(),
                    ip: DnsIp::V6(ip),
                    ttl,
                });
            }
            TYPE_CNAME => {
                // Skip CNAME records — we follow the chain via answer names
            }
            _ => {
                // Skip unknown record types
            }
        }

        offset += rdlength;
    }

    if answers.is_empty() {
        return None;
    }

    Some(DnsResponse {
        query_name,
        answers,
    })
}

/// Read a DNS name with compression pointer support.
/// Advances `offset` past the name in the wire format.
fn read_name(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;
    let mut jump_count = 0;
    let max_jumps = 128;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len_byte = data[pos];

        if len_byte == 0 {
            if !jumped {
                *offset = pos + 1;
            }
            break;
        }

        if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            if !jumped {
                *offset = pos + 2;
            }
            pos = ((len_byte as usize & 0x3F) << 8) | data[pos + 1] as usize;
            jumped = true;
            jump_count += 1;
            if jump_count > max_jumps {
                return None;
            }
            continue;
        }

        let label_len = len_byte as usize;
        pos += 1;
        if pos + label_len > data.len() {
            return None;
        }

        let label = std::str::from_utf8(&data[pos..pos + label_len]).ok()?;
        labels.push(label.to_lowercase());
        pos += label_len;
    }

    if labels.is_empty() {
        return None;
    }

    Some(labels.join("."))
}

/// Skip over a DNS name in the wire format, advancing `offset`.
fn skip_name(data: &[u8], offset: &mut usize) -> Option<()> {
    loop {
        if *offset >= data.len() {
            return None;
        }

        let len_byte = data[*offset];

        if len_byte == 0 {
            *offset += 1;
            return Some(());
        }

        if len_byte & 0xC0 == 0xC0 {
            *offset += 2;
            return Some(());
        }

        *offset += 1 + len_byte as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dns_response(domain: &str, ips: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Header
        pkt.extend_from_slice(&[0x00, 0x01]); // ID
        pkt.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, RD=1, RA=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&(ips.len() as u16).to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Question section
        let qname_offset = pkt.len();
        for label in domain.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0x00); // root
        pkt.extend_from_slice(&TYPE_A.to_be_bytes()); // QTYPE
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS (IN)

        // Answer section — use compression pointer back to question name
        for ip in ips {
            // Name: pointer to question
            pkt.push(0xC0);
            pkt.push(qname_offset as u8);
            pkt.extend_from_slice(&TYPE_A.to_be_bytes());
            pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            pkt.extend_from_slice(&ttl.to_be_bytes());
            pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            pkt.extend_from_slice(&ip.octets());
        }

        pkt
    }

    #[test]
    fn test_parse_simple_response() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let pkt = build_dns_response("example.com", &[ip], 300);
        let resp = parse_dns_response(&pkt).unwrap();

        assert_eq!(resp.query_name, "example.com");
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].ttl, 300);
        assert!(matches!(resp.answers[0].ip, DnsIp::V4(a) if a == ip));
    }

    #[test]
    fn test_parse_multiple_answers() {
        let ips = vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)];
        let pkt = build_dns_response("multi.example.com", &ips, 60);
        let resp = parse_dns_response(&pkt).unwrap();

        assert_eq!(resp.query_name, "multi.example.com");
        assert_eq!(resp.answers.len(), 2);
    }

    #[test]
    fn test_reject_query_packet() {
        // QR=0 means this is a query, not a response
        let mut pkt = build_dns_response("example.com", &[Ipv4Addr::new(1, 2, 3, 4)], 300);
        pkt[2] &= 0x7F; // Clear QR bit
        assert!(parse_dns_response(&pkt).is_none());
    }

    #[test]
    fn test_reject_error_response() {
        let mut pkt = build_dns_response("example.com", &[Ipv4Addr::new(1, 2, 3, 4)], 300);
        pkt[3] |= 0x03; // Set RCODE = NXDOMAIN
        assert!(parse_dns_response(&pkt).is_none());
    }

    #[test]
    fn test_reject_too_short() {
        assert!(parse_dns_response(&[0; 11]).is_none());
        assert!(parse_dns_response(&[]).is_none());
    }

    #[test]
    fn test_name_case_normalization() {
        let pkt = build_dns_response("Example.COM", &[Ipv4Addr::new(1, 1, 1, 1)], 300);
        let resp = parse_dns_response(&pkt).unwrap();
        assert_eq!(resp.query_name, "example.com");
    }
}
