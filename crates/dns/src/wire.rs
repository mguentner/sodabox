//! Minimal DNS wire codec (RFC 1035) — just what the filtering resolver needs:
//! parse a guest query's first question, and build a response (REFUSED or with
//! A/AAAA answers). Hand-rolled on purpose: the resolver parses **untrusted**
//! guest input, so every field is bounds-checked and no third-party parser is in
//! the path.
//!
//! Scope note: this decodes/encodes one question (the common case; multi-question
//! queries are rejected upstream) and A/AAAA answers. Name compression pointers
//! are honoured when *decoding* (upstream responses use them) and never
//! emitted when encoding.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

// RCODEs.
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

/// A parse error on a (possibly hostile) DNS message.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsError {
    TooShort,
    BadName,
    /// We only handle single-question queries.
    NotOneQuestion,
    /// QR bit set — that's a response, not a query.
    NotAQuery,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DnsError::TooShort => "message too short",
            DnsError::BadName => "malformed name",
            DnsError::NotOneQuestion => "expected exactly one question",
            DnsError::NotAQuery => "message is a response, not a query",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DnsError {}

/// One question: the name (as written, case preserved) plus qtype/qclass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A decoded guest query — the fields the resolver acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    /// Recursion-desired bit, echoed into the response.
    pub rd: bool,
    pub question: Question,
}

/// An answer resource record we synthesise (A/AAAA only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub name: String,
    pub ttl: u32,
    pub data: RecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// A CNAME we pass through verbatim so the guest's stub resolver keeps the
    /// chain from the queried name to the A/AAAA records. Not an
    /// egress target itself — the resolver admits only the resolved A/AAAA IPs.
    Cname(String),
}

impl RecordData {
    fn rtype(&self) -> u16 {
        match self {
            RecordData::A(_) => TYPE_A,
            RecordData::Aaaa(_) => TYPE_AAAA,
            RecordData::Cname(_) => TYPE_CNAME,
        }
    }
}

/// Parse a query message. Enforces: ≥ header, QR=0, exactly one question.
pub fn parse_query(buf: &[u8]) -> Result<Query, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::TooShort);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags >> 15) & 1;
    if qr != 0 {
        return Err(DnsError::NotAQuery);
    }
    let rd = (flags >> 8) & 1 == 1;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return Err(DnsError::NotOneQuestion);
    }

    let (name, off) = decode_name(buf, 12)?;
    if off + 4 > buf.len() {
        return Err(DnsError::TooShort);
    }
    let qtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
    let qclass = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);

    Ok(Query {
        id,
        rd,
        question: Question {
            name,
            qtype,
            qclass,
        },
    })
}

/// Decode a domain name starting at `start`. Returns the name and the offset
/// *after* the name (for the top-level name; pointer targets don't advance it).
/// Guards against pointer loops and oversize names.
pub fn decode_name(buf: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0u16;

    loop {
        let len = *buf.get(pos).ok_or(DnsError::TooShort)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    pos += 1;
                    break;
                }
                let s = pos + 1;
                let e = s + len as usize;
                let label = buf.get(s..e).ok_or(DnsError::TooShort)?;
                if !name.is_empty() {
                    name.push('.');
                }
                // Labels are octets; render as-is (ASCII DNS names in practice).
                for &b in label {
                    name.push(b as char);
                }
                pos = e;
                if name.len() > 255 {
                    return Err(DnsError::BadName);
                }
            }
            0xc0 => {
                // Compression pointer: 14-bit offset.
                let b2 = *buf.get(pos + 1).ok_or(DnsError::TooShort)?;
                let ptr = (((len & 0x3f) as usize) << 8) | b2 as usize;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                jumps += 1;
                if jumps > 128 || ptr >= buf.len() {
                    return Err(DnsError::BadName);
                }
                pos = ptr;
            }
            _ => return Err(DnsError::BadName), // 0x40/0x80 reserved
        }
    }
    Ok((name, end.unwrap_or(pos)))
}

pub const TYPE_CNAME: u16 = 5;

/// A parsed answer resource record from an upstream response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rr {
    pub name: String,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    /// A record type we don't interpret (kept for completeness).
    Other(u16),
}

/// A parsed upstream response: id, rcode, and answer records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedResponse {
    pub id: u16,
    pub rcode: u8,
    pub answers: Vec<Rr>,
}

/// Build a recursion-desired query for `name`/`qtype` (single question).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(1u16 << 8).to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar
    encode_name(name, &mut out)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Parse an upstream response: skip the question section, decode A/AAAA/CNAME
/// answers. Bounds-checked against a hostile/truncated upstream.
pub fn parse_response(buf: &[u8]) -> Result<ParsedResponse, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::TooShort);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = (flags & 0x0f) as u8;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut pos = 12;
    for _ in 0..qdcount {
        let (_n, p) = decode_name(buf, pos)?;
        pos = p + 4; // qtype + qclass
        if pos > buf.len() {
            return Err(DnsError::TooShort);
        }
    }

    let mut answers = Vec::with_capacity(ancount as usize);
    for _ in 0..ancount {
        let (name, p) = decode_name(buf, pos)?;
        pos = p;
        if pos + 10 > buf.len() {
            return Err(DnsError::TooShort);
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > buf.len() {
            return Err(DnsError::TooShort);
        }
        let data = match rtype {
            TYPE_A if rdlength == 4 => {
                let o = &buf[rdata_start..rdata_end];
                RData::A(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
            }
            TYPE_AAAA if rdlength == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[rdata_start..rdata_end]);
                RData::Aaaa(Ipv6Addr::from(o))
            }
            TYPE_CNAME => {
                let (target, _) = decode_name(buf, rdata_start)?;
                RData::Cname(target)
            }
            other => RData::Other(other),
        };
        answers.push(Rr { name, ttl, data });
        pos = rdata_end;
    }

    Ok(ParsedResponse { id, rcode, answers })
}

/// Encode a name (no compression). Rejects labels > 63 bytes.
fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DnsError::BadName);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Ok(())
}

/// Build a response to `query` with `rcode` and (optionally) `answers`.
/// Echoes the question; sets QR=1, RA=1, and copies RD.
pub fn build_response(query: &Query, rcode: u8, answers: &[Answer]) -> Vec<u8> {
    // Encode the answer section first so `ancount` counts only records we could
    // actually encode: a record whose owner name (or CNAME target) won't encode
    // is skipped whole, never emitted half-written — a truncated record would
    // desync the guest's parse of the entire packet.
    let mut ans_buf = Vec::new();
    let mut ancount: u16 = 0;
    for a in answers {
        let mut rec = Vec::new();
        if encode_name(&a.name, &mut rec).is_err() {
            continue;
        }
        rec.extend_from_slice(&a.data.rtype().to_be_bytes());
        rec.extend_from_slice(&CLASS_IN.to_be_bytes());
        rec.extend_from_slice(&a.ttl.to_be_bytes());
        match &a.data {
            RecordData::A(ip) => {
                rec.extend_from_slice(&4u16.to_be_bytes());
                rec.extend_from_slice(&ip.octets());
            }
            RecordData::Aaaa(ip) => {
                rec.extend_from_slice(&16u16.to_be_bytes());
                rec.extend_from_slice(&ip.octets());
            }
            RecordData::Cname(target) => {
                // RDATA is the encoded target name (uncompressed — compression is
                // optional when encoding and guests parse plain names fine).
                let mut rd = Vec::new();
                if encode_name(target, &mut rd).is_err() {
                    continue;
                }
                rec.extend_from_slice(&(rd.len() as u16).to_be_bytes());
                rec.extend_from_slice(&rd);
            }
        }
        ans_buf.extend_from_slice(&rec);
        ancount += 1;
    }

    let mut out = Vec::with_capacity(64 + ans_buf.len());
    // Header.
    out.extend_from_slice(&query.id.to_be_bytes());
    let mut flags: u16 = 1 << 15; // QR
    if query.rd {
        flags |= 1 << 8; // RD
    }
    flags |= 1 << 7; // RA
    flags |= (rcode as u16) & 0x0f;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&ancount.to_be_bytes()); // ancount (encodable records)
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount

    // Question (echoed). If the name is somehow unencodable, drop to root — the
    // rcode still conveys the verdict.
    let _ = encode_name(&query.question.name, &mut out);
    out.extend_from_slice(&query.question.qtype.to_be_bytes());
    out.extend_from_slice(&query.question.qclass.to_be_bytes());

    out.extend_from_slice(&ans_buf);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw query for `name`/`qtype` (single question, RD=1).
    fn raw_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&(1u16 << 8).to_be_bytes()); // RD
        b.extend_from_slice(&1u16.to_be_bytes()); // qd
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar
        encode_name(name, &mut b).unwrap();
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b
    }

    #[test]
    fn parse_basic_query() {
        let q = parse_query(&raw_query(0x1234, "example.com", TYPE_A)).unwrap();
        assert_eq!(q.id, 0x1234);
        assert!(q.rd);
        assert_eq!(q.question.name, "example.com");
        assert_eq!(q.question.qtype, TYPE_A);
        assert_eq!(q.question.qclass, CLASS_IN);
    }

    #[test]
    fn rejects_short_response_and_multiq() {
        assert_eq!(parse_query(&[0u8; 4]).unwrap_err(), DnsError::TooShort);
        // QR=1 => response
        let mut r = raw_query(1, "a.b", TYPE_A);
        r[2] |= 0x80;
        assert_eq!(parse_query(&r).unwrap_err(), DnsError::NotAQuery);
        // qdcount=2
        let mut m = raw_query(1, "a.b", TYPE_A);
        m[5] = 2;
        assert_eq!(parse_query(&m).unwrap_err(), DnsError::NotOneQuestion);
    }

    #[test]
    fn truncated_name_is_rejected() {
        let mut q = raw_query(1, "example.com", TYPE_A);
        q.truncate(14); // cut into the name
        assert!(parse_query(&q).is_err());
    }

    #[test]
    fn response_echoes_question_and_answers() {
        let q = parse_query(&raw_query(0xbeef, "host.example", TYPE_A)).unwrap();
        let ans = vec![Answer {
            name: "host.example".into(),
            ttl: 300,
            data: RecordData::A(Ipv4Addr::new(93, 184, 216, 34)),
        }];
        let resp = build_response(&q, RCODE_NOERROR, &ans);
        // QR set, rcode 0, ancount 1.
        assert_eq!(resp[2] & 0x80, 0x80);
        assert_eq!(resp[3] & 0x0f, RCODE_NOERROR);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        // The A record's rdata is the IP.
        assert!(resp.windows(4).any(|w| w == [93, 184, 216, 34]));
    }

    #[test]
    fn refused_has_no_answers() {
        let q = parse_query(&raw_query(1, "blocked.test", TYPE_A)).unwrap();
        let resp = build_response(&q, RCODE_REFUSED, &[]);
        assert_eq!(resp[3] & 0x0f, RCODE_REFUSED);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ancount 0
    }

    #[test]
    fn build_query_roundtrips_through_parse_query() {
        let q = parse_query(&build_query(0x7788, "www.example.com", TYPE_A).unwrap()).unwrap();
        assert_eq!(q.id, 0x7788);
        assert_eq!(q.question.name, "www.example.com");
        assert_eq!(q.question.qtype, TYPE_A);
    }

    #[test]
    fn parse_response_extracts_a_aaaa_cname() {
        // Craft a response for example.com/A with an A and an AAAA answer.
        let q = parse_query(&build_query(0x4242, "example.com", TYPE_A).unwrap()).unwrap();
        let two = vec![
            Answer {
                name: "example.com".into(),
                ttl: 100,
                data: RecordData::A(Ipv4Addr::new(5, 6, 7, 8)),
            },
            Answer {
                name: "example.com".into(),
                ttl: 50,
                data: RecordData::Aaaa("2001:db8::1".parse().unwrap()),
            },
        ];
        let msg = build_response(&q, RCODE_NOERROR, &two);

        let parsed = parse_response(&msg).unwrap();
        assert_eq!(parsed.id, 0x4242);
        assert_eq!(parsed.rcode, RCODE_NOERROR);
        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.answers[0].data, RData::A(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(parsed.answers[0].ttl, 100);
        assert_eq!(
            parsed.answers[1].data,
            RData::Aaaa("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn build_response_encodes_cname_chain_intact() {
        // a CNAME must survive into the guest-facing response, or
        // glibc/curl discard the mismatched-owner A record as "no answer".
        let q = parse_query(&build_query(0xca11, "cache.nixos.org", TYPE_A).unwrap()).unwrap();
        let chain = vec![
            Answer {
                name: "cache.nixos.org".into(),
                ttl: 60,
                data: RecordData::Cname("dualstack.n.sni.global.fastly.net".into()),
            },
            Answer {
                name: "dualstack.n.sni.global.fastly.net".into(),
                ttl: 30,
                data: RecordData::A(Ipv4Addr::new(146, 75, 121, 91)),
            },
        ];
        let msg = build_response(&q, RCODE_NOERROR, &chain);
        assert_eq!(u16::from_be_bytes([msg[6], msg[7]]), 2); // ancount 2

        let parsed = parse_response(&msg).unwrap();
        assert_eq!(parsed.answers.len(), 2);
        // The CNAME comes first, owned by the queried name, targeting the CDN host.
        assert_eq!(parsed.answers[0].name, "cache.nixos.org");
        assert_eq!(
            parsed.answers[0].data,
            RData::Cname("dualstack.n.sni.global.fastly.net".into())
        );
        // The A record is owned by the CNAME target — the chain a stub follows.
        assert_eq!(parsed.answers[1].name, "dualstack.n.sni.global.fastly.net");
        assert_eq!(
            parsed.answers[1].data,
            RData::A(Ipv4Addr::new(146, 75, 121, 91))
        );
    }

    #[test]
    fn build_response_skips_unencodable_record_and_fixes_ancount() {
        // A record whose name won't encode (empty label) is dropped whole, and
        // ancount reflects only the record that survived — never a half-written
        // record that would desync the guest's parse.
        let q = parse_query(&build_query(1, "a.test", TYPE_A).unwrap()).unwrap();
        let ans = vec![
            Answer {
                name: "bad..name".into(),
                ttl: 1,
                data: RecordData::A(Ipv4Addr::LOCALHOST),
            },
            Answer {
                name: "a.test".into(),
                ttl: 1,
                data: RecordData::A(Ipv4Addr::new(1, 2, 3, 4)),
            },
        ];
        let msg = build_response(&q, RCODE_NOERROR, &ans);
        assert_eq!(u16::from_be_bytes([msg[6], msg[7]]), 1); // only the good one
        let parsed = parse_response(&msg).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].data, RData::A(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn parse_response_rejects_truncated_rdata() {
        let q = parse_query(&build_query(1, "a.test", TYPE_A).unwrap()).unwrap();
        let mut msg = build_response(
            &q,
            RCODE_NOERROR,
            &[Answer {
                name: "a.test".into(),
                ttl: 1,
                data: RecordData::A(Ipv4Addr::LOCALHOST),
            }],
        );
        msg.truncate(msg.len() - 2); // chop into the A rdata
        assert!(parse_response(&msg).is_err());
    }

    #[test]
    fn decode_name_follows_compression_pointer() {
        // "example.com" at offset 12, then a pointer to it later.
        let mut buf = vec![0u8; 12];
        encode_name("example.com", &mut buf).unwrap();
        let ptr_at = buf.len();
        buf.push(0xc0);
        buf.push(12); // pointer -> offset 12
        let (name, next) = decode_name(&buf, ptr_at).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(next, ptr_at + 2);
    }
}
