//! The TLS ClientHello at the start of a TCP stream (RFC 8446): its server name (RFC 6066)
//! and whether it carries ECH (`encrypted_client_hello`, RFC 9849).

use super::{MAX_HELLO, Named, Sniff, host_name};

pub(super) const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_NAME: u16 = 0;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
/// Largest TLS record payload (plaintext, plus the slack RFC 8446 allows).
const MAX_RECORD: usize = 16 * 1024 + 256;

/// Reads the ClientHello from the first bytes of a stream; it may span several records.
pub fn stream(data: &[u8]) -> Sniff<Named> {
    let mut message = Vec::new();
    let mut pos = 0;
    loop {
        let Some(header) = data.get(pos..pos + 5) else {
            return partial_record(&data[pos..]);
        };
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[0] != HANDSHAKE || header[1] != 3 || length == 0 || length > MAX_RECORD {
            return Sniff::NotIt;
        }
        let Some(payload) = data.get(pos + 5..pos + 5 + length) else {
            message.extend_from_slice(&data[pos + 5..]);
            return match handshake(&message) {
                Sniff::Done(hello) => Sniff::Done(hello),
                _ if message.len() > MAX_HELLO + 4 => Sniff::NotIt,
                other => other,
            };
        };
        message.extend_from_slice(payload);
        pos += 5 + length;
        match handshake(&message) {
            Sniff::NeedMore if message.len() <= MAX_HELLO + 4 => {}
            Sniff::NeedMore => return Sniff::NotIt,
            done => return done,
        }
    }
}

/// The start of a record header: TLS if what is there fits one.
fn partial_record(rest: &[u8]) -> Sniff<Named> {
    match rest {
        [] | [HANDSHAKE] | [HANDSHAKE, 3, ..] => Sniff::NeedMore,
        _ => Sniff::NotIt,
    }
}

/// Reads a ClientHello handshake message (type, 24-bit length, body), possibly incomplete.
pub fn handshake(message: &[u8]) -> Sniff<Named> {
    let Some(header) = message.get(..4) else {
        return match message.first() {
            None | Some(&CLIENT_HELLO) => Sniff::NeedMore,
            Some(_) => Sniff::NotIt,
        };
    };
    let length =
        usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
    if header[0] != CLIENT_HELLO || length > MAX_HELLO {
        return Sniff::NotIt;
    }
    match message.get(4..4 + length) {
        None => Sniff::NeedMore,
        Some(body) => client_hello(body).map_or(Sniff::NotIt, Sniff::Done),
    }
}

/// Reads the server name and the ECH extension from a ClientHello's body.
fn client_hello(body: &[u8]) -> Option<Named> {
    let mut r = Reader(body);
    r.take(2 + 32)?; // legacy_version, random
    r.vector(1)?; // legacy_session_id
    r.vector(2)?; // cipher_suites
    r.vector(1)?; // legacy_compression_methods
    let mut hello = Named::default();
    if r.0.is_empty() {
        return Some(hello); // no extensions (TLS 1.0 style)
    }
    let mut extensions = Reader(r.vector(2)?);
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vector(2)?;
        match kind {
            SERVER_NAME => hello.name = server_name(data)?,
            // ECHClientHello: type 0 is outer (sent on the wire), 1 inner.
            ENCRYPTED_CLIENT_HELLO => hello.ech = data.first() == Some(&0),
            _ => {}
        }
    }
    Some(hello)
}

/// The first host name in a `server_name` extension; `Some(None)` if it holds none usable.
fn server_name(data: &[u8]) -> Option<Option<String>> {
    let mut list = Reader(Reader(data).vector(2)?);
    while !list.0.is_empty() {
        let kind = list.take(1)?[0];
        let name = list.vector(2)?;
        if kind == 0 {
            return Some(host_name(name));
        }
    }
    Some(None)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// A vector with a 1- or 2-byte length prefix.
    fn vector(&mut self, prefix: usize) -> Option<&'a [u8]> {
        let length = match prefix {
            1 => usize::from(self.take(1)?[0]),
            _ => usize::from(self.u16()?),
        };
        self.take(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hello, records, sni};

    fn named(name: &str) -> Sniff<Named> {
        Sniff::Done(Named {
            name: Some(name.into()),
            ech: false,
        })
    }

    /// A real ClientHello, as rustls sends it.
    fn rustls_hello(name: &str) -> Vec<u8> {
        let roots = rustls::RootCertStore::empty();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            std::sync::Arc::new(config),
            name.to_owned().try_into().unwrap(),
        )
        .unwrap();
        let mut out = Vec::new();
        client.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn reads_real_client_hello_byte_by_byte() {
        let stream_bytes = rustls_hello("Www.Example.com");
        assert_eq!(stream(&stream_bytes), named("www.example.com"));
        for end in 0..stream_bytes.len() {
            assert_eq!(stream(&stream_bytes[..end]), Sniff::NeedMore, "{end}");
        }
        // Bytes after the ClientHello change nothing.
        let mut more = stream_bytes.clone();
        more.extend([23, 3, 3, 0, 1, 0]);
        assert_eq!(stream(&more), named("www.example.com"));
    }

    #[test]
    fn reads_hellos_across_records_and_ech() {
        let big = hello(&[
            (0x11ec, vec![9; 1500]),
            sni("big.example"),
            (0xfe0d, vec![0, 1, 2]),
        ]);
        let split = records(&big, 1000);
        assert_eq!(
            stream(&split),
            Sniff::Done(Named {
                name: Some("big.example".into()),
                ech: true,
            })
        );
        assert_eq!(stream(&split[..1200]), Sniff::NeedMore);
        // Inner ECH (type 1) never appears on the wire; it does not count.
        let inner = hello(&[sni("a.example"), (0xfe0d, vec![1])]);
        assert_eq!(stream(&records(&inner, 100)), named("a.example"));
        let none = hello(&[(0x10, vec![0, 3, 2, b'h', b'2'])]);
        assert_eq!(stream(&records(&none, 512)), Sniff::Done(Named::default()));
        let ip = hello(&[sni("192.0.2.1")]);
        assert_eq!(stream(&records(&ip, 512)), Sniff::Done(Named::default()));
    }

    #[test]
    fn rejects_other_protocols_and_garbage() {
        for data in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"SSH-2.0-OpenSSH_9.9\r\n",
            &[22, 4],
            &[23, 3, 3, 0, 5, 1, 2, 3, 4, 5],
            &[22, 3, 1, 0, 0],
            &[22, 3, 1, 0, 4, 2, 0, 0, 0],
        ] {
            assert_eq!(stream(data), Sniff::NotIt, "{data:?}");
        }
        // A handshake message claiming more than the limit.
        assert_eq!(stream(&[22, 3, 1, 0, 4, 1, 0, 0x40, 1]), Sniff::NotIt);
        // Truncated or overlong fields inside a complete message.
        let good = hello(&[sni("x.example")]);
        for cut in 4..good.len() {
            let mut bad = good[..cut].to_vec();
            let length = (cut - 4) as u32;
            bad[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
            let result = stream(&records(&bad, 512));
            assert!(
                matches!(result, Sniff::NotIt | Sniff::Done(_)),
                "{cut}: {result:?}"
            );
        }
    }
}
