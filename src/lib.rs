//! The name a connection is for, read from the first bytes a client sends: the server
//! name (SNI) in a TLS ClientHello over TCP, the same in the Initial packets of QUIC v1 and
//! v2 (decrypted with the keys anyone on the path can derive), and the `Host` header of
//! plain HTTP/1.x. Also whether the ClientHello carries an outer ECH extension, in which
//! case the server name seen is the public one, not the real destination.
//!
//! Made for the middle of a connection: a transparent proxy, a firewall or a VPN that
//! routes by name. Input is untrusted: every length is checked, what is kept is bounded
//! ([`MAX_HELLO`]), and nothing panics. No I/O and no allocation beyond the ClientHello
//! being reassembled.
//!
//! Feed the bytes received so far; the answer says whether the name is known, more bytes
//! are needed, or this is not the protocol:
//!
//! ```
//! use sni_sniff::{Named, Sniff, Protocol};
//!
//! let request = b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n";
//! assert_eq!(sni_sniff::stream(&request[..10]), Sniff::NeedMore);
//! assert_eq!(
//!     sni_sniff::stream(request),
//!     Sniff::Done(Named { name: Some("example.com".into()), ech: false })
//! );
//! assert_eq!(sni_sniff::protocol(request), Protocol::Http);
//! assert_eq!(sni_sniff::stream(b"SSH-2.0-OpenSSH_9.9\r\n"), Sniff::NotIt);
//! ```
//!
//! For QUIC, push each of the client's first datagrams into a [`quic::Initial`]: browsers
//! split the ClientHello over two datagrams and send its pieces out of order.
//!
//! ```
//! use sni_sniff::{Sniff, quic::Initial};
//!
//! let mut initial = Initial::new();
//! # let datagrams: Vec<Vec<u8>> = vec![b"not QUIC".to_vec()];
//! for datagram in &datagrams {
//!     match initial.push(datagram) {
//!         Sniff::Done(named) => { println!("{:?}", named.name); break }
//!         Sniff::NeedMore => continue,
//!         Sniff::NotIt => break,
//!     }
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod http;
pub mod quic;
#[cfg(any(test, feature = "testing"))]
#[doc(hidden)]
pub mod testing;
pub mod tls;

#[cfg(test)]
mod robustness;

/// What the first bytes of a flow said so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniff<T> {
    /// Read: the answer.
    Done(T),
    /// Looks like the protocol, but is not complete yet: call again with more bytes.
    NeedMore,
    /// Not the protocol, or malformed, or longer than this crate reads: more bytes will
    /// not change that.
    NotIt,
}

impl<T> Sniff<T> {
    /// Maps the answer of `Done`.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Sniff<U> {
        match self {
            Sniff::Done(t) => Sniff::Done(f(t)),
            Sniff::NeedMore => Sniff::NeedMore,
            Sniff::NotIt => Sniff::NotIt,
        }
    }
}

/// The name a flow is for (a ClientHello's server name, or HTTP's `Host`), and whether its
/// ClientHello carries an outer ECH extension (real ECH or GREASE: telling them apart needs
/// the ECH configs from DNS).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Named {
    /// The host name, lowercased and without a trailing dot ([`host_name`]); `None` if the
    /// client named none, or only an IP address.
    pub name: Option<String>,
    /// The ClientHello carries an outer `encrypted_client_hello` extension: `name` is then
    /// the public name of the ECH configuration, not necessarily the destination.
    pub ech: bool,
}

/// Reads the name from the first bytes of a TCP stream: a TLS ClientHello (possibly over
/// several records), or a plain HTTP/1.x request.
pub fn stream(data: &[u8]) -> Sniff<Named> {
    match tls::stream(data) {
        Sniff::NotIt => http::stream(data).map(|name| Named { name, ech: false }),
        tls => tls,
    }
}

/// The protocol that named a TCP stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// A TLS ClientHello.
    Tls,
    /// A plain HTTP/1.x request.
    Http,
}

/// Which protocol named a TCP stream (`stream` returned `Done` for `data`).
pub fn protocol(data: &[u8]) -> Protocol {
    match data.first() {
        Some(&tls::HANDSHAKE) => Protocol::Tls,
        _ => Protocol::Http,
    }
}

/// Largest ClientHello read (handshake message, without its header). Post-quantum key
/// shares make Chrome's about 1.8 kB.
pub const MAX_HELLO: usize = 16 * 1024;

/// A host name as it may appear in SNI or `Host`: lowercased, without a trailing dot.
/// `None` for IP literals and anything that is not a plausible DNS name.
pub fn host_name(raw: &[u8]) -> Option<String> {
    let raw = raw.strip_suffix(b".").unwrap_or(raw);
    if raw.is_empty() || raw.len() > 253 {
        return None;
    }
    let valid = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_');
    if !raw.iter().all(valid) || raw.split(|b| *b == b'.').any(|label| label.is_empty()) {
        return None;
    }
    let name = std::str::from_utf8(raw).ok()?.to_ascii_lowercase();
    if name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names() {
        assert_eq!(
            host_name(b"WWW.Example.com.").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            host_name(b"_srv.x-y.example").as_deref(),
            Some("_srv.x-y.example")
        );
        for bad in [
            &b""[..],
            b".",
            b"a..b",
            b".a",
            b"1.2.3.4",
            b"::1",
            b"a b",
            b"\xc3\xa4.example",
            &[b'a'; 254],
        ] {
            assert_eq!(host_name(bad), None, "{bad:?}");
        }
    }
}
