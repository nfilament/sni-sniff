//! Untrusted input: real browsers' ClientHellos fed at every length, then corrupted at
//! random. Nothing may panic, and a name read is always a valid one.

use super::quic::{self, Frame, Initial, inspect};
use super::testing::records;
use super::{Named, Sniff, host_name, http, stream, tls};

/// The captured QUIC Initial datagrams of `browser` (`testdata/`).
fn datagrams(browser: &str) -> Vec<Vec<u8>> {
    include_str!("../testdata/quic-initials-2026-10-15.txt")
        .lines()
        .filter(|l| l.starts_with(browser))
        .map(|l| {
            let hex = l.rsplit(' ').next().unwrap();
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        })
        .collect()
}

/// The browser's ClientHello handshake message, reassembled from its CRYPTO frames.
fn client_hello(browser: &str) -> Vec<u8> {
    let mut message = Vec::new();
    for datagram in datagrams(browser) {
        for packet in inspect(&datagram) {
            for frame in packet.frames {
                if let Frame::Crypto { offset, data } = frame {
                    if message.len() < offset + data.len() {
                        message.resize(offset + data.len(), 0);
                    }
                    message[offset..offset + data.len()].copy_from_slice(&data);
                }
            }
        }
    }
    message
}

const BROWSERS: [(&str, &str); 2] = [
    ("chrome ", "www.google.com"),
    ("firefox ", "safebrowsing.googleapis.com"),
];

/// A small deterministic generator (xorshift64*), so failures can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// `data` with a few random changes: bytes overwritten, cut short, or bytes inserted.
    fn corrupt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        for _ in 0..1 + self.below(4) {
            if out.is_empty() {
                break;
            }
            let at = self.below(out.len());
            match self.below(4) {
                0 => out.truncate(at),
                1 => out.insert(at, self.next() as u8),
                // Length fields are where parsers go wrong: favour extreme bytes.
                2 => out[at] = [0x00, 0xff, 0x7f, 0x80][self.below(4)],
                _ => out[at] = self.next() as u8,
            }
        }
        out
    }
}

/// A name read must be a valid host name, whatever the input.
fn check(sniff: &Sniff<Named>) {
    if let Sniff::Done(Named {
        name: Some(name), ..
    }) = sniff
    {
        assert_eq!(host_name(name.as_bytes()).as_deref(), Some(name.as_str()));
    }
}

#[test]
fn real_hellos_read_at_every_length() {
    for (browser, name) in BROWSERS {
        let hello = client_hello(browser);
        // A browser's real ClientHello: post-quantum key shares make Chrome's large.
        assert!(hello.len() > 1000, "{browser}: {}", hello.len());
        for size in [16 * 1024, 517, 1] {
            let wire = records(&hello, size);
            for end in 0..wire.len() {
                assert_eq!(
                    stream(&wire[..end]),
                    Sniff::NeedMore,
                    "{browser}{size} at {end}"
                );
            }
            let Sniff::Done(named) = stream(&wire) else {
                panic!("{browser}{size}: not read");
            };
            assert_eq!(named.name.as_deref(), Some(name));
        }
    }
}

#[test]
fn corrupted_tls_and_http_never_panic() {
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    let http = b"GET /index.html HTTP/1.1\r\nHost: www.example.com:443\r\nAccept: */*\r\n\r\n";
    let inputs: Vec<Vec<u8>> = BROWSERS
        .iter()
        .flat_map(|(browser, _)| {
            let hello = client_hello(browser);
            [records(&hello, 16 * 1024), records(&hello, 300), hello]
        })
        .chain([http.to_vec()])
        .collect();
    for round in 0..20_000 {
        let input = rng.corrupt(&inputs[round % inputs.len()]);
        check(&stream(&input));
        check(&tls::stream(&input));
        check(&tls::handshake(&input));
        if let Sniff::Done(Some(name)) = http::stream(&input) {
            assert_eq!(host_name(name.as_bytes()).as_deref(), Some(name.as_str()));
        }
    }
}

#[test]
fn corrupted_quic_initials_never_panic() {
    let mut rng = Rng(0x5eed_1234_abcd_0002);
    let captured: Vec<Vec<u8>> = BROWSERS.iter().flat_map(|(b, _)| datagrams(b)).collect();
    // Every length of each datagram: protection fails, no panic.
    for datagram in &captured {
        for end in 0..datagram.len() {
            let _ = Initial::new().push(&datagram[..end]);
            let _ = inspect(&datagram[..end]);
        }
    }
    for round in 0..5_000 {
        let datagram = rng.corrupt(&captured[round % captured.len()]);
        let mut initial = Initial::new();
        check(&initial.push(&datagram));
        let _ = inspect(&datagram);
    }
    // Valid packets whose decrypted frames are corrupt: the parser, not the AEAD, is hit.
    let hello = client_hello("chrome ");
    for round in 0..5_000 {
        let frames = rng.corrupt(&crate::testing::crypto(0, &hello[..900]));
        let packet = quic::seal(1, &[round as u8; 8], 0, &frames[..frames.len().min(1100)]);
        check(&Initial::new().push(&packet));
        let _ = inspect(&packet);
    }
}
