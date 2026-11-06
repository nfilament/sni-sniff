//! The ClientHello in a client's QUIC Initial packets (RFC 9000, RFC 9001 §5; QUIC v2:
//! RFC 9369). Their protection uses keys derived from the destination connection ID and a
//! published salt, so anyone on the path can read them. Chrome splits the ClientHello into
//! many CRYPTO frames in random order, and with post-quantum key shares across two
//! datagrams: frames are reassembled by offset.

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, quic::HeaderProtectionKey};
use ring::hkdf::{self, HKDF_SHA256, Prk, Salt};

use super::{MAX_HELLO, Named, Sniff, tls};

const V1: u32 = 1;
const V2: u32 = 0x6b33_43cf;
const V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
/// Out-of-order pieces of the ClientHello kept apart before giving up.
const MAX_PIECES: usize = 64;

/// Reads the ClientHello from a client's first datagrams, one `push` per datagram.
///
/// Each Initial packet costs an AES-128-GCM decryption, so a caller should push only a
/// flow's first few datagrams.
#[derive(Default)]
pub struct Initial {
    crypto: Vec<u8>,
    /// Received byte ranges of the CRYPTO stream, sorted and merged.
    have: Vec<(usize, usize)>,
}

impl Initial {
    /// A reader for a new flow.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads one datagram the client sent (Initial packets, possibly coalesced with
    /// others, which are skipped). `NotIt` for a datagram without a client Initial that
    /// opens and parses.
    pub fn push(&mut self, datagram: &[u8]) -> Sniff<Named> {
        let mut rest = datagram;
        let mut initials = 0;
        // Coalesced packets: Initial, then possibly 0-RTT; only Initials are read.
        while let Some(packet) = LongPacket::parse(rest) {
            rest = &rest[packet.end..];
            if !packet.initial {
                continue;
            }
            let Some((_, _, payload)) = packet.open() else {
                return Sniff::NotIt;
            };
            if self.frames(&payload).is_none() {
                return Sniff::NotIt;
            }
            initials += 1;
        }
        if initials == 0 {
            return Sniff::NotIt;
        }
        match self.have.first() {
            Some(&(0, end)) => tls::handshake(&self.crypto[..end]),
            _ => Sniff::NeedMore,
        }
    }

    fn frames(&mut self, mut payload: &[u8]) -> Option<()> {
        while let Some((&kind, rest)) = payload.split_first() {
            payload = rest;
            match kind {
                0x00 | 0x01 => {} // PADDING, PING
                0x02 | 0x03 => {
                    // ACK: largest, delay, range count, first range, ranges, ECN counts.
                    varint(&mut payload)?;
                    varint(&mut payload)?;
                    let ranges = varint(&mut payload)?;
                    varint(&mut payload)?;
                    for _ in 0..ranges.min(payload.len() as u64) * 2 {
                        varint(&mut payload)?;
                    }
                    if kind == 0x03 {
                        for _ in 0..3 {
                            varint(&mut payload)?;
                        }
                    }
                }
                0x06 => {
                    let offset = usize::try_from(varint(&mut payload)?).ok()?;
                    let length = usize::try_from(varint(&mut payload)?).ok()?;
                    let data = payload.get(..length)?;
                    payload = &payload[length..];
                    self.insert(offset, data)?;
                }
                0x1c => {
                    varint(&mut payload)?;
                    varint(&mut payload)?;
                    let length = usize::try_from(varint(&mut payload)?).ok()?;
                    payload = payload.get(length..)?;
                }
                _ => return None, // not allowed in Initial packets
            }
        }
        Some(())
    }

    fn insert(&mut self, offset: usize, data: &[u8]) -> Option<()> {
        let end = offset.checked_add(data.len())?;
        if end > MAX_HELLO + 4 {
            return None;
        }
        if data.is_empty() {
            return Some(());
        }
        if self.crypto.len() < end {
            self.crypto.resize(end, 0);
        }
        self.crypto[offset..end].copy_from_slice(data);
        self.have.push((offset, end));
        self.have.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.have.len());
        for &(start, end) in &self.have {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        self.have = merged;
        (self.have.len() <= MAX_PIECES).then_some(())
    }
}

/// What a client's Initial packet shows to anyone on the path, for looking at a QUIC
/// client's first flight (for example, comparing it with a browser's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialPacket {
    /// QUIC version: 1, or `0x6b3343cf` for v2.
    pub version: u32,
    /// Destination connection ID.
    pub dcid: Vec<u8>,
    /// Source connection ID.
    pub scid: Vec<u8>,
    /// Length of the token (non-zero after a Retry, or with a token from a previous
    /// connection).
    pub token_len: usize,
    /// Packet number.
    pub pn: u64,
    /// Length of the packet number on the wire (1 to 4 bytes).
    pub pn_len: usize,
    /// The whole packet, header and AEAD tag included.
    pub size: usize,
    /// The frames, in the order sent.
    pub frames: Vec<Frame>,
}

/// A frame of an Initial packet; runs of PADDING are one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// This many PADDING bytes in a row.
    Padding(usize),
    /// PING.
    Ping,
    /// ACK (with or without ECN counts).
    Ack,
    /// CRYPTO: a piece of the ClientHello at this offset.
    Crypto {
        /// Offset in the CRYPTO stream.
        offset: usize,
        /// The piece.
        data: Vec<u8>,
    },
    /// CONNECTION_CLOSE.
    Close,
}

/// The Initial packets of a client's datagram, opened; other packets are skipped, and an
/// Initial that does not open or parse ends the list.
pub fn inspect(datagram: &[u8]) -> Vec<InitialPacket> {
    let mut packets = Vec::new();
    let mut rest = datagram;
    while let Some(packet) = LongPacket::parse(rest) {
        rest = &rest[packet.end..];
        if !packet.initial {
            continue;
        }
        let Some((pn, pn_len, payload)) = packet.open() else {
            break;
        };
        let Some(frames) = frame_list(&payload) else {
            break;
        };
        packets.push(InitialPacket {
            version: packet.version,
            dcid: packet.dcid.to_vec(),
            scid: packet.scid.to_vec(),
            token_len: packet.token_len,
            pn,
            pn_len,
            size: packet.end,
            frames,
        });
    }
    packets
}

fn frame_list(mut payload: &[u8]) -> Option<Vec<Frame>> {
    let mut frames = Vec::new();
    while let Some((&kind, rest)) = payload.split_first() {
        let before = payload.len();
        payload = rest;
        match kind {
            0x00 => match frames.last_mut() {
                Some(Frame::Padding(n)) => *n += 1,
                _ => frames.push(Frame::Padding(1)),
            },
            0x01 => frames.push(Frame::Ping),
            0x02 | 0x03 => {
                varint(&mut payload)?;
                varint(&mut payload)?;
                let ranges = varint(&mut payload)?;
                varint(&mut payload)?;
                for _ in 0..ranges.min(payload.len() as u64) * 2 {
                    varint(&mut payload)?;
                }
                if kind == 0x03 {
                    for _ in 0..3 {
                        varint(&mut payload)?;
                    }
                }
                frames.push(Frame::Ack);
            }
            0x06 => {
                let offset = usize::try_from(varint(&mut payload)?).ok()?;
                let length = usize::try_from(varint(&mut payload)?).ok()?;
                let data = payload.get(..length)?.to_vec();
                payload = &payload[length..];
                frames.push(Frame::Crypto { offset, data });
            }
            0x1c => {
                varint(&mut payload)?;
                varint(&mut payload)?;
                let length = usize::try_from(varint(&mut payload)?).ok()?;
                payload = payload.get(length..)?;
                frames.push(Frame::Close);
            }
            _ => return None,
        }
        debug_assert!(payload.len() < before);
    }
    Some(frames)
}

/// A client Initial packet carrying `frames`, padded to 1200 bytes, protected as a
/// client would.
#[cfg(any(test, feature = "testing"))]
pub(super) fn seal(version: u32, dcid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
    let keys = Keys::client(version, dcid).unwrap();
    let kind = if version == V1 { 0 } else { 1 };
    let mut packet = vec![0xc0 | kind << 4 | 3]; // 4-byte packet number
    packet.extend(version.to_be_bytes());
    packet.push(dcid.len() as u8);
    packet.extend(dcid);
    packet.extend([0, 0]); // no source CID, no token
    let mut payload = frames.to_vec();
    payload.resize(1200 - packet.len() - 2 - 4 - 16, 0);
    super::testing::put_varint(&mut packet, (4 + payload.len() + 16) as u64);
    let pn_offset = packet.len();
    packet.extend(pn.to_be_bytes());
    let mut nonce = keys.iv;
    for (n, p) in nonce[4..].iter_mut().zip(u64::from(pn).to_be_bytes()) {
        *n ^= p;
    }
    keys.key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&packet.clone()),
            &mut payload,
        )
        .unwrap();
    packet.extend(payload);
    let mask = keys
        .hp
        .new_mask(&packet[pn_offset + 4..pn_offset + 20])
        .unwrap();
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..4 {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    packet
}

/// A long-header packet at the start of `data`.
struct LongPacket<'a> {
    data: &'a [u8],
    version: u32,
    initial: bool,
    dcid: &'a [u8],
    scid: &'a [u8],
    token_len: usize,
    /// Where the (protected) packet number starts, and where the packet ends.
    pn_offset: usize,
    end: usize,
}

impl<'a> LongPacket<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let first = *data.first()?;
        if first & 0xc0 != 0xc0 {
            return None; // short header, or not QUIC
        }
        let version = u32::from_be_bytes(data.get(1..5)?.try_into().ok()?);
        let kind = (first >> 4) & 3;
        let (initial, retry) = match version {
            V1 => (kind == 0, kind == 3),
            V2 => (kind == 1, kind == 0),
            _ => return None,
        };
        if retry {
            return None;
        }
        let mut r = &data[5..];
        let dcid = cid(&mut r)?;
        let scid = cid(&mut r)?;
        let mut token_len = 0;
        if initial {
            token_len = usize::try_from(varint(&mut r)?).ok()?;
            r = r.get(token_len..)?;
        }
        let length = usize::try_from(varint(&mut r)?).ok()?;
        let pn_offset = data.len() - r.len();
        let end = pn_offset.checked_add(length)?;
        if end > data.len() || length < 20 {
            return None;
        }
        Some(Self {
            data: &data[..end],
            version,
            initial,
            dcid,
            scid,
            token_len,
            pn_offset,
            end,
        })
    }

    /// Removes header protection and decrypts the payload with the client's Initial keys:
    /// the packet number, its length and the payload.
    fn open(&self) -> Option<(u64, usize, Vec<u8>)> {
        let keys = Keys::client(self.version, self.dcid)?;
        let sample = self.data.get(self.pn_offset + 4..self.pn_offset + 20)?;
        let mask = keys.hp.new_mask(sample).ok()?;
        let mut header = self.data[..self.pn_offset + 4].to_vec();
        header[0] ^= mask[0] & 0x0f;
        let pn_len = usize::from(header[0] & 3) + 1;
        header.truncate(self.pn_offset + pn_len);
        let mut pn = 0u64;
        for (i, byte) in header[self.pn_offset..].iter_mut().enumerate() {
            *byte ^= mask[1 + i];
            pn = pn << 8 | u64::from(*byte);
        }
        let mut nonce = keys.iv;
        for (n, p) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
            *n ^= p;
        }
        let mut payload = self.data[self.pn_offset + pn_len..].to_vec();
        let plain = keys
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&header),
                &mut payload,
            )
            .ok()?;
        let length = plain.len();
        payload.truncate(length);
        Some((pn, pn_len, payload))
    }
}

/// A connection ID with its length byte (at most 20 bytes, RFC 9000 §17.2).
fn cid<'a>(r: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (&length, rest) = r.split_first()?;
    let length = usize::from(length);
    if length > 20 {
        return None;
    }
    let id = rest.get(..length)?;
    *r = &rest[length..];
    Some(id)
}

/// A QUIC variable-length integer (RFC 9000 §16).
fn varint(r: &mut &[u8]) -> Option<u64> {
    let first = *r.first()?;
    let length = 1 << (first >> 6);
    let bytes = r.get(..length)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = value << 8 | u64::from(*byte);
    }
    *r = &r[length..];
    Some(value)
}

struct Keys {
    key: LessSafeKey,
    iv: [u8; 12],
    hp: HeaderProtectionKey,
}

impl Keys {
    fn client(version: u32, dcid: &[u8]) -> Option<Self> {
        let (key, iv, hp) = secrets(version, dcid)?;
        Some(Self {
            key: LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).ok()?),
            iv,
            hp: HeaderProtectionKey::new(&aead::quic::AES_128, &hp).ok()?,
        })
    }
}

/// The client's Initial packet key, IV and header protection key.
fn secrets(version: u32, dcid: &[u8]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let (salt, prefix) = match version {
        V1 => (&V1_SALT, "quic"),
        _ => (&V2_SALT, "quicv2"),
    };
    let initial = Salt::new(HKDF_SHA256, salt).extract(dcid);
    let secret: [u8; 32] = expand(&initial, "client in")?;
    let secret = Prk::new_less_safe(HKDF_SHA256, &secret);
    Some((
        expand(&secret, &format!("{prefix} key"))?,
        expand(&secret, &format!("{prefix} iv"))?,
        expand(&secret, &format!("{prefix} hp"))?,
    ))
}

/// HKDF-Expand-Label with an empty context (RFC 8446 §7.1).
fn expand<const N: usize>(prk: &Prk, label: &str) -> Option<[u8; N]> {
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let label = format!("tls13 {label}");
    let info = [
        &(N as u16).to_be_bytes()[..],
        &[label.len() as u8],
        label.as_bytes(),
        &[0],
    ];
    let mut out = [0; N];
    prk.expand(&info, Len(N)).ok()?.fill(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::seal;
    use super::*;
    use crate::testing::{crypto, hello, sni};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn derived(version: u32) -> ([u8; 16], [u8; 12], [u8; 16]) {
        secrets(version, &hex("8394c8f03e515708")).unwrap()
    }

    /// RFC 9001 Appendix A.1 and RFC 9369 Appendix A.1.
    #[test]
    fn initial_keys_match_the_rfcs() {
        let (key, iv, hp) = derived(V1);
        assert_eq!(key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
        let (key, iv, hp) = derived(V2);
        assert_eq!(key.to_vec(), hex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(iv.to_vec(), hex("91f73e2351d8fa91660e909f"));
        assert_eq!(hp.to_vec(), hex("45b95e15235d6f45a6b19cbcb0294ba9"));
    }

    #[test]
    fn reads_out_of_order_crypto_across_datagrams() {
        let message = hello(&[(0x11ec, vec![5; 1400]), sni("Quic.Example")]);
        let dcid = [1, 2, 3, 4, 5, 6, 7, 8];
        for version in [V1, V2] {
            // Chrome style: pieces out of order with PING and PADDING between them.
            let mut first = crypto(600, &message[600..900]);
            first.extend([0x01, 0x00, 0x00]);
            first.extend(crypto(0, &message[..600]));
            let mut second = crypto(900, &message[900..]);
            second.extend([0x02, 0x00, 0x00, 0x00, 0x00]); // ACK
            let mut sniffer = Initial::new();
            assert_eq!(
                sniffer.push(&seal(version, &dcid, 0, &first)),
                Sniff::NeedMore
            );
            assert_eq!(
                sniffer.push(&seal(version, &dcid, 1, &second)),
                Sniff::Done(Named {
                    name: Some("quic.example".into()),
                    ech: false
                })
            );
        }
    }

    #[test]
    fn rejects_other_datagrams() {
        let dcid = [9; 8];
        let good = seal(V1, &dcid, 0, &crypto(0, &hello(&[sni("a.example")])));
        assert!(matches!(Initial::new().push(&good), Sniff::Done(_)));
        let mut tampered = good.clone();
        tampered[100] ^= 1;
        let mut short = good.clone();
        short[0] &= 0x7f;
        let mut unknown = good.clone();
        unknown[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
        let mut cut = good.clone();
        cut.truncate(600);
        let stream = seal(V1, &dcid, 0, &[0x08, 0x00]); // STREAM frame: not in an Initial
        let far = seal(V1, &dcid, 0, &crypto(MAX_HELLO, &[1; 8]));
        for (what, datagram) in [
            ("tampered", tampered),
            ("short header", short),
            ("unknown version", unknown),
            ("truncated", cut),
            ("STREAM frame", stream),
            ("beyond limit", far),
            ("empty", vec![]),
            ("dns", vec![0x12, 0x34, 1, 0, 0, 1]),
        ] {
            assert_eq!(Initial::new().push(&datagram), Sniff::NotIt, "{what}");
        }
        // Every truncation of a good packet is rejected or waited for, never a panic.
        for end in 0..good.len() {
            let _ = Initial::new().push(&good[..end]);
        }
    }

    /// Chrome 155 and Firefox 158 on Android (`testdata/`, captured 2026-10-15).
    #[test]
    fn inspects_browsers_initials() {
        let data = include_str!("../testdata/quic-initials-2026-10-15.txt");
        let datagrams = |browser: &str| -> Vec<Vec<u8>> {
            data.lines()
                .filter(|l| l.starts_with(browser))
                .map(|l| hex(l.rsplit(' ').next().unwrap()))
                .collect()
        };
        let mut sniffer = Initial::new();
        for (i, d) in datagrams("chrome ").iter().enumerate() {
            assert_eq!(d.len(), 1250);
            let p = &inspect(d)[0];
            assert_eq!(
                (p.dcid.len(), p.scid.len(), p.pn, p.size),
                (8, 0, i as u64 + 1, 1250)
            );
            assert!(p.frames.contains(&Frame::Ping));
            let got = sniffer.push(d);
            if i == 1 {
                assert!(
                    matches!(got, Sniff::Done(Named { name: Some(ref n), .. }) if n == "www.google.com")
                );
            }
        }
        let mut sniffer = Initial::new();
        let firefox = datagrams("firefox ");
        let first = &inspect(&firefox[0])[0];
        assert_eq!(
            (firefox[0].len(), first.scid.len(), first.pn_len),
            (1252, 3, 1)
        );
        assert!(first.size < 1252 && firefox[0][first.size..].iter().all(|&b| b == 0));
        assert_eq!(sniffer.push(&firefox[0]), Sniff::NeedMore);
        let got = sniffer.push(&firefox[1]);
        assert!(
            matches!(got, Sniff::Done(Named { name: Some(ref n), .. }) if n == "safebrowsing.googleapis.com")
        );
    }

    /// A real Initial from quinn (rustls), caught on a local socket.
    #[tokio::test]
    async fn reads_quinn_initial() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(crypto)));
        let _connecting = endpoint
            .connect(server.local_addr().unwrap(), "h3.example")
            .unwrap();
        let mut buf = [0; 2048];
        let n = tokio::task::spawn_blocking(move || server.recv(&mut buf).map(|n| (n, buf)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Initial::new().push(&n.1[..n.0]),
            Sniff::Done(Named {
                name: Some("h3.example".into()),
                ech: false
            })
        );
    }
}
