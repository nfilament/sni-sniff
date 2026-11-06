//! Builders of ClientHellos and QUIC Initial packets, for this crate's tests and, with the
//! `testing` feature, tests of code using it. Not a stable API.

use super::quic;

const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_NAME: u16 = 0;

/// A ClientHello handshake message with these extensions (type, data).
pub fn hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend([7; 32]);
    body.extend([32]);
    body.extend([1; 32]);
    body.extend([0, 4, 0x13, 0x01, 0x13, 0x02, 1, 0]);
    let mut ext = Vec::new();
    for (kind, data) in extensions {
        ext.extend(kind.to_be_bytes());
        ext.extend((data.len() as u16).to_be_bytes());
        ext.extend(data);
    }
    body.extend((ext.len() as u16).to_be_bytes());
    body.extend(ext);
    let mut message = vec![CLIENT_HELLO];
    message.extend(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend(body);
    message
}

pub fn sni(name: &str) -> (u16, Vec<u8>) {
    let mut entry = vec![0];
    entry.extend((name.len() as u16).to_be_bytes());
    entry.extend(name.as_bytes());
    let mut data = (entry.len() as u16).to_be_bytes().to_vec();
    data.extend(entry);
    (SERVER_NAME, data)
}

/// The message in records of at most `size` bytes.
pub fn records(message: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in message.chunks(size) {
        out.extend([HANDSHAKE, 3, 1]);
        out.extend((chunk.len() as u16).to_be_bytes());
        out.extend(chunk);
    }
    out
}

/// Appends a QUIC variable-length integer (RFC 9000 §16); `v` below 2^62.
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..64 => out.push(v as u8),
        64..16384 => out.extend((v as u16 | 0x4000).to_be_bytes()),
        16384..0x4000_0000 => out.extend((v as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend((v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

pub fn crypto(offset: usize, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x06];
    put_varint(&mut frame, offset as u64);
    put_varint(&mut frame, data.len() as u64);
    frame.extend(data);
    frame
}

/// A ClientHello naming `name`, with `padding` bytes of an unknown extension, in client
/// Initial packets of QUIC v1 (one per datagram, 1200 bytes each), Chrome style: CRYPTO
/// frames out of order.
pub fn quic_initials(dcid: &[u8], name: &str, padding: usize) -> Vec<Vec<u8>> {
    let message = hello(&[(0x11ec, vec![5; padding]), sni(name)]);
    let mut datagrams = Vec::new();
    for (pn, start) in (0..message.len()).step_by(1000).enumerate() {
        let piece = &message[start..message.len().min(start + 1000)];
        // The second half first, then PING, then the first half.
        let half = piece.len() / 2;
        let mut frames = crypto(start + half, &piece[half..]);
        frames.push(0x01);
        frames.extend(crypto(start, &piece[..half]));
        datagrams.push(quic::seal(1, dcid, pn as u32, &frames));
    }
    datagrams
}
