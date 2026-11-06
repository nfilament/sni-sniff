# sni-sniff

Reads the name a connection is for from the first bytes a client sends:

- the server name (SNI) in a **TLS** ClientHello over TCP, also when it spans several
  records;
- the same in the client's **QUIC** Initial packets (v1 and v2), decrypted with the keys
  anyone on the path can derive from them, with the ClientHello's pieces reassembled across
  datagrams and in any order (browsers split it, and post-quantum key shares make it span
  two datagrams);
- the `Host` header of plain **HTTP/1.x**;
- whether the ClientHello carries an outer **ECH** extension: the name seen is then the
  public one, not necessarily the destination.

It is meant for code in the middle of a connection: a transparent proxy, a firewall, or a
VPN that routes or filters by name. It does no I/O; you hand it the bytes received so far.

```rust
use sni_sniff::{Named, Sniff};

let request = b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n";
assert_eq!(sni_sniff::stream(&request[..10]), Sniff::NeedMore);
assert_eq!(
    sni_sniff::stream(request),
    Sniff::Done(Named { name: Some("example.com".into()), ech: false })
);
```

`Sniff::NeedMore` asks for more bytes, `Sniff::NotIt` says more bytes will not help (another
protocol, malformed, or larger than the crate reads). For QUIC, push each of the client's
first datagrams into a `quic::Initial`.

## Untrusted input

Everything is read as hostile: every length is checked before use, what is kept is bounded
(a ClientHello of at most 16 KiB, at most 64 out-of-order pieces of it), and nothing panics.
Names returned are lowercased, without a trailing dot, and only plausible DNS names: IP
literals and anything else give `None`. The tests feed real Chrome and Firefox ClientHellos
at every length and tens of thousands of randomly corrupted ones through every entry point.

Each QUIC Initial packet costs one AES-128-GCM decryption: push only a flow's first few
datagrams.

## Not covered

- QUIC versions other than 1 and 2 (drafts, or versions of a single vendor).
- The inner (encrypted) ClientHello of ECH: reading it needs the server's private key.
- Cleartext HTTP/2 (h2c with prior knowledge): its `:authority` is HPACK-compressed.
- DTLS, and TLS on anything but the start of a stream (STARTTLS).

## Origin, and written with AI

This crate comes from a userspace network stack for an Android VPN app, where it names
connections for routing and filtering rules. Its code, tests and documentation were written
with an AI assistant (Claude) and are maintained by the repository's owner.

## Minimum Rust version

1.88.

## Licence

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
