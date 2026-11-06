# Changelog

## 0.1.0 (2026-11-06)

First release:
- `stream`: the server name of a TCP stream's TLS ClientHello (over one or more records),
  or the `Host` of a plain HTTP/1.x request, and whether the ClientHello carries an outer
  ECH extension; `protocol` tells which of the two it was.
- `quic::Initial`: the server name in a client's QUIC v1 or v2 Initial packets, with the
  ClientHello's CRYPTO frames reassembled across datagrams and out of order.
- `quic::inspect`: the frames and header fields of a client's Initial packets.
- `host_name`: the normalisation applied to every name returned.
- The `testing` feature: builders of ClientHellos and Initial packets for tests.
