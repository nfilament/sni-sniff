//! The `Host` header of a plain HTTP/1.x request at the start of a TCP stream.

use super::{Sniff, host_name};

/// Longest request head read for the `Host` header.
const MAX_HEAD: usize = 8 * 1024;
const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// The host an HTTP request is for (`Done(None)` if it names none, or an IP address).
pub fn stream(data: &[u8]) -> Sniff<Option<String>> {
    let starts = METHODS.iter().any(|m| {
        let n = m.len().min(data.len());
        data[..n] == m[..n]
    });
    if !starts {
        return Sniff::NotIt;
    }
    let head = &data[..data.len().min(MAX_HEAD)];
    // The request line names HTTP/1.x; anything else that starts like a method is not it.
    if let Some(eol) = head.iter().position(|b| *b == b'\n')
        && !head[..eol].windows(7).any(|w| w == b" HTTP/1")
    {
        return Sniff::NotIt;
    }
    // The head ends with an empty line; bare LF line ends are accepted too.
    let Some(end) = head
        .windows(2)
        .position(|w| w == b"\n\n")
        .into_iter()
        .chain(head.windows(3).position(|w| w == b"\n\r\n"))
        .min()
    else {
        return if data.len() >= MAX_HEAD {
            Sniff::NotIt
        } else {
            Sniff::NeedMore
        };
    };
    let mut lines = head[..end].split(|b| *b == b'\n').skip(1);
    let host = lines.find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|b| *b == b':')?;
        line[..colon]
            .eq_ignore_ascii_case(b"host")
            .then(|| line[colon + 1..].trim_ascii())
    });
    Sniff::Done(host.and_then(authority_host))
}

/// The host of `host[:port]`; IPv6 literals (`[::1]:80`) give none.
fn authority_host(authority: &[u8]) -> Option<String> {
    if authority.first() == Some(&b'[') {
        return None;
    }
    let host = match authority.iter().rposition(|b| *b == b':') {
        Some(colon) if authority[colon + 1..].iter().all(u8::is_ascii_digit) => &authority[..colon],
        Some(_) => return None,
        None => authority,
    };
    host_name(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_host() {
        assert_eq!(
            stream(b"GET / HTTP/1.0\nHost: lf.example\n\n"),
            Sniff::Done(Some("lf.example".into())),
            "bare LF line ends"
        );
        let request = b"GET /x HTTP/1.1\r\nUser-Agent: t\r\nhOsT:  Ads.Example:8080 \r\n\r\nbody";
        assert_eq!(stream(request), Sniff::Done(Some("ads.example".into())));
        for end in 0..request.len() - 4 {
            assert_eq!(stream(&request[..end]), Sniff::NeedMore, "{end}");
        }
        for (request, host) in [
            (&b"POST / HTTP/1.0\r\n\r\n"[..], None),
            (b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n", None),
            (b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n", None),
            (b"GET / HTTP/1.1\r\nHost: a.example:x\r\n\r\n", None),
            (
                b"GET / HTTP/1.1\nHost: a.example\n\r\n\r\n",
                Some("a.example"),
            ),
            (
                b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n",
                Some("a.example"),
            ),
        ] {
            assert_eq!(
                stream(request),
                Sniff::Done(host.map(Into::into)),
                "{request:?}"
            );
        }
    }

    #[test]
    fn rejects_others() {
        for data in [
            &b"\x16\x03\x01"[..],
            b"GETX",
            b"SSH-2.0",
            b"PRI * HTTP/2.0\r\n",
            b"GET /\r\n", // HTTP/0.9
            b"POST\x00\x01\n",
        ] {
            assert_eq!(stream(data), Sniff::NotIt, "{data:?}");
        }
        let mut endless = b"GET / HTTP/1.1\r\n".to_vec();
        endless.resize(MAX_HEAD + 10, b'a');
        assert_eq!(stream(&endless), Sniff::NotIt);
    }
}
