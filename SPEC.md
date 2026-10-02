# ReWeb Protocol Specification

Version 1 (draft). This describes RWP, the ReWeb transport, and ReWeb DNS,
the naming system. The reference implementation is `rwp.py`, `server.py`,
`dnsroots.py`, `dnsresolve.py` and `dnsreg.py`. Where this document and that
code disagree, please open an issue.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Addresses

```
reweb://<host>[:<port>]/<path>[?<query>]
```

- `host` is either a ReWeb name (`mysite.rws`, see section 5) or a literal
  network host when a port is given (`203.0.113.5:5001`, `example.org:6000`).
- The default port is **5001**.
- A host with a port is used as-is and is not looked up in ReWeb DNS.

## 2. Messages

One connection carries exactly one request and one response. The client
connects, sends a request message, reads a response message, and the
connection is closed.

Both directions use the same frame:

| Field       | Size     | Value                                   |
|-------------|----------|-----------------------------------------|
| magic       | 4 bytes  | ASCII `RWP1`                            |
| header_len  | 4 bytes  | unsigned, big-endian                    |
| body_len    | 4 bytes  | unsigned, big-endian                    |
| header      | header_len bytes | UTF-8 JSON object               |
| body        | body_len bytes   | raw bytes                       |

Limits:

- `header_len` MUST NOT exceed 65,536.
- Request bodies MUST NOT exceed 1,000,000 bytes.
- Clients MAY refuse response bodies larger than 64,000,000 bytes.

A receiver MUST reject a frame with the wrong magic, a header that is not a
JSON object, or a length over its limit. A server SHOULD answer such a frame
with status 400.

### 2.1 Request header

| Key      | Required | Meaning |
|----------|----------|---------|
| `verb`   | yes | `FETCH` (read, like HTTP GET) or `SEND` (submit, like HTTP POST) |
| `path`   | yes | Absolute path, starting with `/`, optionally with `?query` |
| `type`   | no  | Media type of the body, e.g. `application/x-www-form-urlencoded` |
| `cookie` | no  | Cookies for this host, `name=value; name2=value2` |
| `call`   | no  | Name of a server function to call (section 7) |

Unknown keys MUST be ignored.

### 2.2 Response header

| Key        | Required | Meaning |
|------------|----------|---------|
| `status`   | yes | Integer status code, same meanings as HTTP (200, 302, 404, ...) |
| `reason`   | no  | Short text for the status, e.g. `Not Found` |
| `type`     | no  | Media type of the body. Default `application/octet-stream` |
| `location` | no  | Redirect target for 301, 302, 303, 307 and 308 |
| `cookies`  | no  | List of strings, each in HTTP `Set-Cookie` syntax |

Unknown keys MUST be ignored.

### 2.3 Redirects

When `status` is 301, 302, 303, 307 or 308 and `location` is present, the
client SHOULD follow it, up to 5 redirects. `location` is either a full
`reweb://` URL or a path, resolved against the current host and path. The
follow-up request is always a `FETCH` with no body.

### 2.4 Cookies

Cookies belong to a single host name. There is no `Domain` attribute. Clients
SHOULD support the `Path`, `Expires` and `Max-Age` attributes, send only
unexpired cookies whose path matches, and send longer paths first. A cookie
whose expiry has passed deletes any stored cookie with the same name and path.

## 3. Encryption (TLS)

RWP MAY run inside TLS on the **same port** as plain RWP.

- A server tells the two apart from the first byte of a connection: `0x16`
  (a TLS handshake record) means TLS. Anything else is plain RWP.
- TLS 1.2 or newer MUST be used.
- Servers use a self-signed certificate. A server's identity is its
  **fingerprint**: the lowercase hex SHA-256 of the DER-encoded
  SubjectPublicKeyInfo of its certificate's public key. Certificate names and
  expiry dates are not checked.

Client rules:

1. If the server's fingerprint is known (section 5.3), the client MUST use
   TLS and MUST close the connection if the fingerprint does not match.
   It MUST NOT fall back to plain RWP.
2. Otherwise the client SHOULD try TLS first. If the handshake fails because
   the server does not speak TLS, it MAY retry with plain RWP.
3. A client MUST NOT fall back to plain RWP for an address that has already
   completed a TLS handshake in the same session.

Clients SHOULD tell the user which of the three cases applies: verified,
encrypted, or not encrypted.

## 4. Signing

ReWeb DNS uses Ed25519. Public keys and signatures are lowercase hex.

**Canonical JSON** is the object serialized with keys sorted and no
whitespace (separators `,` and `:`), UTF-8 encoded.

- **Claims** (section 6) are signed over the canonical JSON of exactly these
  keys: `tld`, `server`, `pubkey`, `seq`, `issued`.
- **Signed documents** (DNS answers and zones) are signed over:
  `<kind>` + `"\n"` + canonical JSON of every key except `sig`,
  where `kind` is `answer` or `zone`. The signature goes in `sig`.
  Signed documents MUST include integer `issued` and `expires` Unix times.
  A client MUST reject one with `issued` more than 300 seconds in the future
  or `expires` more than 300 seconds in the past.

## 5. Names and resolution

### 5.1 Names

A name is dot-separated labels of `a-z`, `0-9` and `-`. Each label is 1–63
characters and does not start or end with `-`. The last label is the **TLD**.
Names are case-insensitive and compared in lowercase.

Each TLD has one DNS server, which serves names under that TLD.

### 5.2 DNS endpoints

A TLD's DNS server answers these requests over RWP:

| Request | Response body (JSON) |
|---------|----------------------|
| `FETCH /dns/resolve?name=<name>` | Answer: `name`, `address` (`host:port`), `ttl` (seconds), `chain` (list of names followed through aliases), `tld`, optional `fingerprint`, and if signed, `issued`, `expires`, `sig` (kind `answer`) |
| `FETCH /dns/zone` | `tld`, `serial`, `records` (name → `{address` or `alias`, `ttl`, optional `fingerprint}`). Signed with kind `zone` |
| `FETCH /dns/info` | `tld`, `owner`, `serial`, `records`, `pending`, `default_ttl` |
| `FETCH /dns/roots` | `claims` (list of claims) and `peers` (list of `host:port`) |
| `SEND /dns/request` | Ask for a new name. JSON body with `name`, `address`, optional `contact` and `fingerprint`. Returns `{"queued": name}` |

Errors use a 4xx status and a body of `{"error": "<message>"}`:

| Status | Meaning |
|--------|---------|
| 400 | Bad request (invalid name, etc.) |
| 404 | Name does not exist |
| 421 | This server is not the DNS server for that TLD |

TTLs are between 30 and 86,400 seconds, default 300. A server MAY support
aliases, followed for at most 8 hops, and wildcard records (`*.example.rws`).

### 5.3 Resolving a name

To resolve `name`, a client:

1. Uses `name` directly if it has a port (section 1).
2. Checks its local hosts table, if it has one.
3. Finds the DNS server for the TLD, from its configuration or from a claim
   (section 6).
4. Sends `FETCH /dns/resolve?name=<name>` to that server.
5. Checks the answer is for the name it asked about.
6. Finds the TLD's key: a **pinned** key from its configuration if there is
   one, otherwise the key in the TLD's claim. If a key is known, the answer
   MUST carry a valid signature from it, or be rejected.
7. Connects to `address`. If the answer has a `fingerprint`, it applies
   client rule 1 of section 3.

Clients SHOULD cache answers for `ttl` seconds, but never past `expires`.

## 6. Claims and peers

Anyone can claim an unclaimed TLD by signing a claim with their key:

```json
{"tld": "rws", "server": "203.0.113.5:5000", "pubkey": "<hex>",
 "seq": 1, "issued": 1790900000, "sig": "<hex>"}
```

- `server` is the TLD's DNS server as `host:port`.
- `seq` is a positive integer. The owner raises it to publish an update.
- `issued` is a Unix time. Claims dated more than 300 seconds in the future
  MUST be rejected.

Nodes exchange claims by fetching `/dns/roots` from their **peers**. A node
MAY add peers it learns about this way, up to a limit (64 in the reference
implementation).

A node keeps at most one claim per TLD, and decides like this:

| Incoming claim | Result |
|----------------|--------|
| Signature invalid | Reject |
| TLD has a pinned key, and the claim's key differs | Reject |
| TLD has no stored claim | Accept |
| Same key as the stored claim, higher `seq` | Accept (replaces it) |
| Different key from the stored claim | Reject (first claim wins) |

When several new claims for the same TLD arrive at once, the one with the
lowest `issued` wins. Because `issued` is chosen by the claimant, clients
SHOULD pin the keys of TLDs they rely on.

## 7. Server functions (optional)

A server MAY let pages call functions on the server. The client sends `SEND`
to the page's own path with `call` set to the function name, `type` set to
`application/json`, and a body of `{"args": [...]}`. The server replies with
`{"result": <value>}` or, on failure, `{"error": "<message>"}`.

## 8. Security considerations

- Plain RWP is not encrypted. Anyone on the network path can read or change
  it. Use TLS (section 3) and publish fingerprints.
- Without a pinned TLD key, the first claim a node sees wins, and an attacker
  can win that race by backdating `issued`.
- There is no way to transfer or revoke a TLD. Losing a TLD's private key
  means losing control of the TLD.
- Cookies are sent with every request to their host, including requests
  started by other sites.
