# ReWeb

<img src="https://github.com/protocol-rwp/ReWeb/blob/main/reweb.png?raw=true" alt="Screenshot" width="70%">

ReWeb is a from-scratch alternative to the web.
Using its own transport protocol instead of HTTP, its own decentralized naming system instead of DNS.
[Quick install](/install.sh)
[Protocol spec](/SPEC.md)

- **Decentralized DNS** (`dnsroots.py`, `dnsresolve.py`, `dnsreg.py`) TLDs
  are owned by whoever holds the Ed25519 key that first claimed them.
  Claims and zone answers are signed, and servers gossip-sync claims with
   their peers instead of relying on a central root.

- **Server** (`server.py`) serves static files and DNS endpoints, and can
   run server-side `.rws` scripts.

- **RWS scripting** (`jsengine.py`, `runner.js`) server-side JavaScript
   pages that can expose functions to the client as a generated
    `window.server.*` RPC.

- **RWP** (`rwp.py`) the protocol.

- **Browser** (`browser.py`, `scheme.py`) example of a ReWeb browser.

## Requirements
- Python 3 with `cryptography` (install it with `pip install cryptography`).
- Node.js (only needed for running servers that host `.rws` server scripts).
- php-cgi (only needed for running servers that host `.php` pages. install with `sudo apt install php-cgi`).
- GTK 3, WebKit2GTK 4.1, and `pywebview` (only needed to run the example browser).

## Running a server
`python3 server.py` serves files from `www/`, change `host:port` in `server.py`.

## Running the example browser
`python3 browser.py`.

## Claiming a TLD

Each server can claim ownership of one top-level domain by signing a claim
 with its local key: `python3 dnsroots.py claim <your-host>:<port>`.
Other servers pick up your claim (and you pick up theirs) via
`python3 dnsroots.py sync`, once you've added each other as peers with
`python3 dnsroots.py peer <host>:<port>`.

## Encryption
RWP connections are encrypted with TLS on the same port as plain RWP, so
old clients keep working. On first start `server.py` creates
`rwp_tls_key.pem` / `rwp_tls_cert.pem` and prints its **TLS fingerprint**.
Keep the key file private and back it up: deleting it changes the fingerprint.

Publish the fingerprint in DNS so browsers can check they reached the real server:
`python3 dnsreg.py fingerprint mysite.rws <fingerprint>` (or include a
`fingerprint` field in a name request).

What the browser does:
- **Fingerprint in DNS:** TLS is required and the server key must match, with no
  fallback. The status bar says "encrypted, server key verified".
- **No fingerprint:** it uses TLS if the server supports it ("encrypted").
  It only falls back to plain RWP ("NOT encrypted") for servers that don't
  support TLS, and it never falls back for an address that has already used TLS.

Upgrade a server **before** adding its fingerprint, or lookups for that name will fail.
Fingerprints are only fully trustworthy when the TLD key is pinned (below),
because the pin is what makes the DNS answer itself trustworthy.

## Pinning a TLD key
Claims are first-come, so a browser that has never seen a TLD will accept
whichever claim reaches it first. To lock a TLD to its real owner, pin the
owner's public key in `dns_roots.json`:

```json
{
    "tlds": {"rws": "24.144.109.255:5000"},
    "keys": {"rws": "<64 hex chars from: python3 dnsroots.py pubkey>"}
}
```

Once a key is pinned, answers for that TLD must be signed by that key, and
claims signed by any other key are ignored. Make sure the DNS server has a key
(`python3 dnsroots.py claim <host>:<port>`) **before** shipping the pin, or
lookups for that TLD will fail.

## Where to get a free site name
In the ReWeb browser enter `reweb.rws/request.html` into the input bar and fill out the form.

## What this is
This is my implementation of the ReWeb (the codes not perfect lol),
 Anyone can make a new implementation, a new browser etc. 
 - [See the license](LICENSE)
