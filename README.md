# ReWeb
ReWeb is a from-scratch alternative to the web.
Using its own transport protocol instead of HTTP, its own decentralized naming system instead of DNS.

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

## Where to get a free site name
In the ReWeb browser enter `reweb.rws/request.html` into the input bar and fill out the form.

## What this is
This is my implementation of the ReWeb (the codes not perfect lol),
 Anyone can make a new implementation, a new browser etc. 
 - [See the license](LICENSE)
