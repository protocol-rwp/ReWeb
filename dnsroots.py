import json
import os
import re
import sys
import time

import rwp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

BASE = os.path.dirname(os.path.abspath(__file__))
CLAIMS_FILE = os.path.join(BASE, "dns_claims.json")
PEERS_FILE = os.path.join(BASE, "dns_peers.json")
KEY_FILE = os.path.join(BASE, "dns_key.json")
SERVER_FILE = os.path.join(BASE, "dns_server.json")

TIMEOUT = 5
MAX_ANSWER = 512000
MAX_PEERS = 64
MAX_CLAIMS = 5000
MAX_SKEW = 300
SYNC_COOLDOWN = 30

TLD_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
HOSTPORT_RE = re.compile(r"^[A-Za-z0-9.-]+:\d{1,5}$")

USAGE = """python3 dnsroots.py claim <host:port>   sign and publish a claim for this server's TLD
python3 dnsroots.py sync                gossip with peers and merge their claims
python3 dnsroots.py list                show known TLDs and who owns them
python3 dnsroots.py peers               show the peer list
python3 dnsroots.py peer <host:port>    add a peer
"""

last_sync_at = 0


class RootError(Exception):
    pass


def load_file(path, default):
    try:
        f = open(path, "r", encoding="utf-8")
        data = json.load(f)
        f.close()
        return data
    except (OSError, json.JSONDecodeError):
        return default


def save_file(path, data):
    tmp = path + ".tmp"
    f = open(tmp, "w", encoding="utf-8")
    json.dump(data, f, indent=4)
    f.write("\n")
    f.close()
    os.replace(tmp, path)


def signing_bytes(claim):
    body = {}
    for k in ("tld", "server", "pubkey", "seq", "issued"):
        body[k] = claim[k]
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def check_claim(claim):
    if not isinstance(claim, dict):
        raise RootError("claim is not an object")
    try:
        tld = claim["tld"]
        server = claim["server"]
        pubkey = claim["pubkey"]
        seq = claim["seq"]
        issued = claim["issued"]
        sig = claim["sig"]
    except KeyError as e:
        raise RootError("claim is missing " + str(e))
    if not isinstance(tld, str) or not TLD_RE.match(tld):
        raise RootError("bad TLD")
    if not isinstance(server, str) or not HOSTPORT_RE.match(server):
        raise RootError("bad server address")
    if type(seq) != int or type(issued) != int or seq < 1 or issued < 0:
        raise RootError("bad seq or issued")
    if issued > time.time() + MAX_SKEW:
        raise RootError("claim is dated in the future")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
        key.verify(bytes.fromhex(sig), signing_bytes(claim))
    except (ValueError, TypeError, InvalidSignature) as e:
        raise RootError("bad signature")
    return claim


def merge_claim(claims, claim):
    claim = check_claim(claim)
    have = claims.get(claim["tld"])
    if have == None:
        claims[claim["tld"]] = claim
        return True
    if have["pubkey"] != claim["pubkey"]:
        return False
    if claim["seq"] > have["seq"]:
        claims[claim["tld"]] = claim
        return True
    return False


def load_claims():
    raw = load_file(CLAIMS_FILE, {})
    claims = {}
    if not isinstance(raw, dict):
        return claims
    for tld in raw:
        try:
            claim = check_claim(raw[tld])
        except RootError:
            continue
        if claim["tld"] == tld:
            claims[tld] = claim
    return claims


def load_peers():
    raw = load_file(PEERS_FILE, [])
    peers = []
    if isinstance(raw, list):
        for p in raw:
            if isinstance(p, str) and HOSTPORT_RE.match(p) and p not in peers:
                peers.append(p)
    return peers[:MAX_PEERS]


def tld_map():
    result = {}
    claims = load_claims()
    for tld in claims:
        result[tld] = claims[tld]["server"]
    return result


def export():
    return {"claims": list(load_claims().values()), "peers": load_peers()}


def load_key():
    raw = load_file(KEY_FILE, None)
    if isinstance(raw, dict) and "private" in raw:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw["private"]))
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"private": private.hex()}, f)
        f.write("\n")
    return key


def have_key():
    raw = load_file(KEY_FILE, None)
    return isinstance(raw, dict) and "private" in raw


def doc_bytes(kind, doc):
    body = {}
    for k in doc:
        if k != "sig":
            body[k] = doc[k]
    return kind.encode() + b"\n" + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_doc(kind, doc, valid_for):
    doc = dict(doc)
    if not have_key():
        return doc
    now = int(time.time())
    doc["issued"] = now
    doc["expires"] = now + int(valid_for)
    doc["sig"] = load_key().sign(doc_bytes(kind, doc)).hex()
    return doc


def verify_doc(kind, doc, tld):
    claim = load_claims().get(tld)
    if claim == None:
        return "unverified"
    sig = doc.get("sig")
    if not isinstance(sig, str):
        raise RootError("." + tld + " is claimed by a key but this answer is not signed.")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(claim["pubkey"])).verify(bytes.fromhex(sig), doc_bytes(kind, doc))
    except (ValueError, InvalidSignature) as e:
        raise RootError("signature does not match the key that owns ." + tld)
    issued = doc.get("issued")
    expires = doc.get("expires")
    if type(issued) != int or type(expires) != int:
        raise RootError("signed answer has no validity window")
    now = time.time()
    if issued > now + MAX_SKEW:
        raise RootError("signed answer is dated in the future")
    if expires < now:
        raise RootError("signed answer has expired (replayed?)")
    return "signed"


def make_claim(tld, server):
    key = load_key()
    pubkey = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    claims = load_claims()
    seq = 1
    have = claims.get(tld)
    if have != None:
        if have["pubkey"] != pubkey:
            raise RootError("." + tld + " is already claimed by key " + have["pubkey"][:16] + "... and it isn't this server's key.")
        seq = have["seq"] + 1
    claim = {"tld": tld, "server": server, "pubkey": pubkey, "seq": seq, "issued": int(time.time())}
    claim["sig"] = key.sign(signing_bytes(claim)).hex()
    merge_claim(claims, claim)
    save_file(CLAIMS_FILE, claims)
    return claim


def fetch_peer(peer):
    header, body = rwp.fetch(peer, "/dns/roots", timeout=TIMEOUT, max_body=MAX_ANSWER)
    if header.get("status") != 200:
        raise RootError("peer answered " + str(header.get("status")))
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RootError("malformed answer")
    return payload


def sync():
    global last_sync_at
    last_sync_at = time.monotonic()
    claims = load_claims()
    peers = load_peers()
    incoming = []
    reached = 0
    for peer in list(peers):
        try:
            payload = fetch_peer(peer)
        except (OSError, ValueError, RootError):
            continue
        reached += 1
        got = payload.get("claims")
        if isinstance(got, list):
            incoming.extend(got[:MAX_CLAIMS])
        more = payload.get("peers")
        if isinstance(more, list):
            for p in more:
                if isinstance(p, str) and HOSTPORT_RE.match(p) and p not in peers and len(peers) < MAX_PEERS:
                    peers.append(p)

    valid = []
    for c in incoming:
        try:
            valid.append(check_claim(c))
        except RootError:
            pass
    valid.sort(key=lambda c: (c["issued"], c["pubkey"]))
    changed = 0
    for c in valid:
        if merge_claim(claims, c):
            changed += 1
    if changed:
        save_file(CLAIMS_FILE, claims)
    if peers != load_peers():
        save_file(PEERS_FILE, peers)
    return {"peers_reached": reached, "changed": changed}


def sync_if_due():
    if last_sync_at != 0 and time.monotonic() - last_sync_at < SYNC_COOLDOWN:
        return None
    return sync()


def main(argv):
    args = argv[1:]
    try:
        if len(args) == 2 and args[0] == "claim":
            cfg = load_file(SERVER_FILE, {})
            tld = str(cfg.get("tld", "")).strip().lower().lstrip(".")
            if not TLD_RE.match(tld):
                raise RootError("Set this server's TLD in dns_server.json first.")
            claim = make_claim(tld, args[1])
            print("claimed ." + tld + " -> " + claim["server"] + " (seq " + str(claim["seq"]) + ", key " + claim["pubkey"][:16] + "...)")
        elif args == ["sync"]:
            r = sync()
            print("reached " + str(r["peers_reached"]) + " peer(s), " + str(r["changed"]) + " claim(s) updated")
        elif args == ["list"]:
            claims = load_claims()
            for tld in sorted(claims):
                c = claims[tld]
                print("  ." + tld.ljust(16) + " " + c["server"].ljust(24) + " seq " + str(c["seq"]) + "  key " + c["pubkey"][:16] + "...")
            if not claims:
                print("No claims known. Add a peer and run sync.")
        elif args == ["peers"]:
            for p in load_peers():
                print("  " + p)
        elif len(args) == 2 and args[0] == "peer":
            if not HOSTPORT_RE.match(args[1]):
                raise RootError("expected host:port")
            peers = load_peers()
            if args[1] not in peers:
                peers.append(args[1])
                save_file(PEERS_FILE, peers)
        else:
            print(USAGE)
            return 1
    except RootError as e:
        print("error: " + str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# print("esdrfghjk")