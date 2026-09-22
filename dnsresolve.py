import json
import os
import sys
import time
import urllib.parse

import dnsroots
import rwp

BASE = os.path.dirname(os.path.abspath(__file__))
ROOTS_FILE = os.path.join(BASE, "dns_roots.json")
CLAIMS_FILE = os.path.join(BASE, "dns_claims.json")

TIMEOUT = 5
NEGATIVE_TTL = 15
MAX_ANSWER = 64000

USAGE = """python3 dnsresolve.py mysite.site       resolve one name
python3 dnsresolve.py --zone site       dump a TLD's zone
"""


class ResolveError(Exception):
    pass


class Answer:
    def __init__(self, name, address, ttl=0, source="", chain=None):
        self.name = name
        self.address = address
        self.ttl = ttl
        self.source = source
        if chain:
            self.chain = chain
        else:
            self.chain = [name]

    def __repr__(self):
        return "<Answer " + self.name + " -> " + self.address + " via " + self.source + ">"


def looks_literal(host):
    if ":" not in host:
        return False
    i = host.rindex(":")
    name = host[:i]
    port = host[i + 1:]
    if port.isdigit() and name != "":
        return True
    return False


class Resolver:
    def __init__(self, roots_file=ROOTS_FILE, timeout=TIMEOUT, local_zone=True):
        self.roots_file = roots_file
        self.timeout = timeout
        self.local_zone = local_zone
        self.cache = {}
        self.roots = {"hosts": {}, "tlds": {}}
        self.roots_mtime = None
        self.load_roots()

    def load_roots(self):
        mtime = (self.mtime(self.roots_file), self.mtime(CLAIMS_FILE))
        if mtime != self.roots_mtime:
            try:
                f = open(self.roots_file, "r", encoding="utf-8")
                raw = json.load(f)
                f.close()
            except (OSError, json.JSONDecodeError):
                raw = {}
            if not isinstance(raw, dict):
                raw = {}
            hosts = {}
            tlds = {}
            tlds.update(dnsroots.tld_map())
            h = raw.get("hosts")
            if h == None:
                h = {}
            for k in h:
                hosts[str(k).strip().lower()] = str(h[k]).strip()
            t = raw.get("tlds")
            if t == None:
                t = {}
            for k in t:
                tlds[str(k).strip().lower().lstrip(".")] = str(t[k]).strip()
            self.roots = {"hosts": hosts, "tlds": tlds}
            self.roots_mtime = mtime
        return self.roots

    def mtime(self, path):
        try:
            return os.path.getmtime(path)
        except OSError:
            return None

    def server_for(self, name):
        tld = name.split(".")[-1]
        roots = self.load_roots()
        return roots["tlds"].get(tld), tld

    def clear_cache(self):
        self.cache.clear()

    def cached(self, name):
        if name not in self.cache:
            return None
        entry = self.cache[name]
        expires_at = entry[0]
        value = entry[1]
        if time.monotonic() >= expires_at:
            del self.cache[name]
            return None
        return value

    def remember(self, name, value, ttl):
        if ttl < 1:
            ttl = 1
        self.cache[name] = (time.monotonic() + ttl, value)

    def get_json(self, server, path):
        try:
            header, body = rwp.fetch(server, path, timeout=self.timeout, max_body=MAX_ANSWER)
            payload = json.loads(body.decode("utf-8"))
        except (rwp.ProtocolError, OSError) as e:
            raise ResolveError("Could not reach DNS server " + server + ": " + str(e))
        except ValueError as e:
            raise ResolveError("DNS server " + server + " sent a malformed answer.")
        if not isinstance(payload, dict):
            raise ResolveError("DNS server " + server + " sent a malformed answer.")
        if header.get("status") != 200:
            if payload.get("error"):
                raise ResolveError(str(payload.get("error")))
            raise ResolveError("DNS server " + server + " returned status " + str(header.get("status")) + ".")
        return payload

    def query(self, server, name):
        path = "/dns/resolve?" + urllib.parse.urlencode({"name": name})
        payload = self.get_json(server, path)
        if payload.get("error"):
            raise ResolveError(str(payload["error"]))
        address = str(payload.get("address") or "")
        if looks_literal(address) == False:
            raise ResolveError("DNS server " + server + " sent no usable address for '" + name + "'.")
        tld = name.split(".")[-1]
        if str(payload.get("name")) != name or payload.get("tld", tld) != tld:
            raise ResolveError("DNS server " + server + " answered for a different name.")
        try:
            status = dnsroots.verify_doc("answer", payload, tld)
        except dnsroots.RootError as e:
            raise ResolveError("Rejected answer from " + server + ": " + str(e))
        ttl = int(payload.get("ttl") or NEGATIVE_TTL)
        if status == "signed":
            ttl = max(1, min(ttl, int(payload["expires"] - time.time())))
        chain = payload.get("chain") or [name]
        source = server
        if status == "signed":
            source = server + ", signed"
        return Answer(name, address, ttl, source, chain)

    def zone(self, tld):
        server = self.load_roots()["tlds"].get(tld.lower().lstrip("."))
        if not server:
            raise ResolveError("No DNS server known for '." + tld + "'.")
        doc = self.get_json(server, "/dns/zone")
        try:
            dnsroots.verify_doc("zone", doc, tld.lower().lstrip("."))
        except dnsroots.RootError as e:
            raise ResolveError("Rejected zone from " + server + ": " + str(e))
        return doc

    def resolve(self, host):
        if host == None:
            host = ""
        name = host.strip().lower().rstrip(".")
        if name == "":
            raise ResolveError("No address given.")

        if looks_literal(name):
            return Answer(name, name, source="literal")

        hosts = self.load_roots()["hosts"]
        if name in hosts:
            return Answer(name, hosts[name], source="hosts")

        cached = self.cached(name)
        if isinstance(cached, ResolveError):
            raise cached
        if cached != None:
            return Answer(cached.name, cached.address, cached.ttl, "cache", cached.chain)

        if "." not in name:
            raise ResolveError("'" + name + "' is not a full name. Try a name with a TLD (e.g. " + name + ".site) or a literal host:port.")

        if self.local_zone:
            answer = self.resolve_locally(name)
            if answer != None:
                self.remember(name, answer, answer.ttl)
                return answer

        server, tld = self.server_for(name)
        if not server:
            dnsroots.sync_if_due()
            server, tld = self.server_for(name)
        if not server:
            error = ResolveError("No DNS server known for '." + tld + "'. No peer has a claim for it (see dnsroots.py peers).")
            self.remember(name, error, NEGATIVE_TTL)
            raise error

        try:
            answer = self.query(server, name)
        except ResolveError as e:
            self.remember(name, e, NEGATIVE_TTL)
            raise
        self.remember(name, answer, answer.ttl)
        return answer

    def resolve_locally(self, name):
        try:
            import dnsreg
        except ImportError:
            return None
        try:
            if name.split(".")[-1] != dnsreg.server_config()[0]:
                return None
            found = dnsreg.resolve(name)
        except dnsreg.NXDomain:
            return None
        except dnsreg.DnsError:
            return None
        return Answer(name, found["address"], found["ttl"], "local zone", found["chain"])


default = None


def get_resolver():
    global default
    if default == None:
        default = Resolver()
    return default


def resolve(host):
    return get_resolver().resolve(host)


def main(argv):
    args = argv[1:]
    resolver = Resolver()
    try:
        if len(args) == 2 and args[0] == "--zone":
            zone = resolver.zone(args[1])
            print("zone ." + str(zone.get("tld", "?")) + "  serial " + str(zone.get("serial", 0)))
            records = zone.get("records") or {}
            for name in sorted(records):
                record = records[name]
                if record.get("address"):
                    target = record.get("address")
                else:
                    target = str(record.get("alias", "?")) + " (alias)"
                print("  " + name.ljust(30) + " -> " + target)
        elif len(args) == 1:
            answer = resolver.resolve(args[0])
            path = " -> ".join(answer.chain)
            print(path + " => " + answer.address)
            print("  via " + answer.source + ", ttl " + str(answer.ttl))
        else:
            print(USAGE)
            return 1
    except ResolveError as e:
        print("error: " + str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
