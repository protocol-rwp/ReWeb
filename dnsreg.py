import contextlib
import json
import os
import re
import sys
import time

try:
    import fcntl
except ImportError:
    fcntl = None

BASE = os.path.dirname(os.path.abspath(__file__))
DNS_FILE = os.path.join(BASE, "dns.json")
REQUESTS_FILE = os.path.join(BASE, "dns_requests.json")
SERVER_FILE = os.path.join(BASE, "dns_server.json")
TLDS_FILE = os.path.join(BASE, "tlds.json")
ROOTS_FILE = os.path.join(BASE, "dns_roots.json")
LOCK_FILE = os.path.join(BASE, ".dnsreg.lock")

MAX_PENDING = 200
DEFAULT_TTL = 300
MIN_TTL = 30
MAX_TTL = 86400
MAX_ALIAS_HOPS = 8
REQUEST_COOLDOWN = 30

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
NAME_RE = re.compile(r"^" + LABEL + r"(?:\." + LABEL + r")*$")
WILD_RE = re.compile(r"^\*(?:\." + LABEL + r")+$")
TLD_RE = re.compile(r"^" + LABEL + r"$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

last_request_at = {}

USAGE = """python3 dnsreg.py list                  pending requests
python3 dnsreg.py approve <name>        move a request into the zone
python3 dnsreg.py reject <name>         drop a request
python3 dnsreg.py zone                  show the live zone
python3 dnsreg.py add <name> <host:port> [ttl]
python3 dnsreg.py alias <name> <target> [ttl]
python3 dnsreg.py remove <name>
python3 dnsreg.py resolve <name>        answer a query the way clients see it
python3 dnsreg.py roots                 show the TLD to DNS server map
"""


class DnsError(Exception):
    pass


class NXDomain(DnsError):
    pass


class NotAuthoritative(DnsError):
    pass


@contextlib.contextmanager
def registry_lock():
    if fcntl == None:
        yield
        return
    handle = open(LOCK_FILE, "w")
    fcntl.flock(handle, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


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


def server_config():
    cfg = load_file(SERVER_FILE, {})
    tld = str(cfg.get("tld", "")).strip().lower().lstrip(".")
    if tld == "" or not TLD_RE.match(tld):
        raise DnsError("Set this server's TLD in " + os.path.basename(SERVER_FILE) + ' (e.g. {"tld": "site", "owner": "me"}).')
    owner = cfg.get("owner")
    if not owner:
        owner = tld
    return tld, str(owner)


def claim_tld():
    tld, owner = server_config()
    tlds = load_file(TLDS_FILE, {})
    if tld in tlds and tlds[tld] != owner:
        raise DnsError("TLD '." + tld + "' belongs to another DNS server (" + str(tlds[tld]) + ").")
    if tld not in tlds:
        tlds[tld] = owner
        save_file(TLDS_FILE, tlds)
    return tld


def clean_ttl(ttl):
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        return DEFAULT_TTL
    if ttl < MIN_TTL:
        ttl = MIN_TTL
    if ttl > MAX_TTL:
        ttl = MAX_TTL
    return ttl


def normalize_records(raw):
    records = {}
    if raw == None:
        raw = {}
    for name in raw:
        value = raw[name]
        name = str(name).strip().lower()
        if name == "":
            continue
        if isinstance(value, str):
            records[name] = {"address": value.strip().lower(), "ttl": DEFAULT_TTL}
            continue
        if not isinstance(value, dict):
            continue
        ttl = clean_ttl(value.get("ttl", DEFAULT_TTL))
        if value.get("alias"):
            record = {"alias": str(value["alias"]).strip().lower(), "ttl": ttl}
        elif value.get("address"):
            record = {"address": str(value["address"]).strip().lower(), "ttl": ttl}
        else:
            continue
        if value.get("added"):
            record["added"] = str(value["added"])[:200]
        if value.get("contact"):
            record["contact"] = str(value["contact"])[:200]
        records[name] = record
    return records


def load_zone():
    raw = load_file(DNS_FILE, {})
    if isinstance(raw, dict) and "records" in raw:
        records = normalize_records(raw.get("records"))
        serial = int(raw.get("serial") or 0)
        tld = str(raw.get("tld") or "").strip().lower()
    else:
        if isinstance(raw, dict):
            records = normalize_records(raw)
        else:
            records = normalize_records({})
        serial = 0
        tld = ""
    if tld == "":
        try:
            tld, owner = server_config()
        except DnsError:
            tld = ""
    return {"tld": tld, "serial": serial, "records": records}


def save_zone(zone):
    data = {}
    data["tld"] = zone.get("tld", "")
    data["serial"] = int(zone.get("serial") or 0) + 1
    data["records"] = zone.get("records", {})
    save_file(DNS_FILE, data)


def load_dns():
    zone = load_zone()
    flat = {}
    for name in zone["records"]:
        if name.startswith("*."):
            continue
        try:
            flat[name] = resolve(name, zone)["address"]
        except DnsError:
            continue
    return flat


def load_requests():
    requests = load_file(REQUESTS_FILE, [])
    if isinstance(requests, list):
        return requests
    return []


def validate_name(name, allow_wildcard=False):
    tld, owner = server_config()
    if name == None:
        name = ""
    name = name.strip().lower().rstrip(".")
    if name == "" or len(name) > 253:
        raise DnsError("Name must be 1-253 characters.")
    if name.startswith("*."):
        if allow_wildcard == False:
            raise DnsError("Wildcard names can only be added by the operator.")
        if not WILD_RE.match(name):
            raise DnsError("Wildcard names look like *.mysite.site.")
    elif not NAME_RE.match(name):
        raise DnsError("Name must be letters, digits, hyphens and dots (e.g. mysite.site).")
    if name.split(".")[-1] != tld:
        raise NotAuthoritative("This DNS server only serves ." + tld + " names (e.g. mysite." + tld + "). Other TLDs have their own DNS server - see dns_roots.json.")
    if name == tld:
        raise DnsError("'" + tld + "' is the TLD itself and cannot be registered.")
    return name


def validate_address(address):
    if address == None:
        address = ""
    address = address.strip().lower()
    if ":" not in address:
        raise DnsError("Address must look like host:port (e.g. 203.0.113.5:5001).")
    i = address.rindex(":")
    host = address[:i]
    port = address[i + 1:]
    if not port.isdigit() or int(port) < 1 or int(port) > 65535:
        raise DnsError("Address must look like host:port (e.g. 203.0.113.5:5001).")
    if IPV4_RE.match(host):
        for part in host.split("."):
            if int(part) > 255:
                raise DnsError("Invalid IPv4 address.")
    elif not NAME_RE.match(host):
        raise DnsError("Invalid host in address.")
    return host + ":" + str(int(port))


def lookup(records, name):
    if name in records:
        return records[name]
    labels = name.split(".")
    for cut in range(1, len(labels)):
        wildcard = "*." + ".".join(labels[cut:])
        if wildcard in records:
            return records[wildcard]
    return None


def resolve(name, zone=None):
    if not zone:
        zone = load_zone()
    records = zone["records"]
    name = validate_name(name, allow_wildcard=True)

    chain = [name]
    ttl = MAX_TTL
    current = name
    for hop in range(MAX_ALIAS_HOPS):
        record = lookup(records, current)
        if record == None:
            raise NXDomain("No record for '" + name + "'.")
        record_ttl = clean_ttl(record.get("ttl", DEFAULT_TTL))
        if record_ttl < ttl:
            ttl = record_ttl
        if "address" in record:
            return {"name": name, "address": record["address"], "ttl": ttl, "chain": chain}
        target = record.get("alias", "")
        if target in chain:
            raise DnsError("Alias loop at '" + target + "'.")
        chain.append(target)
        current = target
    raise DnsError("Alias chain for '" + name + "' is too long.")


def add_record(name, address, ttl=DEFAULT_TTL, contact="", overwrite=False):
    name = validate_name(name, allow_wildcard=True)
    address = validate_address(address)
    with registry_lock():
        zone = load_zone()
        if name in zone["records"] and overwrite == False:
            raise DnsError("'" + name + "' is already registered (use --force to replace).")
        record = {}
        record["address"] = address
        record["ttl"] = clean_ttl(ttl)
        record["added"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if contact:
            record["contact"] = contact.strip()[:200]
        zone["records"][name] = record
        save_zone(zone)
    return name, address


def add_alias(name, target, ttl=DEFAULT_TTL, overwrite=False):
    name = validate_name(name, allow_wildcard=True)
    target = validate_name(target, allow_wildcard=False)
    if name == target:
        raise DnsError("A name cannot be an alias for itself.")
    with registry_lock():
        zone = load_zone()
        if name in zone["records"] and overwrite == False:
            raise DnsError("'" + name + "' is already registered (use --force to replace).")
        zone["records"][name] = {"alias": target, "ttl": clean_ttl(ttl), "added": time.strftime("%Y-%m-%d %H:%M:%S")}
        save_zone(zone)
        try:
            resolve(name, load_zone())
        except DnsError as e:
            raise DnsError("Alias added, but it does not resolve: " + str(e))
    return name, target


def remove_record(name):
    if name == None:
        name = ""
    name = name.strip().lower()
    with registry_lock():
        zone = load_zone()
        if name not in zone["records"]:
            raise NXDomain("No record for '" + name + "'.")
        del zone["records"][name]
        save_zone(zone)
    return name


def throttle(client_ip):
    if not client_ip:
        return
    now = time.monotonic()
    if client_ip in last_request_at:
        last = last_request_at[client_ip]
        if now - last < REQUEST_COOLDOWN:
            wait = int(REQUEST_COOLDOWN - (now - last)) + 1
            raise DnsError("Too many requests; try again in " + str(wait) + " seconds.")
    last_request_at[client_ip] = now


def add_request(name, address, contact="", client_ip=""):
    claim_tld()
    name = validate_name(name, allow_wildcard=False)
    address = validate_address(address)
    throttle(client_ip)
    with registry_lock():
        if name in load_zone()["records"]:
            raise DnsError("'" + name + "' is already registered.")
        pending = load_requests()
        for r in pending:
            if r.get("name") == name:
                raise DnsError("'" + name + "' already has a pending request.")
        if len(pending) >= MAX_PENDING:
            raise DnsError("Too many pending requests; try again later.")
        if contact == None:
            contact = ""
        new_request = {}
        new_request["name"] = name
        new_request["address"] = address
        new_request["contact"] = contact.strip()[:200]
        new_request["requested"] = time.strftime("%Y-%m-%d %H:%M:%S")
        pending.append(new_request)
        save_file(REQUESTS_FILE, pending)
    return name


def pop_request(name, pending):
    if name == None:
        name = ""
    name = name.strip().lower()
    for i in range(len(pending)):
        if pending[i].get("name") == name:
            return pending.pop(i)
    raise NXDomain("No pending request for '" + name + "'.")


def approve(name):
    with registry_lock():
        pending = load_requests()
        request = pop_request(name, pending)
        zone = load_zone()
        if request["name"] in zone["records"]:
            raise DnsError("'" + request["name"] + "' is already registered.")
        record = {"address": request["address"], "ttl": DEFAULT_TTL, "added": time.strftime("%Y-%m-%d %H:%M:%S")}
        if request.get("contact"):
            record["contact"] = request["contact"]
        zone["records"][request["name"]] = record
        save_zone(zone)
        save_file(REQUESTS_FILE, pending)
    return request


def reject(name):
    with registry_lock():
        pending = load_requests()
        request = pop_request(name, pending)
        save_file(REQUESTS_FILE, pending)
    return request


def load_roots():
    raw = load_file(ROOTS_FILE, {})
    tlds = None
    hosts = None
    if isinstance(raw, dict):
        tlds = raw.get("tlds")
        hosts = raw.get("hosts")
    if not tlds:
        tlds = {}
    if not hosts:
        hosts = {}
    result = {"tlds": {}, "hosts": {}}
    for k in tlds:
        result["tlds"][str(k).lower()] = str(tlds[k])
    for k in hosts:
        result["hosts"][str(k).lower()] = str(hosts[k])
    return result


def server_info():
    tld, owner = server_config()
    zone = load_zone()
    info = {}
    info["tld"] = tld
    info["owner"] = owner
    info["serial"] = zone["serial"]
    info["records"] = len(zone["records"])
    info["pending"] = len(load_requests())
    info["default_ttl"] = DEFAULT_TTL
    return info


def describe(record):
    if "address" in record:
        return "-> " + record["address"]
    return "~> " + str(record.get("alias", "?")) + " (alias)"


def main(argv):
    args = []
    force = False
    for a in argv[1:]:
        if a == "--force":
            force = True
        else:
            args.append(a)
    if len(args) > 0:
        cmd = args[0]
    else:
        cmd = "list"
    try:
        if cmd == "list":
            pending = load_requests()
            if len(pending) == 0:
                print("No pending requests.")
            for r in pending:
                print(r["name"].ljust(30) + " " + r["address"].ljust(24) + " " + r["requested"] + "  " + r.get("contact", ""))

        elif cmd == "zone":
            zone = load_zone()
            print("zone ." + zone["tld"] + "  serial " + str(zone["serial"]) + "  " + str(len(zone["records"])) + " record(s)")
            for name in sorted(zone["records"]):
                record = zone["records"][name]
                print("  " + name.ljust(30) + " " + describe(record).ljust(40) + " ttl=" + str(record.get("ttl", DEFAULT_TTL)))

        elif cmd == "approve" and len(args) == 2:
            request = approve(args[1])
            print("approved " + request["name"] + " -> " + request["address"])

        elif cmd == "reject" and len(args) == 2:
            request = reject(args[1])
            print("rejected " + request["name"])

        elif cmd == "add" and (len(args) == 3 or len(args) == 4):
            if len(args) == 4:
                ttl = args[3]
            else:
                ttl = DEFAULT_TTL
            name, address = add_record(args[1], args[2], ttl, overwrite=force)
            print("added " + name + " -> " + address)

        elif cmd == "alias" and (len(args) == 3 or len(args) == 4):
            if len(args) == 4:
                ttl = args[3]
            else:
                ttl = DEFAULT_TTL
            name, target = add_alias(args[1], args[2], ttl, overwrite=force)
            print("added " + name + " ~> " + target)

        elif cmd == "remove" and len(args) == 2:
            print("removed " + remove_record(args[1]))

        elif cmd == "resolve" and len(args) == 2:
            answer = resolve(args[1])
            path = " -> ".join(answer["chain"])
            print(path + " => " + answer["address"] + " (ttl " + str(answer["ttl"]) + ")")

        elif cmd == "roots":
            roots = load_roots()
            for host in sorted(roots["hosts"]):
                print("  host  " + host.ljust(24) + " " + roots["hosts"][host])
            for tld in sorted(roots["tlds"]):
                print("  ." + tld.ljust(24) + " DNS server at " + roots["tlds"][tld])
            if len(roots["hosts"]) == 0 and len(roots["tlds"]) == 0:
                print("No roots configured in " + os.path.basename(ROOTS_FILE) + ".")

        else:
            print(USAGE)
            return 1
    except DnsError as e:
        print("error: " + str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
