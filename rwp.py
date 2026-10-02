import hashlib
import json
import os
import re
import socket
import ssl
import struct
import threading
import time

SCHEME = "reweb"
DEFAULT_PORT = 5001

MAGIC = b"RWP1"
PREFIX = struct.Struct(">4sII")
MAX_HEADER = 65536
MAX_REQUEST_BODY = 1000000
MAX_RESPONSE_BODY = 64000000

VERB_FETCH = "FETCH"
VERB_SEND = "SEND"

TLS_FIRST_BYTE = b"\x16"
TLS_KEY_FILE = "rwp_tls_key.pem"
TLS_CERT_FILE = "rwp_tls_cert.pem"
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
PLAINTEXT_RETRY = 600

SECURITY_VERIFIED = "verified"
SECURITY_ENCRYPTED = "encrypted"
SECURITY_PLAIN = "plain"

tls_lock = threading.Lock()
tls_seen = set()
plaintext_until = {}


class ProtocolError(OSError):
    pass


def encode(header, body=b""):
    if isinstance(body, str):
        body = body.encode()
    head = json.dumps(header, separators=(",", ":")).encode()
    return PREFIX.pack(MAGIC, len(head), len(body)) + head + body


def read_exact(conn, count, deadline=None):
    chunks = []
    timeout = conn.gettimeout()
    while count > 0:
        if deadline != None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise socket.timeout("took too long to send the message")
            if timeout == None or left < timeout:
                conn.settimeout(left)
        chunk = conn.recv(min(count, 65536))
        if not chunk:
            raise ProtocolError("connection closed in the middle of a message")
        chunks.append(chunk)
        count = count - len(chunk)
    return b"".join(chunks)


def read_frame(conn, max_body, deadline=None):
    prefix = read_exact(conn, PREFIX.size, deadline)
    magic, head_len, body_len = PREFIX.unpack(prefix)
    if magic != MAGIC:
        raise ProtocolError("not an RWP message")
    if head_len > MAX_HEADER:
        raise ProtocolError("header too large")
    if body_len > max_body:
        raise ProtocolError("body too large")
    try:
        header = json.loads(read_exact(conn, head_len, deadline).decode("utf-8"))
    except ValueError as e:
        raise ProtocolError("malformed header")
    if not isinstance(header, dict):
        raise ProtocolError("malformed header")
    return header, read_exact(conn, body_len, deadline)


def clean_fingerprint(value):
    if not isinstance(value, str):
        return None
    value = value.strip().lower().replace(":", "")
    if FINGERPRINT_RE.match(value):
        return value
    return None


def cert_fingerprint(der):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    key = x509.load_der_x509_certificate(der).public_key()
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def server_context(directory):
    cert_file, key_file = ensure_certificate(directory)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


def ensure_certificate(directory):
    cert_file = os.path.join(directory, TLS_CERT_FILE)
    key_file = os.path.join(directory, TLS_KEY_FILE)
    if os.path.isfile(cert_file) and os.path.isfile(key_file):
        return cert_file, key_file
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "reweb server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=36500))
            .sign(key, hashes.SHA256()))
    pem_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem_key)
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_file, key_file


def server_fingerprint(directory):
    cert_file, key_file = ensure_certificate(directory)
    with open(cert_file, "rb") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read().decode())
    return cert_fingerprint(der)


def accept_tls(conn, ctx):
    first = conn.recv(1, socket.MSG_PEEK)
    if first == TLS_FIRST_BYTE:
        return ctx.wrap_socket(conn, server_side=True)
    return conn


def split_address(address):
    if address.startswith(SCHEME + "://"):
        address = address[len(SCHEME) + 3:]
    address = address.split("/", 1)[0]
    if ":" in address:
        host, port = address.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return address, DEFAULT_PORT


def open_connection(address, timeout, fingerprint=None, tls="auto"):
    host, port = split_address(address)
    fingerprint = clean_fingerprint(fingerprint)
    now = time.monotonic()
    with tls_lock:
        seen = address in tls_seen
        plain_ok = plaintext_until.get(address, 0) > now
    if fingerprint == None and not seen and (tls == "off" or (tls == "auto" and plain_ok)):
        return socket.create_connection((host, port), timeout=timeout), SECURITY_PLAIN
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        conn = client_context().wrap_socket(raw)
    except ssl.SSLError as e:
        raw.close()
        if fingerprint != None or seen or tls == "require":
            raise ProtocolError("secure connection to " + address + " failed: " + str(e))
        with tls_lock:
            plaintext_until[address] = now + PLAINTEXT_RETRY
        return socket.create_connection((host, port), timeout=timeout), SECURITY_PLAIN
    except OSError:
        raw.close()
        raise
    with tls_lock:
        tls_seen.add(address)
        plaintext_until.pop(address, None)
    if fingerprint == None:
        return conn, SECURITY_ENCRYPTED
    if cert_fingerprint(conn.getpeercert(binary_form=True)) != fingerprint:
        conn.close()
        raise ProtocolError("server key for " + address + " does not match the fingerprint published in DNS")
    return conn, SECURITY_VERIFIED


def request(address, verb, path, body=b"", content_type=None, call=None, cookie=None, timeout=10, max_body=MAX_RESPONSE_BODY, fingerprint=None):
    header, data, security = secure_request(address, verb, path, body, content_type, call, cookie, timeout, max_body, fingerprint)
    return header, data


def secure_request(address, verb, path, body=b"", content_type=None, call=None, cookie=None, timeout=10, max_body=MAX_RESPONSE_BODY, fingerprint=None, tls="auto"):
    if isinstance(body, str):
        body = body.encode()
    header = {"verb": verb, "path": path}
    if content_type:
        header["type"] = content_type
    if call:
        header["call"] = call
    if cookie:
        header["cookie"] = cookie
    conn, security = open_connection(address, timeout, fingerprint, tls)
    with conn:
        conn.sendall(encode(header, body))
        header, data = read_frame(conn, max_body)
    return header, data, security


def fetch(address, path, timeout=10, max_body=MAX_RESPONSE_BODY):
    return request(address, VERB_FETCH, path, timeout=timeout, max_body=max_body)
