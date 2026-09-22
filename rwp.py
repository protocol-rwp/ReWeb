import json
import socket
import struct

SCHEME = "reweb"
DEFAULT_PORT = 5001

MAGIC = b"RWP1"
PREFIX = struct.Struct(">4sII")
MAX_HEADER = 65536
MAX_REQUEST_BODY = 1000000
MAX_RESPONSE_BODY = 64000000

VERB_FETCH = "FETCH"
VERB_SEND = "SEND"


class ProtocolError(OSError):
    pass


def encode(header, body=b""):
    if isinstance(body, str):
        body = body.encode()
    head = json.dumps(header, separators=(",", ":")).encode()
    return PREFIX.pack(MAGIC, len(head), len(body)) + head + body


def read_exact(conn, count):
    chunks = []
    while count > 0:
        chunk = conn.recv(min(count, 65536))
        if not chunk:
            raise ProtocolError("connection closed in the middle of a message")
        chunks.append(chunk)
        count = count - len(chunk)
    return b"".join(chunks)


def read_frame(conn, max_body):
    prefix = read_exact(conn, PREFIX.size)
    magic, head_len, body_len = PREFIX.unpack(prefix)
    if magic != MAGIC:
        raise ProtocolError("not an RWP message")
    if head_len > MAX_HEADER:
        raise ProtocolError("header too large")
    if body_len > max_body:
        raise ProtocolError("body too large")
    try:
        header = json.loads(read_exact(conn, head_len).decode("utf-8"))
    except ValueError as e:
        raise ProtocolError("malformed header")
    if not isinstance(header, dict):
        raise ProtocolError("malformed header")
    return header, read_exact(conn, body_len)


def split_address(address):
    if address.startswith(SCHEME + "://"):
        address = address[len(SCHEME) + 3:]
    address = address.split("/", 1)[0]
    if ":" in address:
        host, port = address.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return address, DEFAULT_PORT


def request(address, verb, path, body=b"", content_type=None, call=None, timeout=10, max_body=MAX_RESPONSE_BODY):
    if isinstance(body, str):
        body = body.encode()
    header = {"verb": verb, "path": path}
    if content_type:
        header["type"] = content_type
    if call:
        header["call"] = call
    host, port = split_address(address)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(encode(header, body))
        return read_frame(s, max_body)


def fetch(address, path, timeout=10, max_body=MAX_RESPONSE_BODY):
    return request(address, VERB_FETCH, path, timeout=timeout, max_body=max_body)
