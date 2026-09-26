import socket
import os
import html
import json
from urllib.parse import urlsplit, parse_qs, unquote

import dnsreg
import dnsroots
import jsengine
import phpengine
import rwp

HOST = "127.0.0.1"
PORT = rwp.DEFAULT_PORT

BASE = os.path.dirname(os.path.abspath(__file__))
WWW_ROOT = os.path.join(BASE, "www")
MAX_BODY = rwp.MAX_REQUEST_BODY

DNS_REQUEST_PATH = "/dns-request"
DNS_RESOLVE_PATH = "/dns/resolve"
DNS_ZONE_PATH = "/dns/zone"
DNS_INFO_PATH = "/dns/info"
DNS_ROOTS_PATH = "/dns/roots"
ZONE_VALID_FOR = 3600
DNS_REQUEST_API_PATH = "/dns/request"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".mp3": "audio/mpeg",
    ".rws": "text/html; charset=utf-8",
    ".php": "text/html; charset=utf-8",
}


def guess_content_type(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in CONTENT_TYPES:
        return CONTENT_TYPES[ext]
    else:
        return "application/octet-stream"


def safe_file_path(url_path):
    decoded = unquote(url_path)
    if "\0" in decoded:
        return None
    relative = os.path.normpath(decoded).lstrip("/\\")
    full = os.path.join(WWW_ROOT, relative)
    if full != WWW_ROOT and not full.startswith(WWW_ROOT + os.sep):
        return None
    return full


def build_response(status_line, body, content_type="text/html; charset=utf-8", location=None):
    code, reason = status_line.split(" ", 1)
    header = {"status": int(code), "reason": reason, "type": content_type}
    if location != None:
        header["location"] = location
    return rwp.encode(header, body)


def parse_body(headers, body):
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    text = body.decode("utf-8", errors="replace")
    if content_type == "application/json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if isinstance(data, dict):
            return data
        else:
            return {}
    result = {}
    parsed = parse_qs(text, keep_blank_values=True)
    for key in parsed:
        result[key] = parsed[key][-1]
    return result


def json_response(status_line, payload):
    return build_response(status_line, json.dumps(payload), "application/json; charset=utf-8")


def dns_status_for(exc):
    if isinstance(exc, dnsreg.NXDomain):
        return "404 Not Found"
    if isinstance(exc, dnsreg.NotAuthoritative):
        return "421 Misdirected Request"
    return "400 Bad Request"


def handle_dns_resolve(query):
    name = query.get("name", [""])[-1]
    if name == None:
        name = ""
    name = name.strip()
    if name == "":
        return json_response("400 Bad Request", {"error": "name is required"})
    try:
        answer = dnsreg.resolve(name)
    except dnsreg.DnsError as e:
        return json_response(dns_status_for(e), {"error": str(e), "name": name.lower()})
    answer["tld"] = answer["name"].split(".")[-1]
    answer = dnsroots.sign_doc("answer", answer, answer["ttl"])
    return json_response("200 OK", answer)


def handle_dns_zone():
    try:
        zone = dnsreg.load_zone()
    except dnsreg.DnsError as e:
        return json_response("500 Internal Server Error", {"error": str(e)})
    records = {}
    for name in zone["records"]:
        record = {}
        for k in zone["records"][name]:
            if k != "contact":
                record[k] = zone["records"][name][k]
        records[name] = record
    doc = {"tld": zone["tld"], "serial": zone["serial"], "records": records}
    return json_response("200 OK", dnsroots.sign_doc("zone", doc, ZONE_VALID_FOR))


def handle_dns_roots():
    return json_response("200 OK", dnsroots.export())


def handle_dns_info():
    try:
        info = dnsreg.server_info()
        return json_response("200 OK", info)
    except dnsreg.DnsError as e:
        return json_response("500 Internal Server Error", {"error": str(e)})


def handle_dns_request(form, client_ip, as_json=False):
    try:
        name = dnsreg.add_request(form.get("name", ""), form.get("address", ""), form.get("contact", ""), client_ip=client_ip)
    except dnsreg.DnsError as e:
        if as_json == True:
            return json_response(dns_status_for(e), {"error": str(e)})
        else:
            page = "<h1>Request rejected</h1><p>" + html.escape(str(e)) + "</p>"
            page = page + '<p><a href="/dns-request.html">Try again</a></p>'
            return build_response("400 Bad Request", page)
    if as_json == True:
        return json_response("200 OK", {"queued": name})
    page = "<h1>Request received</h1><p><b>" + html.escape(name) + "</b> is queued for review. "
    page = page + "It will resolve once the reWeb DNS operator approves it.</p>"
    page = page + '<p><a href="/dns-request.html">Request another</a></p>'
    return build_response("200 OK", page)


def reply(status, payload):
    return build_response(status, json.dumps(payload), "application/json")


def handle_rpc(file_path, name, form, variables, method):
    if method != "POST":
        return reply("405 Method Not Allowed", {"error": "POST required"})
    args = form.get("args", [])
    if not isinstance(args, list):
        return reply("400 Bad Request", {"error": "args must be a list"})
    try:
        result = jsengine.call_function(file_path, name, args, variables, root=WWW_ROOT)
    except jsengine.RwsError as e:
        return reply("500 Internal Server Error", {"error": str(e)})
    return reply("200 OK", {"result": result})


def handle_request(header, body, client_ip=""):
    verb = header.get("verb")
    target = header.get("path")
    if not isinstance(target, str) or not target.startswith("/"):
        return build_response("400 Bad Request", "<h1>400 Bad Request</h1>")

    if verb == rwp.VERB_FETCH:
        method = "GET"
    elif verb == rwp.VERB_SEND:
        method = "POST"
    else:
        return build_response("405 Method Not Allowed", "<h1>405 Method Not Allowed</h1>")

    headers = {}
    if header.get("type"):
        headers["content-type"] = str(header["type"])
    if header.get("call"):
        headers["x-reweb-call"] = str(header["call"])

    split = urlsplit(target)
    path = split.path
    query = parse_qs(split.query)
    if method == "POST":
        form = parse_body(headers, body)
    else:
        form = {}

    if path == DNS_RESOLVE_PATH or path == DNS_ZONE_PATH or path == DNS_INFO_PATH or path == DNS_ROOTS_PATH:
        if method != "GET":
            return json_response("405 Method Not Allowed", {"error": "GET required"})
        if path == DNS_RESOLVE_PATH:
            return handle_dns_resolve(query)
        if path == DNS_ZONE_PATH:
            return handle_dns_zone()
        if path == DNS_ROOTS_PATH:
            return handle_dns_roots()
        return handle_dns_info()

    if path == DNS_REQUEST_PATH or path == DNS_REQUEST_API_PATH:
        if method != "POST":
            return build_response("405 Method Not Allowed", "<h1>405 Method Not Allowed</h1>")
        wants_json = False
        if path == DNS_REQUEST_API_PATH:
            wants_json = True
        if headers.get("content-type", "").startswith("application/json"):
            wants_json = True
        return handle_dns_request(form, client_ip, as_json=wants_json)

    file_path = safe_file_path(path)
    if file_path == None:
        return build_response("403 Forbidden", "<h1>403 Forbidden</h1>")

    if os.path.isdir(file_path):
        index = os.path.join(file_path, "index.html")
        if not os.path.isfile(index) and os.path.isfile(os.path.join(file_path, "index.php")):
            index = os.path.join(file_path, "index.php")
        file_path = index

    if not os.path.isfile(file_path):
        return build_response("404 Not Found", "<h1>404 Not Found</h1>")

    if file_path.endswith(".rws"):
        request_vars = {}
        for k in query:
            request_vars[k] = query[k][-1]
        variables = {"request": request_vars, "post": form, "method": method}
        if "x-reweb-call" in headers:
            return handle_rpc(file_path, headers["x-reweb-call"], form, variables, method)
        try:
            body_out = jsengine.execute_script_from_file(file_path, variables, root=WWW_ROOT)
        except jsengine.RwsError as e:
            error_html = "<h1>500 Script Error</h1><pre>" + html.escape(str(e)) + "</pre>"
            return build_response("500 Internal Server Error", error_html)
        return build_response("200 OK", body_out, guess_content_type(file_path))

    if file_path.endswith(".php"):
        try:
            status, body_out, content_type, location = phpengine.run(file_path, WWW_ROOT, method, path, split.query, headers.get("content-type", ""), body, client_ip, HOST, PORT)
        except phpengine.PhpError as e:
            error_html = "<h1>500 Script Error</h1><pre>" + html.escape(str(e)) + "</pre>"
            return build_response("500 Internal Server Error", error_html)
        return build_response(status, body_out, content_type, location)

    if method == "POST":
        return build_response("405 Method Not Allowed", "<h1>405 Method Not Allowed</h1>")

    try:
        f = open(file_path, "rb")
        body_out = f.read()
        f.close()
    except OSError:
        return build_response("500 Internal Server Error", "<h1>500 Could Not Read File</h1>")
    return build_response("200 OK", body_out, guess_content_type(file_path))


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()

    print("Server listening on " + rwp.SCHEME + "://" + HOST + ":" + str(PORT))
    try:
        info = dnsreg.server_info()
        print("DNS: authoritative for ." + info["tld"] + " (" + str(info["records"]) + " record(s), " + str(info["pending"]) + " pending) at " + rwp.SCHEME + "://" + HOST + ":" + str(PORT) + DNS_RESOLVE_PATH + "?name=example." + info["tld"])
    except dnsreg.DnsError as e:
        print("DNS: not serving any TLD - " + str(e))

    while True:
        try:
            conn, addr = server.accept()
        except KeyboardInterrupt:
            print("\nShutting down.")
            break

        print("Connected by:", addr)
        conn.settimeout(5)
        try:
            try:
                header, body = rwp.read_frame(conn, MAX_BODY)
            except rwp.ProtocolError as e:
                print("Bad message:", e)
                conn.sendall(build_response("400 Bad Request", "<h1>400 Bad Request</h1>"))
                conn.close()
                continue

            print("--- Request ---")
            print(str(header.get("verb")) + " " + str(header.get("path")))

            try:
                response = handle_request(header, body, client_ip=addr[0])
            except Exception as e:
                print("Error handling request:", e)
                response = build_response("500 Internal Server Error", "<h1>500 Internal Server Error</h1>")
            conn.sendall(response)
        except (socket.timeout, OSError) as e:
            print("Connection problem:", e)
        conn.close()

    server.close()


if __name__ == "__main__":
    main()