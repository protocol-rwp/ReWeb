import os
import subprocess
from http import HTTPStatus

PHP_CGI = "php-cgi"
PROCESS_TIMEOUT = 5
MAX_OUTPUT = 5000000


class PhpError(Exception):
    pass


def make_env(file_path, root, method, path, query_string, content_type, body, client_ip, host, port):
    env = {}
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    env["GATEWAY_INTERFACE"] = "CGI/1.1"
    env["SERVER_PROTOCOL"] = "RWP/1"
    env["SERVER_SOFTWARE"] = "ReWeb"
    env["SERVER_NAME"] = host
    env["SERVER_PORT"] = str(port)
    env["REQUEST_METHOD"] = method
    env["REQUEST_URI"] = path
    if query_string:
        env["REQUEST_URI"] = path + "?" + query_string
    env["SCRIPT_NAME"] = path
    env["SCRIPT_FILENAME"] = os.path.abspath(file_path)
    env["DOCUMENT_ROOT"] = os.path.abspath(root)
    env["QUERY_STRING"] = query_string
    env["REMOTE_ADDR"] = client_ip
    env["REDIRECT_STATUS"] = "200"
    if method == "POST":
        env["CONTENT_TYPE"] = content_type
        env["CONTENT_LENGTH"] = str(len(body))
    return env


def parse_output(output):
    sep = output.find(b"\r\n\r\n")
    sep_len = 4
    if sep == -1:
        sep = output.find(b"\n\n")
        sep_len = 2
    if sep == -1:
        return {}, output
    headers = {}
    for line in output[:sep].decode("latin-1").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return headers, output[sep + sep_len:]


def run(file_path, root, method, path, query_string="", content_type="", body=b"", client_ip="", host="", port=0):
    env = make_env(file_path, root, method, path, query_string, content_type, body, client_ip, host, port)
    try:
        p = subprocess.run([PHP_CGI], input=body, env=env, cwd=os.path.dirname(os.path.abspath(file_path)), capture_output=True, timeout=PROCESS_TIMEOUT)
    except FileNotFoundError:
        raise PhpError("php-cgi is required to run .php pages")
    except subprocess.TimeoutExpired:
        raise PhpError("Script exceeded the time limit")
    if len(p.stdout) > MAX_OUTPUT:
        raise PhpError("Script output too large")
    if p.stdout == b"" and p.returncode != 0:
        raise PhpError(p.stderr.decode("utf-8", errors="replace").strip() or "php-cgi failed")

    headers, page = parse_output(p.stdout)
    status = "200 OK"
    if "status" in headers:
        status = headers["status"]
        if " " not in status:
            try:
                status = status + " " + HTTPStatus(int(status)).phrase
            except ValueError:
                raise PhpError("Script sent an invalid status: " + status)
    elif "location" in headers:
        status = "302 Found"
    content_type = headers.get("content-type", "text/html; charset=utf-8")
    return status, page, content_type, headers.get("location")