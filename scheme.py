import html
import json
import threading

import gi

gi.require_version("WebKit2", "4.1")
from gi.repository import Gio, GLib, WebKit2

import dnsresolve
import rwp

SCHEME = rwp.SCHEME
MAX_REDIRECTS = 5

ERROR_PAGE = """<!DOCTYPE html>
<html><head><title>{title}</title></head>
<body style="font-family:sans-serif; margin:2em; color:#222;">
<h1 style="color:#a00;">{title}</h1>
<p>{message}</p>
<p style="color:#666; font-size:13px;">reweb browser</p>
</body></html>"""


def error_page(title, message):
    return ERROR_PAGE.format(title=html.escape(title), message=html.escape(message)).encode()


def split_uri(uri):
    rest = uri[len(SCHEME) + 3:]
    rest = rest.split("#", 1)[0]
    host, sep, path = rest.partition("/")
    if "?" in host:
        host, _, query = host.partition("?")
        path = "?" + query
    else:
        path = "/" + path
    return host, path


def absolute_location(host, path, location):
    if location.startswith(SCHEME + "://"):
        return location
    if not location.startswith("/"):
        base = path.split("?", 1)[0]
        location = base[:base.rfind("/") + 1] + location
    return SCHEME + "://" + host + location


def redirect_page(url):
    script = json.dumps(url).replace("</", "<\\/")
    page = '<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=' + html.escape(url, quote=True) + '"></head>'
    return (page + "<body><script>location.replace(" + script + ")</script></body></html>").encode()


class SchemeHandler:
    def __init__(self, resolver):
        self.resolver = resolver

    def register(self, context):
        context.register_uri_scheme(SCHEME, self.on_request, None)
        security = context.get_security_manager()
        security.register_uri_scheme_as_secure(SCHEME)
        security.register_uri_scheme_as_cors_enabled(SCHEME)

    def on_request(self, request, user_data=None):
        verb = rwp.VERB_FETCH
        body = b""
        if request.get_http_method() == "POST":
            verb = rwp.VERB_SEND
            stream = request.get_http_body()
            if stream != None:
                while len(body) < rwp.MAX_REQUEST_BODY:
                    chunk = stream.read_bytes(65536, None).get_data()
                    if not chunk:
                        break
                    body = body + chunk
        headers = request.get_http_headers()
        content_type = None
        call = None
        if headers != None:
            content_type = headers.get_one("Content-Type")
            call = headers.get_one("X-Reweb-Call")
            navigation = headers.get_one("Upgrade-Insecure-Requests") != None
        else:
            navigation = False
        uri = request.get_uri()
        t = threading.Thread(target=self.serve, args=(request, uri, verb, body, content_type, call, navigation), daemon=True)
        t.start()

    def serve(self, request, uri, verb, body, content_type, call, navigation):
        status, reason, ctype, data = self.fetch(uri, verb, body, content_type, call, navigation)
        GLib.idle_add(self.finish, request, status, reason, ctype, data)

    def fetch(self, uri, verb, body, content_type, call, navigation):
        html_type = "text/html; charset=utf-8"
        host, path = split_uri(uri)
        for _ in range(MAX_REDIRECTS + 1):
            try:
                address = self.resolver.resolve(host).address
            except dnsresolve.ResolveError as e:
                return 404, "Not Found", html_type, error_page("Cannot find that site", str(e))
            try:
                header, data = rwp.request(address, verb, path, body, content_type=content_type, call=call)
            except OSError as e:
                return 502, "Bad Gateway", html_type, error_page("Cannot reach the server", address + ": " + str(e))
            location = header.get("location")
            if header.get("status") not in (301, 302, 303, 307, 308) or not location:
                status = int(header.get("status", 502))
                reason = str(header.get("reason", ""))
                ctype = str(header.get("type", "application/octet-stream"))
                return status, reason, ctype, data
            target = absolute_location(host, path, str(location))
            if navigation:
                return 200, "OK", html_type, redirect_page(target)
            host, path = split_uri(target)
            verb = rwp.VERB_FETCH
            body = b""
            content_type = None
            call = None
        return 508, "Loop Detected", html_type, error_page("Too many redirects", uri)

    def finish(self, request, status, reason, ctype, data):
        stream = Gio.MemoryInputStream.new_from_bytes(GLib.Bytes.new(data))
        response = WebKit2.URISchemeResponse.new(stream, len(data))
        response.set_status(status, reason)
        response.set_content_type(ctype)
        request.finish_with_response(response)
        return False


def install(resolver, web_view):
    SchemeHandler(resolver).register(web_view.get_context())
