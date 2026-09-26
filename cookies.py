import json
import os
import threading
import time
from email.utils import parsedate_to_datetime


def default_path(request_path):
    path = request_path.split("?", 1)[0]
    if not path.startswith("/") or path.count("/") == 1:
        return "/"
    return path[:path.rfind("/")]


def path_matches(request_path, cookie_path):
    request_path = request_path.split("?", 1)[0]
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"


def parse_expires(value):
    try:
        return parsedate_to_datetime(value.replace("-", " ")).timestamp()
    except (TypeError, ValueError):
        return None


def parse_set_cookie(line, request_path):
    parts = line.split(";")
    name, sep, value = parts[0].partition("=")
    name = name.strip()
    if sep == "" or name == "":
        return None
    cookie = {"name": name, "value": value.strip(), "path": default_path(request_path), "expires": None}
    max_age = None
    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key == "path" and val.startswith("/"):
            cookie["path"] = val
        elif key == "expires" and max_age == None:
            cookie["expires"] = parse_expires(val)
        elif key == "max-age":
            try:
                max_age = int(val)
            except ValueError:
                continue
            cookie["expires"] = time.time() + max_age
    return cookie


class CookieJar:

    def __init__(self, path=None):
        self.path = path
        self.lock = threading.Lock()
        self.cookies = {}
        if path != None and os.path.isfile(path):
            try:
                f = open(path)
                saved = json.load(f)
                f.close()
                for c in saved:
                    self.cookies[(c["host"], c["name"], c["path"])] = c
            except (OSError, ValueError, KeyError, TypeError):
                print("Could not read cookies from " + path)

    def header_for(self, host, request_path):
        host = host.lower()
        now = time.time()
        matches = []
        with self.lock:
            for c in self.cookies.values():
                if c["host"] != host or not path_matches(request_path, c["path"]):
                    continue
                if c["expires"] != None and c["expires"] <= now:
                    continue
                matches.append(c)
        if not matches:
            return None
        matches.sort(key=lambda c: -len(c["path"]))
        return "; ".join(c["name"] + "=" + c["value"] for c in matches)

    def store(self, host, request_path, set_cookie_lines):
        if not set_cookie_lines:
            return
        host = host.lower()
        now = time.time()
        with self.lock:
            for line in set_cookie_lines:
                c = parse_set_cookie(str(line), request_path)
                if c == None:
                    continue
                c["host"] = host
                key = (host, c["name"], c["path"])
                if c["expires"] != None and c["expires"] <= now:
                    self.cookies.pop(key, None)
                else:
                    self.cookies[key] = c
            self.save()

    def clear(self):
        with self.lock:
            self.cookies = {}
            self.save()

    def save(self):
        if self.path == None:
            return
        now = time.time()
        keep = [c for c in self.cookies.values() if c["expires"] != None and c["expires"] > now]
        tmp = self.path + ".tmp"
        try:
            f = open(tmp, "w")
            json.dump(keep, f)
            f.close()
            os.replace(tmp, self.path)
        except OSError as e:
            print("what " + str(e))