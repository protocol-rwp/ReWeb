#!/usr/bin/env python3
import json
import threading

import webview
from gi.repository import GLib
from webview.platforms import gtk as webview_gtk

import dnsresolve
import dnsroots
import scheme

HOME = "reweb://synapse.rws"

TOOLBAR_JS = """
(function () {
  var TOOLBAR_ID = "__reweb_toolbar";
  var existing = document.getElementById(TOOLBAR_ID);
  if (existing) existing.remove();

  var bar = document.createElement("div");
  bar.id = TOOLBAR_ID;
  bar.innerHTML =
    '<button id="__reweb_back" title="Back">&#8592;</button>' +
    '<button id="__reweb_fwd" title="Forward">&#8594;</button>' +
    '<button id="__reweb_reload" title="Reload">&#8635;</button>' +
    '<button id="__reweb_home">Home</button>' +
    '<input id="__reweb_address" type="text">' +
    '<button id="__reweb_go">Go</button>' +
    '<span id="__reweb_status"></span>';
  bar.style.cssText =
    "position:fixed; top:0; left:0; right:0; z-index:2147483647;" +
    "display:flex; align-items:center; gap:4px; padding:4px;" +
    "background:#eee; border-bottom:1px solid #999;" +
    "font-family:sans-serif; font-size:13px; box-sizing:border-box;";
  document.documentElement.appendChild(bar);
  document.body.style.marginTop =
    (bar.offsetHeight + parseInt(getComputedStyle(document.body).marginTop || 0, 10)) + "px";

  bar.querySelector("#__reweb_address").style.cssText = "flex:1;";
  bar.querySelector("#__reweb_status").style.cssText =
    "font-size:11px; color:#333; white-space:nowrap; overflow:hidden;";

  var addressInput = document.getElementById("__reweb_address");
  addressInput.value = __ADDRESS__;
  document.getElementById("__reweb_status").textContent = __STATUS__;

  document.getElementById("__reweb_back").onclick = function () {
    window.pywebview.api.go_back();
  };
  document.getElementById("__reweb_fwd").onclick = function () {
    window.pywebview.api.go_forward();
  };
  document.getElementById("__reweb_reload").onclick = function () {
    window.pywebview.api.reload_page();
  };
  document.getElementById("__reweb_home").onclick = function () {
    window.pywebview.api.go_home();
  };
  document.getElementById("__reweb_go").onclick = function () {
    window.pywebview.api.navigate(addressInput.value);
  };
  addressInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      window.pywebview.api.navigate(addressInput.value);
    }
  });

  document.addEventListener("keydown", function (e) {
    var key = (e.key || "").toLowerCase();
    if (e.ctrlKey && !e.altKey && !e.metaKey && key === "h") {
      e.preventDefault();
      window.pywebview.api.go_home();
    } else if (e.ctrlKey && !e.altKey && !e.metaKey && key === "l") {
      e.preventDefault();
      addressInput.focus();
      addressInput.select();
    } else if (e.altKey && !e.ctrlKey && !e.metaKey && e.key === "ArrowLeft") {
      e.preventDefault();
      window.pywebview.api.go_back();
    } else if (e.altKey && !e.ctrlKey && !e.metaKey && e.key === "ArrowRight") {
      e.preventDefault();
      window.pywebview.api.go_forward();
    } else if (!e.ctrlKey && !e.altKey && !e.metaKey && e.key === "F5") {
      e.preventDefault();
      window.pywebview.api.reload_page();
    } else if (e.ctrlKey && e.shiftKey && !e.altKey && !e.metaKey && key === "r") {
      e.preventDefault();
      window.pywebview.api.flush_dns();
      window.pywebview.api.reload_page();
    }
  });

  var tags = document.getElementsByTagName("blink");
  if (tags.length > 0) {
    var elements = Array.prototype.slice.call(tags);
    setInterval(function () {
      elements.forEach(function (el) {
        el.style.visibility =
          el.style.visibility === "hidden" ? "visible" : "hidden";
      });
    }, 500);
  }
})();
"""


class Browser:
    def __init__(self):
        self.resolver = dnsresolve.Resolver()
        self.scheme_installed = False
        self.history = []
        self.history_index = -1
        self.programmatic = True
        self.pending_record = True
        t = threading.Thread(target=self.update_dns, daemon=True)
        t.start()
        self.window = webview.create_window("Reweb Browser", url="about:blank", js_api=self, width=1000, height=700)
        self.window.events.before_show += lambda: self.load(HOME)
        self.window.events.loaded += self.on_loaded

    def update_dns(self):
        try:
            r = dnsroots.sync()
        except Exception as e:
            print("DNS update failed: " + str(e))
            return
        self.resolver.clear_cache()
        print("DNS updated: reached " + str(r["peers_reached"]) + " peer(s), " + str(r["changed"]) + " claim(s) updated")

    def load(self, url):
        def go():
            view = webview_gtk.BrowserView.instances[self.window.uid].webview
            if self.scheme_installed == False:
                scheme.install(self.resolver, view)
                self.scheme_installed = True
            view.load_uri(url)
            return False
        GLib.idle_add(go)

    def to_url(self, address):
        address = address.strip()
        if "://" in address:
            return address
        return scheme.SCHEME + "://" + address

    def friendly_for_url(self, url):
        prefix = scheme.SCHEME + "://"
        if url.startswith(prefix):
            return url[len(prefix):]
        return url

    def navigate(self, address, record_history=True):
        if not address:
            return
        url = self.to_url(address)
        self.programmatic = True
        self.pending_record = record_history
        self.set_status("Loading " + self.friendly_for_url(url) + " ...")
        self.load(url)

    def flush_dns(self):
        self.resolver.clear_cache()
        self.set_status("DNS cache cleared.")

    def is_redirect_stub(self):
        try:
            return self.window.evaluate_js("!!document.querySelector('meta[http-equiv=refresh]')") == True
        except Exception:
            return False

    def on_loaded(self):
        if self.is_redirect_stub():
            return
        url = self.window.get_current_url()
        if not url or url == "about:blank":
            return
        friendly = self.friendly_for_url(url)
        if self.programmatic == True:
            record = self.pending_record
            self.programmatic = False
        else:
            record = True
        if record == True:
            self.history = self.history[:self.history_index + 1]
            self.history.append(friendly)
            self.history_index = len(self.history) - 1
        self.inject_toolbar(friendly, "Done (" + url + ")")
        self.update_title()

    def update_title(self):
        try:
            page_title = self.window.evaluate_js("document.title")
        except Exception:
            page_title = None
        if page_title and str(page_title).strip() != "":
            self.window.set_title("'" + str(page_title).strip() + "' - Reweb Browser")
        else:
            self.window.set_title("Reweb Browser")

    def go_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.navigate(self.history[self.history_index], record_history=False)

    def go_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.navigate(self.history[self.history_index], record_history=False)

    def reload_page(self):
        if self.history_index >= 0 and self.history_index < len(self.history):
            self.navigate(self.history[self.history_index], record_history=False)

    def go_home(self):
        self.navigate(HOME)

    def inject_toolbar(self, address_text, status_text):
        script = TOOLBAR_JS.replace("__ADDRESS__", json.dumps(address_text))
        script = script.replace("__STATUS__", json.dumps(status_text))
        try:
            self.window.evaluate_js(script)
        except Exception as e:
            print("Could not add the toolbar:", e)

    def set_status(self, text):
        script = "var s = document.getElementById('__reweb_status'); "
        script = script + "if (s) s.textContent = " + json.dumps(text) + ";"
        try:
            self.window.evaluate_js(script)
        except Exception:
            pass


if __name__ == "__main__":
    Browser()
    webview.start()
