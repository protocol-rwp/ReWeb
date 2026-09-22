import json
import os
import re
import subprocess

RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runner.js")
PROCESS_TIMEOUT = 5
MAX_OUTPUT = 5000000


class RwsError(Exception):
    pass


CLIENT_JS = """<script>
(function () {
  var s = window.server = {};
  %s.forEach(function (name) {
    s[name] = function () {
      var args = Array.prototype.slice.call(arguments);
      return fetch(location.pathname, {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-Reweb-Call": name},
        body: JSON.stringify({args: args})
      }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.error !== undefined) throw new Error(d.error);
        return d.result;
      });
    };
  });
})();
</script>
"""


def run_job(job):
    try:
        p = subprocess.run(["node", RUNNER], input=json.dumps(job), capture_output=True, text=True, timeout=PROCESS_TIMEOUT)
    except FileNotFoundError:
        raise RwsError("Node.js is required to run server-side scripts")
    except subprocess.TimeoutExpired:
        raise RwsError("Script exceeded the time limit")
    if len(p.stdout) > MAX_OUTPUT:
        raise RwsError("Script output too large")
    try:
        result = json.loads(p.stdout)
    except json.JSONDecodeError:
        if p.stderr.strip() != "":
            raise RwsError(p.stderr.strip())
        else:
            raise RwsError("Script runner failed")
    if result.get("ok") == False or result.get("ok") == None:
        if result.get("error") != None:
            raise RwsError(result.get("error"))
        raise RwsError("Unknown error")
    return result


def make_job(file_path, variables, root):
    if variables == None:
        variables = {}
    job = {}
    job["file"] = os.path.abspath(file_path)
    if root:
        job["root"] = os.path.abspath(root)
    else:
        job["root"] = os.path.abspath(os.path.dirname(file_path))
    job["request"] = variables.get("request", {})
    job["post"] = variables.get("post", {})
    job["method"] = variables.get("method", "GET")
    return job


def add_stub(page, names):
    stub = CLIENT_JS % json.dumps(names).replace("</", "<\\/")
    m = re.search(r"<head[^>]*>", page, re.I)
    if m:
        return page[:m.end()] + "\n" + stub + page[m.end():]
    else:
        return stub + page


def execute_script_from_file(file_path, variables=None, root=None):
    job = make_job(file_path, variables, root)
    result = run_job(job)
    page = result["html"]
    names = result["exposed"]
    if names:
        return add_stub(page, names)
    return page


def call_function(file_path, name, args, variables=None, root=None):
    job = make_job(file_path, variables, root)
    job["call"] = {"name": name, "args": args}
    result = run_job(job)
    return result["result"]
