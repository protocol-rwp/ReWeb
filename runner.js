'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const TIMEOUT_MS = 2000;
const MAX_INCLUDE_DEPTH = 20;

function fail(error) {
  process.stdout.write(JSON.stringify({ ok: false, error: String(error) }));
  process.exit(0);
}

function splitTemplate(src) {
  const segs = [];
  let pos = 0;
  for (;;) {
    const start = src.indexOf('<?js', pos);
    if (start === -1) { segs.push(['raw', src.slice(pos)]); break; }
    segs.push(['raw', src.slice(pos, start)]);
    const codeStart = start + 4;
    const end = src.indexOf('?>', codeStart);
    if (end === -1) throw new Error("Unterminated '<?js' tag");
    segs.push(['code', src.slice(codeStart, end)]);
    pos = end + 2;
  }
  return segs;
}

function compile(src) {
  return splitTemplate(src)
    .map(([kind, text]) =>
      kind === 'raw' ? (text ? `__echo(${JSON.stringify(text)});\n` : '') : text + '\n')
    .join('');
}

const stringify = (v) =>
  typeof v === 'string' ? v : v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);

const escapeHtml = (s) =>
  stringify(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function main() {
  const job = JSON.parse(fs.readFileSync(0, 'utf8'));
  const root = fs.realpathSync(job.root);
  const out = [];
  const exposed = Object.create(null);
  const dirStack = [];

  function resolveInside(p, fromDir) {
    const full = fs.realpathSync(p.startsWith('/') ? path.join(root, p) : path.join(fromDir, p));
    if (full !== root && !full.startsWith(root + path.sep)) throw new Error(`file outside the site folder: ${p}`);
    return full;
  }

  function runFile(full, ctx) {
    if (dirStack.length > MAX_INCLUDE_DEPTH) throw new Error('include nested too deeply');
    const src = fs.readFileSync(full, 'utf8');
    dirStack.push(path.dirname(full));
    try {
      new vm.Script(compile(src), { filename: full }).runInContext(ctx, { timeout: TIMEOUT_MS });
    } finally {
      dirStack.pop();
    }
  }

  const sandbox = {
    __echo: (s) => { out.push(s); },
    echo: (...args) => { out.push(args.map(stringify).join('')); },
    escapeHtml,
    include: (p) => {
      let full;
      try { full = resolveInside(String(p), dirStack[dirStack.length - 1]); }
      catch (e) { throw new Error(e.code === 'ENOENT' ? `include file not found: ${p}` : e.message); }
      runFile(full, ctx);
    },
    expose: (arg) => {
      const fns = typeof arg === 'function' ? { [arg.name]: arg } : arg;
      for (const [name, fn] of Object.entries(fns || {})) {
        if (typeof fn !== 'function' || !name) throw new Error('expose() needs named functions');
        exposed[name] = fn;
      }
    },
    console: { log: (...a) => process.stderr.write(a.map(stringify).join(' ') + '\n') },
    setTimeout,
    __in: JSON.stringify({ request: job.request || {}, post: job.post || {}, method: job.method || 'GET' }),
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(
    'var __d = JSON.parse(__in); var request = __d.request, post = __d.post, method = __d.method; delete globalThis.__in; delete globalThis.__d;',
    ctx);

  const main = fs.realpathSync(job.file);
  if (!main.startsWith(root + path.sep)) throw new Error('page outside the site folder');
  runFile(main, ctx);

  if (!job.call) {
    process.stdout.write(JSON.stringify({ ok: true, html: out.join(''), exposed: Object.keys(exposed) }));
    return;
  }

  const { name, args } = job.call;
  if (!Object.prototype.hasOwnProperty.call(exposed, name)) throw new Error(`No exposed server function '${name}'`);
  const result = await exposed[name](...(Array.isArray(args) ? args : []));
  process.stdout.write(JSON.stringify({ ok: true, result: result === undefined ? null : result }));
}

main().catch((e) => fail(e && e.message ? e.message : e));
