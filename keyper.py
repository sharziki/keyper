#!/usr/bin/env python3
"""
keyper — a local, encrypted secrets vault exposed over the Model Context Protocol.

Keep your API keys / env vars encrypted at rest on your own machine. Instead of
re-pasting secrets into your AI, your AI calls this MCP and pulls them on demand.

Two entry points from one file:
  * CLI  (interactive) — manage the vault:
        init | set | get | list | rm | rotate | import-env
  * serve (non-interactive) — the MCP server your AI client connects to.

Security design
  - Encryption:  AES-256-GCM, a fresh random 96-bit nonce per secret, with the
                 secret's NAME bound in as Additional Authenticated Data (so a
                 ciphertext can't be silently swapped to another name).
  - Master key:  32 random bytes stored in the OS keychain (default), OR derived
                 from a passphrase via scrypt (n=2^15). The vault file alone is
                 useless without the key.
  - Plaintext is NEVER written to disk and NEVER written to the audit log.
  - Vault file + audit log are created with 0600 permissions.

Requires: cryptography, mcp   (keyring only needed for keychain mode)
    pip install cryptography "mcp[cli]" keyring
"""

from __future__ import annotations

import argparse
import base64
import datetime
import getpass
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:  # pragma: no cover - surfaced at runtime with a clear message
    AESGCM = None
    Scrypt = None

    class InvalidTag(Exception):  # placeholder so except clauses are valid
        pass

__version__ = "1.0.0"

BANNER = r"""
██╗  ██╗███████╗██╗   ██╗██████╗ ███████╗██████╗
██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
█████╔╝ █████╗   ╚████╔╝ ██████╔╝█████╗  ██████╔╝
██╔═██╗ ██╔══╝    ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██╗███████╗   ██║   ██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝
      your keys, kept — encrypted, local, MCP-native
"""

SERVICE = "keyper"
KEY_NAME = "master-key"
DEFAULT_VAULT = Path(
    os.environ.get(
        "KEYPER_VAULT",
        str(Path.home() / ".config" / "keyper" / "vault.json"),
    )
)
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _die(msg: str, code: int = 1) -> "None":
    print(f"keyper: error: {msg}", file=sys.stderr)
    sys.exit(code)


def _require_crypto() -> None:
    if AESGCM is None or Scrypt is None:
        _die("the 'cryptography' package is required — run: pip install cryptography")


def _keyring():
    try:
        import keyring  # type: ignore

        # Touch the backend so we fail here rather than deep in a call.
        keyring.get_keyring()
        return keyring
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# crypto core
# --------------------------------------------------------------------------- #
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(key: bytes, name: str, plaintext: str) -> tuple[str, str]:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), name.encode("utf-8"))
    return _b64e(nonce), _b64e(ct)


def decrypt(key: bytes, name: str, nonce_b64: str, ct_b64: str) -> str:
    pt = AESGCM(key).decrypt(_b64d(nonce_b64), _b64d(ct_b64), name.encode("utf-8"))
    return pt.decode("utf-8")


# --------------------------------------------------------------------------- #
# vault storage
# --------------------------------------------------------------------------- #
def load_vault(path: Path) -> dict:
    if not path.exists():
        _die(f"no vault at {path} — run `keyper init` first")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        _die(f"vault at {path} is corrupt: {e}")


def save_vault(vault: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(vault, indent=2))
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def audit(vault_path: Path, event: str) -> None:
    """Append an access record. Never contains secret values."""
    if os.environ.get("KEYPER_NO_AUDIT"):
        return
    log = vault_path.parent / "access.log"
    try:
        with open(log, "a") as f:
            f.write(f"{_now()} {event}\n")
        os.chmod(log, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# master-key resolution
# --------------------------------------------------------------------------- #
def load_master_key(meta: dict, *, interactive: bool) -> bytes:
    """
    Resolve the 32-byte master key for an existing vault.

    interactive=True  -> may prompt on a TTY (CLI use).
    interactive=False -> never prompts (server use); must find the key in the
                         keychain or the KEYPER_PASSPHRASE env var.
    """
    _require_crypto()
    mode = meta.get("mode", "keychain")

    if mode == "keychain":
        kr = _keyring()
        if kr is None:
            _die("vault is keychain-mode but no OS keyring backend is available")
        val = kr.get_password(SERVICE, KEY_NAME)
        if not val:
            _die("master key not found in the OS keychain — was the vault created on this machine/user?")
        return _b64d(val)

    if mode == "passphrase":
        salt = _b64d(meta["salt"])
        pw = os.environ.get("KEYPER_PASSPHRASE")
        if not pw:
            if interactive and sys.stdin.isatty():
                pw = getpass.getpass("Vault passphrase: ")
            else:
                _die("passphrase-mode vault: set the KEYPER_PASSPHRASE environment variable")
        return derive_key(pw, salt)

    _die(f"unknown vault mode: {mode!r}")


# --------------------------------------------------------------------------- #
# CLI commands
# --------------------------------------------------------------------------- #
def cmd_init(args) -> None:
    _require_crypto()
    path = Path(args.vault)
    if path.exists() and not args.force:
        _die(f"vault already exists at {path} (use --force to overwrite)")

    mode = "passphrase" if args.passphrase else "keychain"
    meta = {"version": 1, "mode": mode, "created": _now(), "secrets": {}}

    if mode == "keychain":
        kr = _keyring()
        if kr is None:
            _die("no OS keyring backend found — re-run with --passphrase instead")
        key = os.urandom(32)
        kr.set_password(SERVICE, KEY_NAME, _b64e(key))
        print("Master key generated and stored in the OS keychain.")
    else:
        salt = os.urandom(16)
        meta["salt"] = _b64e(salt)
        env_pw = os.environ.get("KEYPER_PASSPHRASE")
        if env_pw:
            pw = env_pw
        else:
            pw = getpass.getpass("Set vault passphrase: ")
            pw2 = getpass.getpass("Confirm passphrase: ")
            if pw != pw2:
                _die("passphrases do not match")
        if not pw:
            _die("passphrase must not be empty")
        derive_key(pw, salt)  # sanity: ensure KDF works on this machine
        print("Passphrase-mode vault created. Provide KEYPER_PASSPHRASE to the server.")

    save_vault(meta, path)
    print(f"Vault created at {path}")


def _read_value(name: str, provided: Optional[str]) -> str:
    if provided is not None:
        return provided
    env_val = os.environ.get("KEYPER_VALUE")
    if env_val is not None:
        return env_val
    if sys.stdin.isatty():
        return getpass.getpass(f"Value for {name}: ")
    # piped input, e.g. `echo -n sk-... | keyper set KEY`
    return sys.stdin.readline().rstrip("\n")


def cmd_set(args) -> None:
    path = Path(args.vault)
    vault = load_vault(path)
    key = load_master_key(vault, interactive=True)
    value = _read_value(args.name, args.value)
    if value == "":
        _die("refusing to store an empty value")
    nonce, ct = encrypt(key, args.name, value)
    vault["secrets"][args.name] = {
        "nonce": nonce,
        "ciphertext": ct,
        "description": args.description or "",
        "updated": _now(),
    }
    save_vault(vault, path)
    print(f"Stored '{args.name}'.")


def cmd_get(args) -> None:
    path = Path(args.vault)
    vault = load_vault(path)
    key = load_master_key(vault, interactive=True)
    m = vault["secrets"].get(args.name)
    if not m:
        _die(f"no secret named {args.name!r}")
    value = decrypt(key, args.name, m["nonce"], m["ciphertext"])
    audit(path, f"cli.get name={args.name}")
    # No trailing newline so `$(... get KEY)` captures exactly the value.
    sys.stdout.write(value)
    if sys.stdout.isatty():
        sys.stdout.write("\n")


def cmd_list(args) -> None:
    path = Path(args.vault)
    vault = load_vault(path)
    secrets = vault.get("secrets", {})
    if not secrets:
        print("(vault is empty)")
        return
    width = max(len(n) for n in secrets)
    for name in sorted(secrets):
        m = secrets[name]
        desc = m.get("description", "")
        print(f"{name.ljust(width)}  {desc}".rstrip())


def cmd_rm(args) -> None:
    path = Path(args.vault)
    vault = load_vault(path)
    if args.name not in vault.get("secrets", {}):
        _die(f"no secret named {args.name!r}")
    del vault["secrets"][args.name]
    save_vault(vault, path)
    print(f"Removed '{args.name}'.")


def cmd_import_env(args) -> None:
    path = Path(args.vault)
    vault = load_vault(path)
    key = load_master_key(vault, interactive=True)
    src = Path(args.file)
    if not src.exists():
        _die(f"no such file: {src}")
    count = 0
    for raw in src.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        k, _, val = line.partition("=")
        k = k.strip()
        val = val.strip()
        if (val.startswith('"') and val.endswith('"')) or (
            val.startswith("'") and val.endswith("'")
        ):
            val = val[1:-1]
        if not k or val == "":
            continue
        nonce, ct = encrypt(key, k, val)
        vault["secrets"][k] = {
            "nonce": nonce,
            "ciphertext": ct,
            "description": f"imported from {src.name}",
            "updated": _now(),
        }
        count += 1
    save_vault(vault, path)
    print(f"Imported {count} secret(s) from {src}.")


def cmd_rotate(args) -> None:
    """Re-encrypt every secret under a fresh master key (keychain mode only)."""
    path = Path(args.vault)
    vault = load_vault(path)
    if vault.get("mode") != "keychain":
        _die("rotate currently supports keychain-mode vaults only")
    kr = _keyring()
    if kr is None:
        _die("no OS keyring backend available")
    old_key = load_master_key(vault, interactive=True)

    # Decrypt everything with the old key first (fail before we change anything).
    plain: dict[str, str] = {}
    for name, m in vault["secrets"].items():
        plain[name] = decrypt(old_key, name, m["nonce"], m["ciphertext"])

    new_key = os.urandom(32)
    for name, value in plain.items():
        nonce, ct = encrypt(new_key, name, value)
        vault["secrets"][name]["nonce"] = nonce
        vault["secrets"][name]["ciphertext"] = ct
        vault["secrets"][name]["updated"] = _now()

    kr.set_password(SERVICE, KEY_NAME, _b64e(new_key))
    save_vault(vault, path)
    print(f"Rotated master key and re-encrypted {len(plain)} secret(s).")


# --------------------------------------------------------------------------- #
# ui — a tiny localhost web UI to add / name / manage keys
# --------------------------------------------------------------------------- #
UI_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>keyper vault</title>
<style>
:root{--bg:#0f1115;--panel:#181b22;--line:#2a2f3a;--fg:#e7e9ee;--mut:#9aa3b2;--acc:#c8a24a;--danger:#e0605e}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
.wrap{max-width:720px;margin:0 auto;padding:32px 20px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--mut);margin:0 0 24px;font-size:13px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:18px}
label{display:block;font-size:12px;color:var(--mut);margin:10px 0 4px;text-transform:uppercase;letter-spacing:.04em}
input{width:100%;padding:10px 12px;background:#0d0f14;border:1px solid var(--line);border-radius:7px;color:var(--fg);font-size:14px}
button{cursor:pointer;border:0;border-radius:7px;padding:10px 16px;font-size:14px;font-weight:600}
.primary{background:var(--acc);color:#1a1300}
.row{display:flex;gap:8px;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--line)}
.row:last-child{border-bottom:0}
.name{font-family:ui-monospace,Menlo,monospace;font-weight:600}
.desc{color:var(--mut);font-size:12px}
.del{background:transparent;color:var(--danger);border:1px solid var(--line);padding:6px 10px}
.msg{font-size:13px;margin-top:10px;min-height:18px}
.ok{color:#67c184}.err{color:var(--danger)}
.empty{color:var(--mut);font-size:13px;padding:8px 0}
</style></head><body>
<div class="wrap">
  <h1>keyper vault</h1>
  <p class="sub" id="sub">local &middot; encrypted at rest</p>
  <div class="card" id="lock" style="display:none">
    <label>Vault passphrase</label>
    <input id="pass" type="password" placeholder="enter passphrase to unlock" autofocus>
    <div style="margin-top:12px"><button class="primary" onclick="unlock()">Unlock</button></div>
    <div class="msg err" id="lockmsg"></div>
  </div>
  <div id="app" style="display:none">
    <div class="card">
      <label>Name</label>
      <input id="k" placeholder="OPENAI_API_KEY" autocapitalize="off" autocomplete="off" spellcheck="false">
      <label>Value</label>
      <input id="v" type="password" placeholder="sk-..." autocomplete="off">
      <label>Description (optional)</label>
      <input id="d" placeholder="personal OpenAI key">
      <div style="margin-top:14px"><button class="primary" onclick="addKey()">Save key</button></div>
      <div class="msg" id="addmsg"></div>
    </div>
    <div class="card"><div id="list"><div class="empty">loading&hellip;</div></div></div>
  </div>
</div>
<script>
const token=new URLSearchParams(location.search).get('token')||'';
const H={'Content-Type':'application/json','X-Token':token};
const $=id=>document.getElementById(id);
async function api(path,opts={}){opts.headers=H;const r=await fetch(path,opts);const t=await r.text();let j;try{j=JSON.parse(t)}catch(e){j={error:t}}if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}
async function boot(){try{const s=await api('/api/status');if(s.locked){$('lock').style.display='block'}else{$('app').style.display='block';load()}}catch(e){$('sub').textContent='error: '+e.message}}
async function unlock(){$('lockmsg').textContent='';try{await api('/api/unlock',{method:'POST',body:JSON.stringify({passphrase:$('pass').value})});$('lock').style.display='none';$('app').style.display='block';load()}catch(e){$('lockmsg').textContent=e.message}}
async function load(){try{const items=await api('/api/secrets');const el=$('list');if(!items.length){el.innerHTML='<div class="empty">No keys yet. Add one above.</div>';return}el.innerHTML=items.map(it=>`<div class="row"><div><div class="name">${esc(it.name)}</div><div class="desc">${esc(it.description||'')}</div></div><button class="del" onclick="del('${esc(it.name)}')">Delete</button></div>`).join('')}catch(e){$('list').innerHTML='<div class="empty err">'+e.message+'</div>'}}
async function addKey(){const name=$('k').value.trim();const value=$('v').value;const m=$('addmsg');m.className='msg';m.textContent='';if(!name||!value){m.className='msg err';m.textContent='name and value required';return}try{await api('/api/secrets',{method:'POST',body:JSON.stringify({name,value,description:$('d').value})});m.className='msg ok';m.textContent='Saved '+name;$('k').value='';$('v').value='';$('d').value='';load()}catch(e){m.className='msg err';m.textContent=e.message}}
async function del(name){if(!confirm('Delete '+name+'?'))return;try{await api('/api/delete',{method:'POST',body:JSON.stringify({name})});load()}catch(e){alert(e.message)}}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
boot();
</script></body></html>
"""


def cmd_ui(args) -> None:
    _require_crypto()
    import json as _json
    import secrets as _sec
    import webbrowser
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    vault_path = Path(args.vault)
    meta = load_vault(vault_path)
    mode = meta.get("mode", "keychain")
    token = _sec.token_urlsafe(18)
    state = {"key": None}  # decrypted master key, held only in this process

    # Unlock up front where we can; passphrase-mode vaults can unlock in the browser.
    if mode == "keychain":
        state["key"] = load_master_key(meta, interactive=False)
    else:
        env_pw = os.environ.get("KEYPER_PASSPHRASE")
        if env_pw:
            state["key"] = derive_key(env_pw, _b64d(meta["salt"]))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence request logging
            pass

        def _host_ok(self) -> bool:
            host = self.headers.get("Host", "")
            return host.startswith("127.0.0.1") or host.startswith("localhost")

        def _auth(self) -> bool:
            return self._host_ok() and self.headers.get("X-Token") == token

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _json(self, code, obj):
            self._send(code, _json.dumps(obj))

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                return _json.loads(raw or b"{}")
            except Exception:
                return {}

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/":
                self._send(200, UI_HTML, "text/html; charset=utf-8")
                return
            if not self._auth():
                self._json(403, {"error": "unauthorized"})
                return
            if path == "/api/status":
                self._json(200, {"locked": state["key"] is None, "mode": mode})
                return
            if path == "/api/secrets":
                if state["key"] is None:
                    self._json(403, {"error": "locked"})
                    return
                secrets = load_vault(vault_path).get("secrets", {})
                items = [
                    {"name": n, "description": m.get("description", ""), "updated": m.get("updated")}
                    for n, m in sorted(secrets.items())
                ]
                self._json(200, items)
                return
            self._json(404, {"error": "not found"})

        def do_POST(self):
            path = self.path.split("?")[0]
            if not self._auth():
                self._json(403, {"error": "unauthorized"})
                return
            body = self._body()
            if path == "/api/unlock":
                if mode != "passphrase":
                    self._json(400, {"error": "vault is not passphrase mode"})
                    return
                k = derive_key(body.get("passphrase") or "", _b64d(meta["salt"]))
                secrets = load_vault(vault_path).get("secrets", {})
                if secrets:  # verify against an existing secret
                    n = next(iter(secrets))
                    m = secrets[n]
                    try:
                        decrypt(k, n, m["nonce"], m["ciphertext"])
                    except InvalidTag:
                        self._json(403, {"error": "wrong passphrase"})
                        return
                state["key"] = k
                self._json(200, {"ok": True})
                return
            if state["key"] is None:
                self._json(403, {"error": "locked"})
                return
            if path == "/api/secrets":
                name = (body.get("name") or "").strip()
                value = body.get("value") or ""
                if not name or value == "":
                    self._json(400, {"error": "name and value required"})
                    return
                vault = load_vault(vault_path)
                nonce, ct = encrypt(state["key"], name, value)
                vault.setdefault("secrets", {})[name] = {
                    "nonce": nonce,
                    "ciphertext": ct,
                    "description": (body.get("description") or ""),
                    "updated": _now(),
                }
                save_vault(vault, vault_path)
                audit(vault_path, f"ui.set name={name}")
                self._json(200, {"ok": True})
                return
            if path == "/api/delete":
                name = (body.get("name") or "").strip()
                vault = load_vault(vault_path)
                if name in vault.get("secrets", {}):
                    del vault["secrets"][name]
                    save_vault(vault, vault_path)
                    audit(vault_path, f"ui.delete name={name}")
                self._json(200, {"ok": True})
                return
            self._json(404, {"error": "not found"})

    httpd = None
    port = args.port
    for p in range(args.port, args.port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            port = p
            break
        except OSError:
            continue
    if httpd is None:
        _die(f"no free port near {args.port}")

    url = f"http://127.0.0.1:{port}/?token={token}"
    print(BANNER)
    print(
        f"keyper UI running at:\n  {url}\n(only reachable from this machine; Ctrl+C to stop)",
        flush=True,
    )
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")


# --------------------------------------------------------------------------- #
# serve — the MCP server
# --------------------------------------------------------------------------- #
def cmd_serve(args) -> None:
    _require_crypto()
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        _die('the MCP SDK is required — run: pip install "mcp[cli]"')

    vault_path = Path(args.vault)
    meta = load_vault(vault_path)
    # Resolve the key once at startup so misconfiguration fails immediately
    # (and is held only in this process's memory, never on disk).
    key = load_master_key(meta, interactive=False)

    mcp = FastMCP("keyper")

    def _secrets() -> dict:
        # Re-read on each call so `set`/`rm` from the CLI show up live.
        return load_vault(vault_path).get("secrets", {})

    @mcp.tool()
    def list_secrets() -> str:
        """List the NAMES and descriptions of available secrets. Never returns values.
        Call this first to see what is in the vault."""
        secrets = _secrets()
        items = [
            {
                "name": n,
                "description": m.get("description", ""),
                "updated": m.get("updated"),
            }
            for n, m in sorted(secrets.items())
        ]
        return json.dumps(items, indent=2)

    @mcp.tool()
    def describe_secret(name: str) -> str:
        """Return metadata (name, description, last-updated) for one secret. Never returns the value."""
        m = _secrets().get(name)
        if not m:
            return f"error: no secret named {name!r}"
        return json.dumps(
            {"name": name, "description": m.get("description", ""), "updated": m.get("updated")},
            indent=2,
        )

    @mcp.tool()
    def get_secret(name: str) -> str:
        """Decrypt and RETURN the plaintext value of a secret.

        WARNING: the returned value enters the model's context and may be logged.
        Prefer `run_with_secrets` when you only need to *use* a secret (e.g. call an
        API, run a deploy) rather than read it. Use this only when the raw value is
        genuinely needed in the conversation."""
        m = _secrets().get(name)
        if not m:
            return f"error: no secret named {name!r}"
        try:
            value = decrypt(key, name, m["nonce"], m["ciphertext"])
        except InvalidTag:
            return f"error: could not decrypt {name!r} (key mismatch or tampered vault)"
        audit(vault_path, f"tool.get_secret name={name}")
        return value

    @mcp.tool()
    def run_with_secrets(
        command: str,
        secret_names: list[str],
        cwd: Optional[str] = None,
        timeout: int = 120,
    ) -> str:
        """Run a shell command with the named secrets injected as environment variables.

        The secret VALUES are never returned — any occurrence of a value in stdout/stderr
        is redacted. This is the safe way to *use* a secret without exposing it to the model.
        Example: command="curl -s -H \\"Authorization: Bearer $OPENAI_API_KEY\\" https://api.openai.com/v1/models",
        secret_names=["OPENAI_API_KEY"]."""
        secrets = _secrets()
        env = dict(os.environ)
        values: list[str] = []
        for n in secret_names:
            m = secrets.get(n)
            if not m:
                return f"error: no secret named {n!r}"
            try:
                val = decrypt(key, n, m["nonce"], m["ciphertext"])
            except InvalidTag:
                return f"error: could not decrypt {n!r} (key mismatch or tampered vault)"
            env[n] = val
            values.append(val)
        audit(vault_path, f"tool.run_with_secrets names={secret_names} cmd={command!r}")
        try:
            p = subprocess.run(
                command,
                shell=True,
                env=env,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return f"error: command timed out after {timeout}s"
        out = p.stdout or ""
        if p.stderr:
            out += ("\n[stderr]\n" + p.stderr)
        for val in values:
            if val:
                out = out.replace(val, "***REDACTED***")
        return f"exit_code={p.returncode}\n{out}".rstrip()

    mcp.run()  # stdio transport


# --------------------------------------------------------------------------- #
# arg parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keyper",
        description="keyper — local encrypted secrets vault + MCP server.",
    )
    parser.add_argument("--version", action="version", version=f"keyper {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_vault_arg(p):
        p.add_argument(
            "--vault",
            default=str(DEFAULT_VAULT),
            help=f"path to the vault file (default: {DEFAULT_VAULT})",
        )

    p_init = sub.add_parser("init", help="create a new vault")
    add_vault_arg(p_init)
    p_init.add_argument(
        "--passphrase",
        action="store_true",
        help="use a passphrase (scrypt) instead of the OS keychain",
    )
    p_init.add_argument("--force", action="store_true", help="overwrite an existing vault")
    p_init.set_defaults(func=cmd_init)

    p_set = sub.add_parser("set", help="add or update a secret")
    add_vault_arg(p_set)
    p_set.add_argument("name", help="secret name, e.g. OPENAI_API_KEY")
    p_set.add_argument("value", nargs="?", help="value (omit to be prompted / read stdin)")
    p_set.add_argument("-d", "--description", help="optional description")
    p_set.set_defaults(func=cmd_set)

    p_get = sub.add_parser("get", help="print a secret value")
    add_vault_arg(p_get)
    p_get.add_argument("name")
    p_get.set_defaults(func=cmd_get)

    p_list = sub.add_parser("list", help="list secret names (no values)")
    add_vault_arg(p_list)
    p_list.set_defaults(func=cmd_list)

    p_rm = sub.add_parser("rm", help="remove a secret")
    add_vault_arg(p_rm)
    p_rm.add_argument("name")
    p_rm.set_defaults(func=cmd_rm)

    p_imp = sub.add_parser("import-env", help="import a .env file")
    add_vault_arg(p_imp)
    p_imp.add_argument("file", help="path to a .env file")
    p_imp.set_defaults(func=cmd_import_env)

    p_rot = sub.add_parser("rotate", help="rotate the master key (keychain mode)")
    add_vault_arg(p_rot)
    p_rot.set_defaults(func=cmd_rotate)

    p_ui = sub.add_parser("ui", help="local web UI to add / name / manage keys")
    add_vault_arg(p_ui)
    p_ui.add_argument("--port", type=int, default=8765, help="localhost port (default 8765)")
    p_ui.add_argument("--no-browser", action="store_true", help="do not auto-open a browser")
    p_ui.set_defaults(func=cmd_ui)

    p_serve = sub.add_parser("serve", help="run the MCP server (stdio)")
    add_vault_arg(p_serve)
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except InvalidTag:
        _die("decryption failed — wrong passphrase, wrong key, or the vault was tampered with")


if __name__ == "__main__":
    main()
