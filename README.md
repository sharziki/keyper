<div align="center">

<img src="assets/hero.png" alt="keyper — an encrypted local secrets vault that serves your API keys to your AI over MCP" width="820">

```
██╗  ██╗███████╗██╗   ██╗██████╗ ███████╗██████╗
██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
█████╔╝ █████╗   ╚████╔╝ ██████╔╝█████╗  ██████╔╝
██╔═██╗ ██╔══╝    ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██╗███████╗   ██║   ██║     ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝
```

**your keys, kept — encrypted, local, MCP-native**

Stop pasting `sk-...` into your AI. `keyper` keeps your API keys and env vars
**encrypted at rest on your own machine** and hands them to your AI agent on demand
over the [Model Context Protocol](https://modelcontextprotocol.io).

![license](https://img.shields.io/badge/license-MIT-black)
![python](https://img.shields.io/badge/python-3.9%2B-black)
![deps](https://img.shields.io/badge/deps-cryptography%20%C2%B7%20mcp-black)
![status](https://img.shields.io/badge/status-beta-black)

</div>

---

## Why

Every time you paste an API key into a chat, it lands in a transcript, maybe a log, maybe a
training set. `keyper` breaks that habit. Your secrets live in one AES-256-GCM–encrypted file
that only unlocks with your OS keychain or a passphrase. Your AI asks `keyper` for what it
needs — and for the common case (calling an API, running a deploy) the value never even
enters the conversation.

- 🔐 **Encrypted at rest** — AES-256-GCM, per-secret nonce, secret-name bound as AAD.
- 🗝️ **Unlocks your way** — OS keychain (silent) or a scrypt-derived passphrase.
- 🤖 **MCP-native** — works with Claude Desktop, Claude Code, Cowork, or any MCP client.
- 🧾 **Redacted execution** — `run_with_secrets` uses a key without ever showing it.
- 🖥️ **Local web UI** — add and name keys with a click; nothing leaves `127.0.0.1`.
- 📄 **One auditable file** — ~800 lines of Python, two real dependencies.

---

## Quickstart

```bash
git clone https://github.com/sharziki/keyper
cd keyper
bash quickstart.sh
```

That installs the deps, creates your vault, prints your MCP config line, and opens the web
UI to add keys. Prefer to do it by hand? Read on.

### Install

```bash
pip install cryptography "mcp[cli]" keyring
# keyring is only needed for keychain mode; skip it if you'll use --passphrase
```

### Create a vault

```bash
python keyper.py init                 # keychain mode (master key in your OS keychain)
python keyper.py init --passphrase    # or derive the key from a passphrase (scrypt)
```

### Add secrets

```bash
python keyper.py set OPENAI_API_KEY -d "personal key"   # prompts (not in shell history)
echo -n 'sk-...' | python keyper.py set STRIPE_KEY       # or pipe it in
python keyper.py import-env ./.env                       # or bulk-import a .env
python keyper.py list                                    # names only, no values
```

…or skip the terminal entirely:

```bash
python keyper.py ui        # opens http://127.0.0.1:8765/?token=…
```

<div align="center">

*add · name · describe · delete — all over localhost, token-gated, values encrypted the instant you save*

</div>

---

## Connect it to your AI

All clients run the same stdio command: `python keyper.py serve`. Use **absolute paths**.

<details>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add keyper -- /usr/bin/python3 /abs/path/keyper.py serve
# passphrase mode:
claude mcp add keyper -e KEYPER_PASSPHRASE=your-passphrase -- /usr/bin/python3 /abs/path/keyper.py serve
```
</details>

<details>
<summary><b>Claude Desktop / Cowork</b> (<code>claude_desktop_config.json</code> → <code>mcpServers</code>)</summary>

```json
{
  "mcpServers": {
    "keyper": {
      "command": "/usr/bin/python3",
      "args": ["/abs/path/keyper.py", "serve"],
      "env": { "KEYPER_PASSPHRASE": "your-passphrase" }
    }
  }
}
```
Drop the `env` block if you use keychain mode. Restart the app afterward.
</details>

Then ask your AI things like *"use `run_with_secrets` with `OPENAI_API_KEY` to list my models."*

---

## Tools the AI gets

| Tool | Returns the value? | Use it for |
|------|:---:|------------|
| `list_secrets` | ❌ names + descriptions | Discovering what's in the vault |
| `describe_secret(name)` | ❌ metadata only | Details on one secret |
| `get_secret(name)` | ✅ **plaintext into context** | When the AI must read the raw value |
| `run_with_secrets(command, secret_names[])` | ❌ redacted from output | Using a key without exposing it |

> **The one tradeoff:** `get_secret` puts a plaintext value into the model's context, where
> it could be logged. Prefer `run_with_secrets` — it injects secrets as environment variables
> into a subprocess and redacts any occurrence from the output. Treat a `get_secret` result
> as you would the key itself.

---

## How it protects your secrets

- **AES-256-GCM** authenticated encryption; a fresh random 96-bit nonce per secret.
- The secret's **name is bound in as Additional Authenticated Data**, so a ciphertext can't
  be silently moved onto another name without decryption failing.
- **Master key**: 32 random bytes in your OS keychain, or **scrypt** (n=2¹⁵) from a passphrase.
  The vault file alone is useless without it.
- Plaintext is **never** written to disk or to the audit log.
- Vault file and `access.log` are created `0600`.
- The web UI binds to **127.0.0.1**, requires a per-launch **token**, and rejects any request
  whose `Host` header isn't localhost (blocks DNS-rebinding from malicious sites).

### Threat model, briefly

`keyper` protects secrets **at rest** and keeps them out of your shell history and out of
chat when you use `run_with_secrets`. It does **not** defend against malware already running
as your user, or against you asking the AI to `get_secret` and pasting the result somewhere
public.

---

## Configuration

| Variable | Purpose |
|----------|---------|
| `KEYPER_VAULT` | Vault file path (default `~/.config/keyper/vault.json`) |
| `KEYPER_PASSPHRASE` | Passphrase for passphrase-mode vaults (required by the server) |
| `KEYPER_VALUE` | Value source for non-interactive `set` (scripting) |
| `KEYPER_NO_AUDIT` | Set to disable the access log |

CLI: `init · set · get · list · rm · rotate · import-env · ui · serve` — run `keyper <cmd> -h`.

---

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). keyper is intentionally
small and auditable; changes that touch crypto or the UI's auth must spell out their
threat-model impact.

## License

[MIT](LICENSE) © 2026 Sharvil Saxena
