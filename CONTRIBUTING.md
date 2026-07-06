# Contributing to keyper

Thanks for wanting to help. keyper is deliberately small — one file, few dependencies,
easy to audit. Please keep it that way.

## Ground rules

- **Security first.** Any change touching crypto, key handling, the audit log, or the UI's
  auth must explain its threat-model impact in the PR description. When in doubt, open an
  issue to discuss before writing code.
- **No new runtime dependencies** without a strong reason. The whole point is auditability.
- **Never** commit a real vault, `.env`, or secret. `.gitignore` covers the obvious cases;
  double-check your diffs.
- Keep `keyper.py` a single self-contained module. New commands are welcome; new packages
  generally are not.

## Dev setup

```bash
git clone https://github.com/sharziki/keyper
cd keyper
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[keychain]"
```

## Manual test checklist (until there's a test suite)

```bash
export KEYPER_VAULT=/tmp/ktest/vault.json
export KEYPER_PASSPHRASE=devpass
python keyper.py init --passphrase
echo -n 'sk-abc' | python keyper.py set OPENAI_API_KEY
python keyper.py get OPENAI_API_KEY        # -> sk-abc
grep -q sk-abc "$KEYPER_VAULT" && echo LEAK || echo "encrypted OK"
python keyper.py ui                        # click through add / delete
```

Wrong passphrase and a renamed ciphertext should both fail with a clean error, not a stack
trace — if you break that, the AAD binding or error handling regressed.

## Ideas that would be genuinely useful

- A proper `pytest` suite covering the crypto round-trip and the UI auth gates.
- `argon2id` as an alternative KDF.
- Windows Credential Manager verification (keychain mode is only lightly tested there).
- A read-confirmation gate so `get_secret` requires explicit approval before revealing a value.

By contributing you agree your work is licensed under the project's MIT license.
