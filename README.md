# dpapi-config

Encrypt just the secrets in a JSON config file, with Windows DPAPI, and keep the
file readable by everything else.

```json
{
    "password": "dpapi:AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA...",
    "ai": { "api_key": "dpapi:AQAAANCMnd8BFdERjHoAwE..." },
    "theme": "dark"
}
```

No master password, no key file, no extra dependency — DPAPI derives the key from
the logged-in Windows account, so there is nothing to store and nothing to leak
alongside the config.

## Install

```bash
pip install dpapi-config
```

## Why this exists

Most Python apps that need to remember a password put it in JSON in plaintext, or
invent a "key file" next to it (which is the same secret, one indirection away).
On Windows the OS already provides the right primitive. This package wraps it in
the two behaviours that actually matter:

**Encrypt in place.** Each configured field is replaced by `"dpapi:<base64>"`, so
the file is still one JSON document. Anything that reads the config keeps working;
only the values you listed become opaque.

**Fail closed.** If DPAPI is not available, `protect()` raises
`CredentialError` — it never returns the input. The first version of this code
returned the plaintext on failure, which meant a machine without DPAPI silently
wrote passwords to disk while the UI said "encrypted". Refusing to write is the
only safe behaviour.

## Platform

Windows only for encryption. The module imports fine everywhere, `available()`
returns `False` elsewhere, and the read path still works on a plaintext file —
but the encryption functions (`protect`, `encrypt_config`, `save`) raise
`CredentialError` rather than writing secrets in the clear.

## Use

```python
from dpapi_config import load, save

PATHS = (("password",), ("ai", "api_key"))
PLACEHOLDERS = ("", "sk-")      # "not filled in yet" values, never encrypted

cfg = load("config.json", PATHS, PLACEHOLDERS)     # plaintext in memory
cfg["ai"]["api_key"] = "sk-new"
save("config.json", cfg, PATHS, PLACEHOLDERS)      # ciphertext on disk
```

`load()` does **not** write, by default. Pass `migrate=True` to encrypt a file that
still holds plaintext — the first read then rewrites it in place:

```python
cfg = load("config.json", PATHS, PLACEHOLDERS, migrate=True)
```

The migration is one-way: older builds that do not know about `dpapi:` envelopes
will read the file as if the secret were missing, so ship both changes together.
If the file cannot be rewritten (read-only media, a directory the user cannot
write to), `load` emits a `RuntimeWarning` and returns the decrypted values —
reading never fails because writing did.

Everything else the package does is mechanical: `encrypt_config` /
`decrypt_config` operate on a dict you already loaded, `protect` / `unprotect`
work on single strings.

## Semantics worth knowing

| Situation | Behaviour |
| --- | --- |
| DPAPI unavailable, writing a config with secrets | `CredentialError`, nothing written |
| DPAPI unavailable, reading an encrypted value | `CredentialError` (ask the user again) |
| Ciphertext from a different Windows user or machine | `CredentialError` |
| Secret field holds a non-string (`"password": 12345`) | `CredentialError` — never silently written in the clear |
| Secret field is `null` (not filled in yet) | left as `null`, not encrypted, save succeeds |
| Value is a placeholder (`""`, `"sk-"`, …) | left as-is, not encrypted |
| Path does not exist in the config | skipped |
| Path goes through a list (`servers[0].token`) | not supported; list indices are not walked |
| `load()` on a plaintext file | returns values, writes nothing unless `migrate=True` |
| `migrate=True` on a read-only file | `RuntimeWarning`, values still returned |
| Save interrupted | temp file removed, old config untouched, data is `fsync`ed before the rename |

The file permissions are whatever the process creates — this module does not
tighten the ACL to the current user. If the config lives somewhere other than the
user's own profile, do that yourself (`icacls` or `SetFileSecurity`).

## Scope and non-goals

Deliberately not in this package, so you know what you are getting:

- **No ACL tightening.** The file keeps whatever permissions the process creates.
  Putting a config in a shared location and relying on this module to protect it
  will not work — use `icacls` / `SetFileSecurity` for that.
- **No keychain or credential-manager backend.** It is DPAPI, nothing else; the
  ciphertext is only readable by the same Windows user on the same machine.
- **No encryption of non-string values.** A number, list or dict where a secret is
  expected raises `CredentialError` instead of being written in the clear. `null`
  is the one exception: it means "not filled in yet" and is left alone.
- **No list traversal.** `servers[0].token` is not a supported path; keep secrets
  as direct string keys.
- **Not portable.** Encryption raises off Windows; reading a plaintext config
  still works there, but this is not a cross-platform secrets store.

## Status

0.1.2 — on PyPI (`pip install dpapi-config`); 0.1.0 is yanked because its project page
still carried the pre-release README. Trusted Publishing (OIDC) does the upload,
so no token lives in this repository. Tags (`v*`) build sdist + wheel and attach
them to the GitHub release.

## Tests

```bash
python -m pytest -q
```

The DPAPI cases are skipped on non-Windows, so the same suite runs in CI on both
Ubuntu and Windows:

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
```

## Licence

MIT.
