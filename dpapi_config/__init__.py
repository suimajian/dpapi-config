"""Encrypt selected fields of a JSON config file with Windows DPAPI.

The ciphertext is stored in place as ``"dpapi:<base64>"``, so the file stays a
plain JSON document that other tools can still read. Values that are already
encrypted are left alone, and plaintext secrets are migrated on first load.

Design rules (all deliberate):

* **Per-user, per-machine.** DPAPI keys are tied to the Windows account and the
  machine. Move the file to another machine and :func:`unprotect` raises
  :class:`CredentialError`; the caller should ask for the secret again.
* **Fail closed.** If DPAPI is unavailable, :func:`protect` raises instead of
  returning the input. A silent fallback would write plaintext while the UI and
  the docs claim everything is encrypted.
* **Atomic writes.** :func:`save` writes a temporary file and renames it, so an
  interrupted save cannot leave a half-written config behind.

Example::

    from dpapi_config import load, save

    PATHS = (("password",), ("ai", "api_key"))

    cfg = load("config.json", PATHS)      # plaintext in memory, ciphertext on disk
    cfg["ai"]["api_key"] = "sk-new"
    save("config.json", cfg, PATHS)       # encrypts the fields listed in PATHS
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import tempfile
import warnings
from ctypes import wintypes
from typing import Any, Iterable, Sequence

__all__ = [
    "PREFIX",
    "CredentialError",
    "available",
    "is_protected",
    "protect",
    "unprotect",
    "encrypt_config",
    "decrypt_config",
    "load",
    "save",
]

PREFIX = "dpapi:"

Path_ = Sequence[str]


class CredentialError(RuntimeError):
    """The ciphertext cannot be opened (different user, different machine, or corrupt)."""


class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _load_libs():
    if os.name != "nt":
        return None, None
    try:
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):
        return None, None
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_BLOB), wintypes.LPCWSTR, ctypes.POINTER(_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_BLOB), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_BLOB),
    ]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    return crypt32, kernel32


_crypt32, _kernel32 = _load_libs()

#: Do not show any DPAPI UI prompts.
_UI_FORBIDDEN = 0x1


def available() -> bool:
    """True when DPAPI can be used on this platform."""
    return _crypt32 is not None


def is_protected(value: Any) -> bool:
    """True when *value* looks like a ``dpapi:`` envelope."""
    return isinstance(value, str) and value.startswith(PREFIX)


def _blob(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    return _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def protect(text: str) -> str:
    """Encrypt one value and return its ``dpapi:`` envelope.

    Raises :class:`CredentialError` when DPAPI is unavailable. Never returns the
    input unchanged: a silent fallback is how plaintext ends up on disk while
    everything else says "encrypted".
    """
    if not available():
        raise CredentialError(
            "Windows DPAPI is not available (crypt32 could not be loaded); "
            "refusing to write the value in plaintext."
        )
    data_in, _keep = _blob(text.encode("utf-8"))
    data_out = _BLOB()
    ok = _crypt32.CryptProtectData(
        ctypes.byref(data_in), None, None, None, None, _UI_FORBIDDEN,
        ctypes.byref(data_out),
    )
    if not ok:
        raise CredentialError(f"CryptProtectData failed, error {ctypes.get_last_error()}")
    try:
        raw = ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(data_out.pbData, ctypes.c_void_p))
    return PREFIX + base64.b64encode(raw).decode("ascii")


def unprotect(value: str) -> str:
    """Decrypt a ``dpapi:`` envelope. Plain values are returned unchanged."""
    if not is_protected(value):
        return value
    if not available():
        raise CredentialError("This is a Windows DPAPI envelope; the current platform cannot open it.")
    try:
        raw_blob = base64.b64decode(value[len(PREFIX):], validate=True)
    except Exception as e:  # noqa: BLE001 - anything undecodable counts as corrupt
        raise CredentialError(f"envelope payload is not valid base64: {e}") from e
    data_in, _keep = _blob(raw_blob)
    data_out = _BLOB()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(data_in), None, None, None, None, _UI_FORBIDDEN,
        ctypes.byref(data_out),
    )
    if not ok:
        raise CredentialError(
            "DPAPI decryption failed (usually a different Windows user or machine); "
            "ask the user to enter the secret again."
        )
    try:
        raw = ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(data_out.pbData, ctypes.c_void_p))
    return raw.decode("utf-8")


def _walk(cfg: dict, paths: Iterable[Path_]):
    """Yield ``(parent dict, key, value)`` for every existing path in *paths*."""
    for path in paths:
        if not path:
            continue
        node: Any = cfg
        for key in path[:-1]:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(key)
        if isinstance(node, dict) and path[-1] in node:
            yield node, path[-1], node[path[-1]]


def decrypt_config(cfg: dict, paths: Iterable[Path_]) -> dict:
    """Decrypt in place and return the same dict."""
    for parent, key, value in _walk(cfg, paths):
        if is_protected(value):
            parent[key] = unprotect(value)
    return cfg


def encrypt_config(cfg: dict, paths: Iterable[Path_], placeholders: Iterable[str] = ()) -> dict:
    """Encrypt in place and return the same dict. Placeholder values are skipped.

    A sensitive field holding a non-string (``"password": 12345``) raises instead of
    being left alone: silently skipping would write that value to disk in the clear,
    which is the one thing this module promises not to do.
    """
    skip = set(placeholders)
    for parent, key, value in _walk(cfg, paths):
        if not isinstance(value, str):
            raise CredentialError(
                f"field {key!r} must hold a string to be encrypted; got "
                f"{type(value).__name__}. Convert it before saving, or drop it from "
                f"the paths list if it is not actually a secret."
            )
        if value not in skip and not is_protected(value):
            parent[key] = protect(value)
    return cfg


def _needs_migration(cfg: dict, paths: Iterable[Path_], placeholders: Iterable[str]) -> bool:
    skip = set(placeholders)
    return any(
        isinstance(value, str) and value not in skip and not is_protected(value)
        for _, _, value in _walk(cfg, paths)
    )


def load(path: str | os.PathLike[str], paths: Iterable[Path_],
         placeholders: Iterable[str] = (), *, migrate: bool = False) -> dict:
    """Read *path* and return a dict with decrypted values.

    ``migrate=True`` encrypts plaintext secrets found on disk and writes the file
    back, so a config written by an older build becomes encrypted after one read.
    It is off by default: reading should not write. A read-only config (Program
    Files, a network share, a signed image) still loads, and a failed migration is
    reported as a warning rather than turning ``load`` into an error.

    The migration is one-way: older builds cannot read ``dpapi:`` values.
    """
    paths = tuple(paths)
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise CredentialError(f"{path} does not contain a JSON object")
    needs_migration = migrate and _needs_migration(cfg, paths, placeholders)
    decrypt_config(cfg, paths)
    if needs_migration and available():
        try:
            save(path, cfg, paths, placeholders)
        except OSError as exc:
            warnings.warn(
                f"could not encrypt {path} in place ({exc}); continuing with the "
                f"decrypted values in memory",
                RuntimeWarning,
                stacklevel=2,
            )
    return cfg


def save(path: str | os.PathLike[str], cfg: dict, paths: Iterable[Path_],
         placeholders: Iterable[str] = ()) -> None:
    """Write *cfg* to *path* with the sensitive fields encrypted.

    Fail closed: when DPAPI is unavailable and the config holds secrets, this
    raises instead of writing plaintext. The write itself is atomic
    (``mkstemp`` + :func:`os.replace`), so a crash cannot truncate the file.
    """
    paths = tuple(paths)
    if not available() and _needs_migration(cfg, paths, placeholders):
        raise CredentialError(
            "Windows DPAPI is not available, so the secrets in this config cannot be "
            "encrypted; refusing to write them to disk."
        )
    disk = encrypt_config(json.loads(json.dumps(cfg)), paths, placeholders)
    parent = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".config-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(disk, f, indent=4, ensure_ascii=False)
            f.write("\n")
            f.flush()
            # Without fsync the rename can land before the data does, and a power
            # cut leaves the new name pointing at a truncated file.
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_directory(parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _fsync_directory(directory: str) -> None:
    """Flush the directory entry so the rename itself survives a power loss."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return                      # not supported on Windows; best effort
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
