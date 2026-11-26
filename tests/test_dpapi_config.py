from __future__ import annotations

import json

import pytest

from dpapi_config import (
    CredentialError,
    available,
    decrypt_config,
    encrypt_config,
    is_protected,
    load,
    protect,
    save,
    unprotect,
)

PATHS = (("password",), ("ai", "api_key"))
PLACEHOLDERS = ("", "sk-")

win_only = pytest.mark.skipif(not available(), reason="Windows DPAPI not available")


@win_only
def test_roundtrip():
    env = protect("hunter2")
    assert env.startswith("dpapi:")
    assert unprotect(env) == "hunter2"


@win_only
def test_ciphertext_differs_per_call():
    # DPAPI salts each call; identical plaintext must not produce identical bytes.
    assert protect("same") != protect("same")


def test_plain_value_is_returned_unchanged():
    assert unprotect("not encrypted") == "not encrypted"
    assert not is_protected("not encrypted")


def test_is_protected():
    assert is_protected("dpapi:AAAA")
    assert not is_protected("DPAPI:AAAA")
    assert not is_protected(None)


def test_unprotect_rejects_bad_base64():
    with pytest.raises(CredentialError):
        unprotect("dpapi:not base64!!")


@win_only
def test_config_encrypt_decrypt_roundtrip():
    cfg = {"password": "pw", "ai": {"api_key": "sk-live"}, "other": "keep"}
    encrypt_config(cfg, PATHS)
    assert is_protected(cfg["password"])
    assert is_protected(cfg["ai"]["api_key"])
    assert cfg["other"] == "keep"

    decrypt_config(cfg, PATHS)
    assert cfg == {"password": "pw", "ai": {"api_key": "sk-live"}, "other": "keep"}


@win_only
def test_placeholders_are_not_encrypted():
    cfg = {"password": "", "ai": {"api_key": "sk-"}}
    encrypt_config(cfg, PATHS, PLACEHOLDERS)
    assert cfg["password"] == ""
    assert cfg["ai"]["api_key"] == "sk-"


@win_only
def test_missing_paths_are_skipped():
    cfg = {"ai": {"nope": "x"}}
    encrypt_config(cfg, (("ai", "api_key"), ("missing", "deep", "key")))
    assert cfg == {"ai": {"nope": "x"}}


@win_only
def test_save_and_load_persist_ciphertext(tmp_path):
    path = tmp_path / "config.json"
    save(path, {"password": "pw", "ai": {"api_key": "sk-live"}}, PATHS, PLACEHOLDERS)

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["password"].startswith("dpapi:")
    assert raw["ai"]["api_key"].startswith("dpapi:")

    assert load(path, PATHS, PLACEHOLDERS) == {"password": "pw", "ai": {"api_key": "sk-live"}}


@win_only
def test_load_migrates_plaintext_in_place(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"password": "legacy"}), encoding="utf-8")

    assert load(path, PATHS)["password"] == "legacy"
    assert json.loads(path.read_text(encoding="utf-8"))["password"].startswith("dpapi:")


@win_only
def test_save_is_atomic_and_leaves_no_temp_files(tmp_path):
    path = tmp_path / "config.json"
    save(path, {"password": "pw"}, PATHS)
    save(path, {"password": "pw2"}, PATHS)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.json"]


def test_load_rejects_non_object(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(CredentialError):
        load(path, PATHS)
