#!/usr/bin/env python3
"""Offline exact-scope decision; does not authorize or execute network/device work."""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit
from _common import read_json


def origin(value, allow_path=True):
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError("origin must be a URL without whitespace/control characters")
    u = urlsplit(value)
    if "\\" in value or "*" in value or "%" in u.netloc or u.netloc.endswith(":"):
        raise ValueError("ambiguous URL authority")
    if u.scheme.lower() not in ("https", "http") or not u.hostname:
        raise ValueError("an explicit http(s) origin is required")
    if u.username is not None or u.password is not None or u.fragment:
        raise ValueError("credentials and fragments are forbidden")
    if not allow_path and (u.path not in ("", "/") or u.query):
        raise ValueError("allowlist entries must be origins, without paths or query")
    host = u.hostname.encode("idna").decode("ascii").lower()
    if host.endswith(".") or not re.fullmatch(r"[a-z0-9.:-]+", host):
        raise ValueError("ambiguous hostname")
    port = u.port if u.port is not None else (443 if u.scheme.lower() == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    host = "[" + host + "]" if ":" in host else host
    return f"{u.scheme.lower()}://{host}:{port}"


def decide(scope, kind, target):
    if not isinstance(scope, dict) or type(scope.get("schema_version")) is not int or scope["schema_version"] != 1:
        raise ValueError("scope schema_version must be 1")
    auth = scope.get("authorization", {})
    if not isinstance(auth, dict):
        raise ValueError("authorization must be an object")
    if auth.get("status") != "approved" or not isinstance(auth.get("reference"), str) or not auth["reference"].strip():
        return False, "authorization is not recorded as approved with a reference"
    allow = scope.get("active_allowlist", {})
    if not isinstance(allow, dict):
        raise ValueError("active_allowlist must be an object")
    key = "packages" if kind == "package" else "origins"
    entries = allow.get(key, [])
    if not isinstance(entries, list) or not all(isinstance(x, str) for x in entries):
        raise ValueError("allowlist must be a list of strings")
    if kind == "package":
        valid = r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+"
        if not re.fullmatch(valid, target) or any(not re.fullmatch(valid, x) for x in entries):
            raise ValueError("invalid package identity")
        matched = target in entries
    elif kind == "origin":
        matched = origin(target) in {origin(x, False) for x in entries}
    else:
        raise ValueError("unknown target kind")
    return matched, "exact allowlist match" if matched else "no exact allowlist match"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scope", required=True, type=Path)
    p.add_argument("--kind", choices=["package", "origin"], required=True)
    p.add_argument("--target", required=True)
    a = p.parse_args()
    try:
        scope = read_json(a.scope, 1024 * 1024)
        if not isinstance(scope, dict):
            raise ValueError("scope must be an object")
        passed, reason = decide(scope, a.kind, a.target)
        print(json.dumps({"allowed_by_recorded_scope": passed, "reason": reason,
                          "network_or_device_action_executed": False}))
        return 0 if passed else 1
    except (ValueError, OSError, TypeError, AttributeError, IndexError, UnicodeError) as e:
        print(json.dumps({"allowed_by_recorded_scope": False, "error": str(e)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
