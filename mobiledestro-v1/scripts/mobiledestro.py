#!/usr/bin/env python3
"""Mobiledestro v1: bounded, offline evidence and analysis helpers.

No subprocess, device execution, network access, extraction, or finding generation.
See README.md in this directory for the supported schema and limitations.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile

VERSION = "1.0.0"
ANDROID = "{http://schemas.android.com/apk/res/android}"
MAX_JSON = 8 * 1024 * 1024
MAX_XML = 8 * 1024 * 1024
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_MEMBER = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_RATIO = 200
MAX_EVIDENCE = 256 * 1024 * 1024
MAX_EVIDENCE_TOTAL = 1024 * 1024 * 1024
STATES = ("hypothesis", "static-supported", "dynamic-confirmed", "refuted", "blocked")
COVERAGE_STATES = ("not-tested", "in-progress", "tested", "blocked", "not-applicable")
EDGE_TYPES = ("entry", "data-flow", "control-flow", "authority", "state-transition")
DEFAULT_AREAS = (
    "ipc", "providers", "deep-links", "webview", "storage", "network", "crypto",
    "authentication", "authorization", "business-logic", "native", "supply-chain",
    "privacy", "platform-version", "resilience", "chain-validation",
)


class InputError(ValueError):
    """An input is unsafe, malformed, unsupported, or outside a fixed bound."""


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def no_links(path):
    """Reject symlinks and Windows reparse points in existing path components."""
    absolute = Path(os.path.abspath(path))
    for candidate in (absolute, *absolute.parents):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise InputError(f"Symlink/reparse point is not allowed: {candidate}")
    return absolute


def regular_file(path, maximum):
    path = no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise InputError(f"Expected a regular file: {path}")
    if info.st_size > maximum:
        raise InputError(f"File exceeds {maximum} bytes: {path}")
    return path


def sha256_file(path, maximum=MAX_EVIDENCE):
    path = regular_file(path, maximum)
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            count += len(chunk)
            if count > maximum:
                raise InputError("File grew beyond its size limit during hashing")
            digest.update(chunk)
    return digest.hexdigest()


def read_bounded(path, maximum):
    path = regular_file(path, maximum)
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise InputError("File grew beyond its size limit during reading")
    return data


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    try:
        return json.loads(read_bounded(path, MAX_JSON).decode("utf-8-sig"),
                          object_pairs_hook=reject_duplicates,
                          parse_constant=lambda value: (_ for _ in ()).throw(
                              InputError(f"Non-finite JSON number: {value}")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError(f"Invalid bounded UTF-8 JSON: {exc}") from exc


def write_new(path, content):
    path = no_links(path)
    if not path.parent.is_dir():
        raise InputError(f"Output parent must already exist: {path.parent}")
    # Exclusive creation prevents accidental overwrite, including dangling links.
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def write_json(path, value):
    write_new(path, json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n")


def obj(value, label):
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    return value


def sequence(value, label, maximum=20000):
    if not isinstance(value, list) or len(value) > maximum:
        raise InputError(f"{label} must be an array with at most {maximum} items")
    return value


def string(value, label, allow_empty=False, maximum=20000):
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value.strip()):
        raise InputError(f"{label} must be a {'possibly empty ' if allow_empty else 'nonempty '}string of at most {maximum} characters")
    if any(ord(c) < 32 and c not in "\n\r\t" for c in value):
        raise InputError(f"{label} contains control characters")
    return value


def string_list(value, label, maximum=2000):
    return [string(item, label, maximum=500) for item in sequence(value, label, maximum)]


def schema(value, label):
    obj(value, label)
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise InputError(f"{label}.schema_version must be 1")


def portable_parts(value):
    """Conservative portable relative path policy, shared by ZIP/evidence paths."""
    string(value, "relative path", maximum=1024)
    if "\x00" in value or value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", value):
        raise InputError(f"Absolute path is not allowed: {value!r}")
    normalized = value.replace("\\", "/")
    parts = normalized.rstrip("/").split("/")
    for part in parts:
        if part in ("", ".", "..") or ":" in part or part.endswith((".", " ")):
            raise InputError(f"Ambiguous/traversing path is not allowed: {value!r}")
        if any(ord(c) < 32 for c in part):
            raise InputError("Control characters are not allowed in paths")
        stem = part.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(?:COM|LPT)[1-9]", stem):
            raise InputError(f"Reserved device name in path: {value!r}")
    return parts


def contained_file(root, relative, maximum=MAX_EVIDENCE):
    root = no_links(root)
    if not root.is_dir():
        raise InputError("Engagement root must exist as a directory")
    parts = portable_parts(relative)
    candidate = regular_file(root.joinpath(*parts), maximum)
    try:
        # Every component was checked for links/reparse points above. Lexical
        # containment also works when Windows denies directory-handle resolving.
        candidate.relative_to(root)
    except ValueError as exc:
        raise InputError("Evidence path escapes engagement directory") from exc
    return candidate


def doctor():
    names = ("adb", "apkanalyzer", "aapt2", "apksigner", "jadx", "apktool", "frida", "objection", "java", "git")
    return {
        "schema_version": 1, "toolkit_version": VERSION, "python": sys.version.split()[0],
        "mode": "offline-discovery-only", "tools": {
            name: {"found": bool(path), "path": path, "executed": False,
                   "version_verified": False} for name in names for path in [shutil.which(name)]},
        "note": "PATH presence does not verify a tool's version, integrity, authorization, or readiness.",
    }


def init_engagement(out):
    out = no_links(out)
    out.mkdir(parents=False, exist_ok=False)
    for folder in ("inputs", "evidence", "analysis", "reports"):
        (out / folder).mkdir()
    write_json(out / "scope.json", {
        "schema_version": 1, "engagement_id": out.name,
        "authorization": {"status": "pending", "reference": ""},
        "targets": [], "attacker_models": [], "exclusions": [],
    })
    write_json(out / "ledger.json", {"schema_version": 1, "findings": []})
    write_json(out / "graph.json", {
        "schema_version": 1, "nodes": [], "edges": [], "initial_facts": [], "context": {},
    })
    write_json(out / "coverage.json", {
        "schema_version": 1,
        "areas": [{"id": name, "status": "not-tested", "notes": ""} for name in DEFAULT_AREAS],
    })
    return {"engagement": str(out), "authorization": "pending", "files_created": 4}


def intake(path):
    path = regular_file(path, MAX_ARCHIVE)
    # Bound the directory before ZipFile allocates a ZipInfo object per entry.
    # APKs need not use ZIP64; unsupported ZIP64 is explicit rather than guessed.
    with path.open("rb") as handle:
        handle.seek(max(0, path.stat().st_size - 65557))
        tail = handle.read(65557)
    marker = tail.rfind(b"PK\x05\x06")
    if marker < 0 or len(tail) - marker < 22:
        raise InputError("ZIP end-of-central-directory record is absent")
    _, disk, cd_disk, disk_count, entry_count, cd_size, cd_offset, comment_size = struct.unpack_from("<4s4H2LH", tail, marker)
    if marker + 22 + comment_size != len(tail):
        raise InputError("ZIP end record/comment length is inconsistent")
    if disk or cd_disk or disk_count != entry_count:
        raise InputError("Multi-disk archives are unsupported")
    if entry_count == 65535 or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        raise InputError("ZIP64 archives are unsupported by bounded inventory")
    if entry_count > MAX_ENTRIES or cd_size > 16 * 1024 * 1024:
        raise InputError("Archive central directory exceeds the entry/16 MiB bound")
    archive_hash = sha256_file(path, MAX_ARCHIVE)
    members = []
    seen = set()
    total = 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise InputError(f"Archive exceeds {MAX_ENTRIES} entries")
        for entry in entries:
            # orig_filename preserves embedded NULs that ZipInfo.filename truncates.
            parts = portable_parts(entry.orig_filename)
            normalized = "/".join(parts)
            key = normalized.casefold()
            if key in seen:
                raise InputError(f"Duplicate/case-colliding archive path: {normalized}")
            seen.add(key)
            mode = entry.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise InputError(f"Archive symlink rejected: {normalized}")
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise InputError(f"Archive special file rejected: {normalized}")
            if entry.flag_bits & 1:
                raise InputError(f"Encrypted member is unsupported: {normalized}")
            if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise InputError(f"Only STORE/DEFLATE members are supported: {normalized}")
            if entry.file_size > MAX_MEMBER:
                raise InputError(f"Member exceeds {MAX_MEMBER} uncompressed bytes: {normalized}")
            total += entry.file_size
            if total > MAX_TOTAL:
                raise InputError(f"Declared archive size exceeds {MAX_TOTAL} uncompressed bytes")
            if entry.file_size > max(entry.compress_size, 1) * MAX_RATIO:
                raise InputError(f"Declared compression ratio exceeds {MAX_RATIO}: {normalized}")
            members.append({"path": normalized, "directory": entry.is_dir(),
                            "uncompressed_bytes": entry.file_size, "compressed_bytes": entry.compress_size,
                            "crc32_declared": f"{entry.CRC:08x}", "compression": entry.compress_type})
    names = [item["path"] for item in members if not item["directory"]]
    return {
        "schema_version": 1, "source_name": path.name, "sha256": archive_hash,
        "archive_bytes": path.stat().st_size, "entries": len(members), "declared_uncompressed_bytes": total,
        "apk_structure_hint": "AndroidManifest.xml" in names, "signature_verified": False,
        "member_contents_verified": False, "extracted": False,
        "dex_files": [name for name in names if re.fullmatch(r"classes(?:[0-9]+)?\.dex", name)],
        "native_libraries": [name for name in names if name.startswith("lib/") and name.endswith(".so")],
        "members": members,
        "limitations": ["Central-directory inventory only; member bodies, CRCs, signatures and APK installability are not verified.",
                        "Declared sizes are untrusted. No member is decompressed or extracted.",
                        "This is not a complete archive malware or format validator."],
    }


def a(element, name):
    return element.get(ANDROID + name)


def unresolved(raw):
    return raw is not None and (raw.startswith(("@", "?")) or "${" in raw)


def boolean(raw, default):
    if raw is None:
        return default
    if raw == "true":
        return True
    if raw == "false":
        return False
    return None


def integer(raw):
    return int(raw) if raw and raw.isascii() and raw.isdigit() and 0 < int(raw) < 10000 else None


def combined_bool(left, right):
    if left is False or right is False:
        return False
    return True if left is True and right is True else None


def class_name(package, raw):
    if not raw or unresolved(raw) or not package or unresolved(package):
        return None
    return package + raw if raw.startswith(".") else raw if "." in raw else package + "." + raw


def permission_value(raw, source):
    return {"name": None if not raw or unresolved(raw) else raw,
            "raw": raw, "resolved": not unresolved(raw), "source": source}


def filter_data(element):
    data = [dict((key.removeprefix(ANDROID), value) for key, value in item.attrib.items())
            for item in element.findall("data")]
    combined = {}
    for item in data:
        for key, value in item.items():
            if value not in combined.setdefault(key, []):
                combined[key].append(value)
    return {"actions": [a(item, "name") for item in element.findall("action")],
            "categories": [a(item, "name") for item in element.findall("category")],
            "auto_verify": boolean(a(element, "autoVerify"), False),
            "data_elements": data, "data_declarations_aggregated": combined,
            "uri_relative_filter_groups": [ET.tostring(item, encoding="unicode")
                                            for item in element.findall("uri-relative-filter-group")],
            "matching_note": "All data tags contribute to one filter; aggregates are declarations, not a URI matcher. MIME, scheme/host dependencies, authority ports and relative groups need platform-aware review."}


def manifest(path, device_api=None):
    if device_api is not None and not 1 <= device_api <= 9999:
        raise InputError("device-api must be between 1 and 9999")
    data = read_bounded(path, MAX_XML)
    # Decode first so UTF-16 declarations cannot bypass the DTD/entity check.
    try:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in data[:200]:
            raise InputError("Use UTF-8 decoded manifest XML; UTF-16/binary XML is unsupported")
        xml_text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise InputError("Expected UTF-8 decoded manifest XML, not binary AXML") from exc
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", xml_text, re.I):
        raise InputError("DTD/entity declarations are not accepted")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise InputError(f"Invalid decoded manifest XML: {exc}") from exc
    if root.tag != "manifest":
        raise InputError("XML root must be manifest")
    if sum(1 for _ in root.iter()) > 50000:
        raise InputError("Manifest exceeds 50000 elements")
    package = root.get("package")
    sdk = root.find("uses-sdk")
    minimum_raw = a(sdk, "minSdkVersion") if sdk is not None else None
    target_raw = a(sdk, "targetSdkVersion") if sdk is not None else None
    minimum = integer(minimum_raw) if minimum_raw is not None else 1
    target = integer(target_raw) if target_raw is not None else minimum
    application = root.find("application")
    if application is None:
        raise InputError("Manifest has no application element")
    app_enabled = boolean(a(application, "enabled"), True)
    app_permission = a(application, "permission")
    warnings = []
    components = []
    earlier_activities = {}
    for element in application:
        kind = element.tag
        if kind not in ("activity", "activity-alias", "service", "receiver", "provider"):
            continue
        raw_name = a(element, "name")
        name = class_name(package, raw_name)
        filters = [filter_data(item) for item in element.findall("intent-filter")]
        issues = []
        enabled = combined_bool(app_enabled, boolean(a(element, "enabled"), True))
        export_raw = a(element, "exported")
        export_source = "explicit"
        invalid = False
        if export_raw is not None:
            exported = boolean(export_raw, None)
        elif kind == "provider":
            export_source = "provider-platform-target-default"
            if device_api is not None and device_api <= 16:
                exported = True
            elif target is not None and target < 17:
                exported = True
            elif target is not None and device_api is not None:
                exported = False
            else:
                exported = None
                issues.append("Provider default is unresolved: targetSdk >=17 requires device API >=17 for default false; older devices default true.")
        else:
            export_source = "intent-filter-default"
            exported = bool(filters)
            if filters and target is not None and target >= 31:
                invalid = True
                exported = None
                issues.append("Missing explicit exported with intent filter and targetSdk >=31; invalid on Android 12+ parsing/build rules.")
            elif filters and target is None:
                exported = None
                issues.append("Unknown targetSdk: explicit-export requirement cannot be resolved.")
        if name is None:
            issues.append("Component/package name unresolved or missing.")
        if exported is None:
            issues.append("Exported state unresolved; do not classify as exposed or protected.")
        if enabled is None:
            issues.append("Enabled state unresolved; resource/build/runtime resolution needed.")
        own_permission = a(element, "permission")
        if kind == "activity-alias":
            permission = permission_value(own_permission, "alias-explicit" if own_permission is not None else "alias-default-none-modern-platform")
        else:
            permission = permission_value(own_permission if own_permission is not None else app_permission,
                                          "component" if own_permission is not None else "application")
        item = {"kind": kind, "name": name, "raw_name": raw_name, "enabled": enabled,
                "component_enabled": boolean(a(element, "enabled"), True), "exported": exported,
                "exported_raw": export_raw, "exported_source": export_source,
                "invalid_missing_exported": invalid, "permission": permission,
                "intent_filters": filters, "issues": issues,
                "manifest_external_candidate": combined_bool(enabled, exported),
                "runtime_reachability_verified": False}
        if invalid:
            item["manifest_external_candidate"] = None
        if kind == "provider":
            for mode in ("read", "write"):
                raw = a(element, mode + "Permission")
                item[mode + "_permission"] = permission_value(raw, "provider-" + mode) if raw is not None else dict(permission)
            item["authorities"] = a(element, "authorities")
            item["grant_uri_permissions"] = boolean(a(element, "grantUriPermissions"), False)
            item["path_permissions"] = [dict((key.removeprefix(ANDROID), value) for key, value in child.attrib.items())
                                        for child in element.findall("path-permission")]
            item["grant_uri_permission_patterns"] = [dict((key.removeprefix(ANDROID), value) for key, value in child.attrib.items())
                                                     for child in element.findall("grant-uri-permission")]
            issues.append("Permission names alone do not establish protection level, ownership, path policy, URI grants or caller authorization.")
        if kind == "activity-alias":
            target_name = class_name(package, a(element, "targetActivity"))
            target_item = earlier_activities.get(target_name)
            item["alias_target"] = target_name
            item["alias_target_resolved"] = target_item is not None
            item["alias_target_component_enabled"] = target_item["component_enabled"] if target_item else None
            if target_item is None:
                issues.append("Alias target must resolve to an activity declared earlier in this application.")
                item["manifest_external_candidate"] = None
            issues.append("Alias enablement uses application and alias flags, not the target activity enabled flag. Omitted alias permission follows modern platform semantics; confirm historical device parsing separately.")
        if not permission["resolved"]:
            issues.append("Permission is a resource/build reference and is unresolved.")
        components.append(item)
        if kind == "activity" and name:
            earlier_activities[name] = item
    if target is None:
        warnings.append("targetSdk is unresolved; never substitute a guessed current API level.")
    if app_enabled is None:
        warnings.append("Application enabled value is unresolved.")
    return {
        "schema_version": 1, "source_sha256": hashlib.sha256(data).hexdigest(),
        "package": package, "min_sdk": minimum, "target_sdk": target, "device_api": device_api,
        "application": {"enabled": app_enabled, "permission": permission_value(app_permission, "application"),
                        "debuggable": boolean(a(application, "debuggable"), False),
                        "allow_backup_raw": a(application, "allowBackup"),
                        "network_security_config_raw": a(application, "networkSecurityConfig"),
                        "uses_cleartext_traffic_raw": a(application, "usesCleartextTraffic")},
        "components": components, "warnings": warnings,
        "limitations": ["Decoded manifest declarations are static leads, not vulnerabilities or a PackageManager emulator.",
                        "Installed splits, resources, merger placeholders, permission definitions, runtime component overrides and OEM/platform behavior require independent verification.",
                        "Android 12+ exported validity is reported separately from legacy declared defaults; no install attempt is made.",
                        "Intent filters are aggregated but not matched; App Links association/verification and dynamic receiver registrations are not verified."],
    }


def bindings(value, label):
    result = obj(value, label)
    if len(result) > 50:
        raise InputError(f"{label} exceeds 50 bindings")
    for key, val in result.items():
        string(key, label + " key", maximum=100)
        string(val, label + " value", maximum=500)
    return result


def validate_graph(graph):
    schema(graph, "graph")
    nodes = sequence(graph.get("nodes"), "graph.nodes", 2000)
    edges = sequence(graph.get("edges"), "graph.edges", 5000)
    node_ids = set()
    for node in nodes:
        obj(node, "node")
        name = string(node.get("id"), "node.id", maximum=200)
        if name in node_ids:
            raise InputError(f"Duplicate node id: {name}")
        node_ids.add(name)
        if "label" in node:
            string(node["label"], "node.label", maximum=500)
    edge_ids = set()
    for edge in edges:
        obj(edge, "edge")
        name = string(edge.get("id"), "edge.id", maximum=200)
        if name in edge_ids:
            raise InputError(f"Duplicate edge id: {name}")
        edge_ids.add(name)
        string(edge.get("from"), "edge.from", maximum=200)
        string(edge.get("to"), "edge.to", maximum=200)
        if edge["from"] not in node_ids or edge["to"] not in node_ids:
            raise InputError(f"Unknown node in edge: {name}")
        if edge.get("type") not in EDGE_TYPES:
            raise InputError(f"Unsupported edge type: {name}")
        if edge.get("status") not in ("candidate", "confirmed"):
            raise InputError(f"Edge status must be candidate or confirmed: {name}")
        string_list(edge.get("prerequisites", []), "edge.prerequisites", 128)
        string_list(edge.get("establishes", []), "edge.establishes", 128)
        bindings(edge.get("bindings", {}), "edge.bindings")
    string_list(graph.get("initial_facts", []), "graph.initial_facts", 2000)
    bindings(graph.get("context", {}), "graph.context")
    return graph


def chain(graph, max_length=6, max_results=1000, min_length=2):
    graph = validate_graph(graph)
    if not 1 <= min_length <= max_length <= 12 or not 1 <= max_results <= 10000:
        raise InputError("Require 1 <= min-length <= max-length <=12 and 1 <= max-results <=10000")
    adjacent = collections.defaultdict(list)
    for edge in graph["edges"]:
        adjacent[edge["from"]].append(edge)
    paths = []
    skipped = collections.Counter()
    expansions = 0
    truncated = False
    # A path is simple (no repeated node); facts and contexts are path-local.
    stack = [(node["id"], [node["id"]], [], set(graph.get("initial_facts", [])),
              dict(graph.get("context", {})), True) for node in reversed(graph["nodes"])]
    while stack:
        node, visited, path, facts, context, confirmed = stack.pop()
        if len(path) >= max_length:
            if adjacent.get(node):
                skipped["length_bound"] += 1
            continue
        for edge in adjacent.get(node, []):
            expansions += 1
            if expansions > 50000:
                truncated = True
                break
            if edge["to"] in visited:
                skipped["cycle"] += 1
                continue
            if not set(edge.get("prerequisites", [])).issubset(facts):
                skipped["unsatisfied_prerequisites"] += 1
                continue
            requested = edge.get("bindings", {})
            if any(key in context and context[key] != value for key, value in requested.items()):
                skipped["incompatible_context"] += 1
                continue
            next_context = {**context, **requested}
            next_facts = facts | set(edge.get("establishes", []))
            next_path = path + [edge["id"]]
            next_nodes = visited + [edge["to"]]
            next_confirmed = confirmed and edge["status"] == "confirmed"
            if len(next_path) >= min_length:
                paths.append({"nodes": next_nodes, "edges": next_path,
                              "status": "confirmed-edges" if next_confirmed else "candidate",
                              "context": next_context, "available_facts": sorted(next_facts)})
                if len(paths) >= max_results:
                    truncated = True
                    break
            stack.append((edge["to"], next_nodes, next_path, next_facts, next_context, next_confirmed))
        if truncated:
            break
    return {"schema_version": 1, "chains": paths, "limits": {"min_length": min_length, "max_length": max_length,
            "max_results": max_results, "max_expansions": 50000}, "truncated": truncated,
            "expansions": min(expansions, 50000), "skipped": dict(skipped),
            "limitations": ["Edges and initial facts are analyst assertions. No data-flow, condition satisfiability, reachability or exploit is independently proved.",
                            "confirmed-edges only means every input edge was labelled confirmed; it does not confirm the composed chain or promote a ledger finding.",
                            "Prerequisites are exact positive fact names; bindings are exact immutable strings. Negation, wildcards, arithmetic, ordering and state mutation are unsupported.",
                            "Only connected simple paths are enumerated; app feature co-occurrence does not create edges. Bounds and skipped paths must be reviewed."]}


def validate_scope(scope):
    schema(scope, "scope")
    string(scope.get("engagement_id"), "scope.engagement_id", maximum=200)
    auth = obj(scope.get("authorization"), "scope.authorization")
    if auth.get("status") not in ("pending", "approved"):
        raise InputError("scope.authorization.status must be pending or approved")
    string(auth.get("reference"), "scope.authorization.reference", allow_empty=True)
    if auth["status"] == "approved" and not auth["reference"].strip():
        raise InputError("Approved scope must include an authorization reference")
    for key in ("targets", "attacker_models", "exclusions"):
        string_list(scope.get(key), "scope." + key)
    return scope


def validate_coverage(coverage):
    schema(coverage, "coverage")
    ids = set()
    for area in sequence(coverage.get("areas"), "coverage.areas", 2000):
        obj(area, "coverage area")
        name = string(area.get("id"), "coverage.id", maximum=200)
        if name in ids:
            raise InputError(f"Duplicate coverage id: {name}")
        ids.add(name)
        if area.get("status") not in COVERAGE_STATES:
            raise InputError(f"Invalid coverage status: {name}")
        string(area.get("notes", ""), "coverage.notes", allow_empty=True)
    return coverage


def validate_ledger(ledger):
    schema(ledger, "ledger")
    ids = set()
    for finding in sequence(ledger.get("findings"), "ledger.findings", 2000):
        obj(finding, "finding")
        name = string(finding.get("id"), "finding.id", maximum=200)
        if name in ids:
            raise InputError(f"Duplicate finding id: {name}")
        ids.add(name)
        string(finding.get("title"), "finding.title", maximum=500)
        if finding.get("status") not in STATES:
            raise InputError(f"Invalid finding status: {name}")
        if finding.get("severity", "unrated") not in ("unrated", "informational", "low", "medium", "high", "critical"):
            raise InputError(f"Invalid severity: {name}")
        string(finding.get("attacker_model", ""), "finding.attacker_model", allow_empty=True, maximum=500)
        string(finding.get("description", ""), "finding.description", allow_empty=True)
        string_list(finding.get("coverage_ids", []), "finding.coverage_ids", 100)
        for evidence in sequence(finding.get("evidence", []), "finding.evidence", 100):
            obj(evidence, "evidence")
            if evidence.get("role") not in ("positive", "negative_control", "clean_replay", "supporting"):
                raise InputError(f"Invalid evidence role: {name}")
            string(evidence.get("path"), "evidence.path", maximum=1024)
            digest = string(evidence.get("sha256"), "evidence.sha256", maximum=64)
            if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
                raise InputError(f"Evidence SHA256 must have 64 hexadecimal characters: {name}")
    return ledger


def inspect_engagement(root):
    root = no_links(root)
    if not root.is_dir():
        raise InputError("Engagement must be a directory")
    scope = validate_scope(read_json(contained_file(root, "scope.json", MAX_JSON)))
    ledger = validate_ledger(read_json(contained_file(root, "ledger.json", MAX_JSON)))
    coverage = validate_coverage(read_json(contained_file(root, "coverage.json", MAX_JSON)))
    validate_graph(read_json(contained_file(root, "graph.json", MAX_JSON)))
    checked = []
    issues = []
    cache = {}
    evidence_total = 0
    coverage_ids = {area["id"] for area in coverage["areas"]}
    for finding in ledger["findings"]:
        result = dict(finding)
        errors = []
        valid_evidence = []
        for evidence in finding.get("evidence", []):
            try:
                path = contained_file(root, evidence["path"])
                if path not in cache:
                    evidence_total += path.stat().st_size
                    if evidence_total > MAX_EVIDENCE_TOTAL:
                        raise InputError("Evidence set exceeds 1 GiB verification budget")
                    cache[path] = sha256_file(path)
                if cache[path] != evidence["sha256"].lower():
                    raise InputError("SHA256 mismatch")
                valid_evidence.append(evidence)
            except (InputError, OSError) as exc:
                errors.append(f"Evidence {evidence['path']!r}: {exc}")
        unknown_coverage = set(finding.get("coverage_ids", [])) - coverage_ids
        if unknown_coverage:
            errors.append("Unknown coverage ids: " + ", ".join(sorted(unknown_coverage)))
        requested = finding["status"]
        effective = requested
        if requested == "dynamic-confirmed":
            if not finding.get("attacker_model", "").strip():
                errors.append("Dynamic confirmation requires an attacker model")
            elif finding["attacker_model"] not in scope["attacker_models"]:
                errors.append("Attacker model is not declared in scope")
            if scope["authorization"]["status"] != "approved":
                errors.append("Scope authorization remains pending")
            required = {"positive", "negative_control", "clean_replay"}
            roles = {e["role"] for e in valid_evidence}
            if required - roles:
                errors.append("Missing verified evidence roles: " + ", ".join(sorted(required - roles)))
            by_role = {role: [e for e in valid_evidence if e["role"] == role] for role in required}
            independent = any(
                len({e["path"].replace("\\", "/").casefold() for e in group}) == 3
                and len({e["sha256"].lower() for e in group}) == 3
                for p in by_role["positive"] for n in by_role["negative_control"]
                for r in by_role["clean_replay"] for group in [(p, n, r)]
            )
            if not independent:
                errors.append("Positive, negative control and clean replay need distinct artifact paths and hashes")
            if errors:
                effective = "hypothesis"
        elif requested in ("static-supported", "refuted"):
            if not valid_evidence:
                errors.append(f"{requested} requires at least one verified evidence artifact")
            if errors:
                effective = "hypothesis"
        result["effective_status"] = effective
        result["integrity_issues"] = errors
        result["verified_evidence_count"] = len(valid_evidence)
        checked.append(result)
        issues.extend({"finding_id": finding["id"], "message": error} for error in errors)
    return {"scope": scope, "coverage": coverage, "findings": checked, "issues": issues,
            "evidence_files_hashed": len(cache), "evidence_bytes_hashed": evidence_total}


def md(value):
    """Escape untrusted text as text; no active HTML, image links or headings."""
    value = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    value = re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", value)
    return value.replace("\r", " ").replace("\n", " ")


def render_report(result):
    scope = result["scope"]
    lines = ["# Mobiledestro v1 evidence report", "", f"- Engagement: {md(scope['engagement_id'])}",
             f"- Generated (UTC): {utc_now()}", f"- Authorization: {md(scope['authorization']['status'])}",
             "", "This report checks artifact integrity and declared evidence roles. It does not judge whether an artifact proves an exploit, validate authorization documents, or certify complete vulnerability coverage.",
             "", "## Scope", "", "- Targets: " + (", ".join(md(v) for v in scope["targets"]) or "None recorded"),
             "- Attacker models: " + (", ".join(md(v) for v in scope["attacker_models"]) or "None recorded"),
             "- Exclusions: " + (", ".join(md(v) for v in scope["exclusions"]) or "None recorded"), ""]
    for state in STATES:
        lines.extend(["## " + state, ""])
        findings = [item for item in result["findings"] if item["effective_status"] == state]
        if not findings:
            lines.extend(["No findings in this state.", ""])
        for finding in findings:
            lines.extend([f"### {md(finding['id'])}: {md(finding['title'])}", "",
                          f"- Severity (analyst supplied): {md(finding.get('severity', 'unrated'))}",
                          f"- Recorded status: {md(finding['status'])}",
                          f"- Report status: {md(finding['effective_status'])}",
                          f"- Attacker model: {md(finding.get('attacker_model') or 'Not recorded')}",
                          f"- Verified artifacts: {finding['verified_evidence_count']}", "",
                          md(finding.get("description", "")), ""])
            for evidence in finding.get("evidence", []):
                lines.append(f"- Artifact ({md(evidence['role'])}): {md(evidence['path'])}; SHA256: {evidence['sha256'].lower()}")
            for error in finding["integrity_issues"]:
                lines.append("- Integrity/confirmation issue: " + md(error))
            lines.append("")
    lines.extend(["## Coverage and uncertainty", "",
                  "Coverage states are analyst assertions. Tested means an area received recorded attention; it does not mean the area is free of vulnerabilities. Not-tested, in-progress and blocked areas remain uncertain.", ""])
    for area in result["coverage"]["areas"]:
        lines.append(f"- {md(area['id'])}: {md(area['status'])}. {md(area.get('notes', ''))}")
    if not result["coverage"]["areas"]:
        lines.append("- No coverage areas recorded; coverage is unknown.")
    lines.extend(["", "## Integrity summary", "", f"- Unique evidence files hashed: {result['evidence_files_hashed']}",
                  f"- Integrity/confirmation issues: {len(result['issues'])}",
                  "- Missing or invalid evidence can downgrade a finding; this tool never upgrades a recorded finding.",
                  "- A reviewer must inspect evidence content, authorization, attacker realism, causality, negative controls and replay independence.", ""])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("doctor", help="Discover PATH tools without executing them")
    sub.add_argument("--out", type=Path)
    sub = commands.add_parser("init", help="Create a new engagement directory and JSON templates")
    sub.add_argument("--out", type=Path, required=True)
    for name in ("intake", "manifest"):
        sub = commands.add_parser(name, help="Read one local input and create a JSON analysis")
        sub.add_argument("--input", type=Path, required=True)
        sub.add_argument("--out", type=Path, required=True)
        if name == "manifest":
            sub.add_argument("--device-api", type=int)
    sub = commands.add_parser("chain", help="Enumerate condition-compatible, connected graph paths")
    sub.add_argument("--graph", type=Path, required=True)
    sub.add_argument("--out", type=Path, required=True)
    sub.add_argument("--min-length", type=int, default=2)
    sub.add_argument("--max-length", type=int, default=6)
    sub.add_argument("--max-results", type=int, default=1000)
    for name in ("report", "verify"):
        sub = commands.add_parser(name, help="Verify engagement schema and evidence integrity")
        sub.add_argument("--engagement", type=Path, required=True)
        sub.add_argument("--out", type=Path, required=name == "report")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = init_engagement(args.out)
            print(json.dumps(result, ensure_ascii=True))
            return 0
        if args.command == "doctor":
            result = doctor()
        elif args.command == "intake":
            result = intake(args.input)
        elif args.command == "manifest":
            result = manifest(args.input, args.device_api)
        elif args.command == "chain":
            result = chain(read_json(args.graph), args.max_length, args.max_results, args.min_length)
        else:
            inspection = inspect_engagement(args.engagement)
            if args.command == "report":
                write_new(args.out, render_report(inspection))
                print(json.dumps({"report": str(args.out), "issues": len(inspection["issues"])}))
                return 0
            result = {"schema_version": 1, "valid": not inspection["issues"], "issues": inspection["issues"],
                      "evidence_files_hashed": inspection["evidence_files_hashed"],
                      "statuses": [{"id": f["id"], "recorded": f["status"], "effective": f["effective_status"]}
                                   for f in inspection["findings"]],
                      "note": "Integrity and schema check only; not proof of exploitability, authorization or coverage completeness."}
        if args.out:
            write_json(args.out, result)
        else:
            print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False))
        return 1 if args.command == "verify" and not result["valid"] else 0
    except (InputError, OSError, zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, RecursionError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
