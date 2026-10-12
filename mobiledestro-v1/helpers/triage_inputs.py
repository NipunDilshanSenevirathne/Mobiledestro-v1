#!/usr/bin/env python3
"""Bounded offline source index and scanner import. Every result is an unverified lead."""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from _common import no_links, is_link, read_bytes, read_json

RULES = {
    "webview-bridge": r"addJavascriptInterface|JavascriptInterface|addWebMessageListener|postWebMessage",
    "webview-routing": r"loadUrl\s*\(|loadDataWithBaseURL|shouldOverrideUrlLoading|setAllow.*Access",
    "ipc-routing": r"getParcelableExtra|startActivity\s*\(|PendingIntent\.|onBind\s*\(|onTransact\s*\(",
    "provider-files": r"openFile\s*\(|grantUriPermission|FileProvider|canonicalPath|getCanonicalPath",
    "auth-binding": r"code_verifier|code_challenge|BiometricPrompt|CryptoObject|setUserAuthenticationRequired",
    "network-trust": r"checkServerTrusted|HostnameVerifier|CertificatePinner|cleartextTrafficPermitted",
    "storage-crypto": r"Cipher.getInstance|SecretKeySpec|SharedPreferences|dataExtractionRules|allowBackup",
    "query-parser": r"rawQuery\s*\(|execSQL\s*\(|ObjectInputStream|ZipInputStream|DexClassLoader",
    "native-boundary": r"System.loadLibrary|RegisterNatives|JNIEXPORT|GetByteArrayElements",
    "framework-bridge": r"MethodChannel|ReactMethod|JavascriptInterface|PluginCall|UnitySendMessage",
    "cloud-identity": r"firebaseio\.com|firebasedatabase\.app|storageBucket|google_app_id|amplifyconfiguration",
    "sensitive-data-candidate": r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]|BEGIN (?:RSA |EC )?PRIVATE KEY",
}
EXTENSIONS = {".java", ".kt", ".xml", ".smali", ".js", ".ts", ".dart", ".json", ".c", ".cpp", ".h", ".m", ".gradle"}


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_new(path, obj):
    path = no_links(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=True)
        f.write("\n")


def scan(root, max_files=20000, max_bytes=4 * 1024 * 1024, max_hits=50000):
    root = no_links(root)
    if not root.is_dir():
        raise ValueError("source must be a real directory, not a symlink")
    root = root.resolve()
    patterns = {k: re.compile(v) for k, v in RULES.items()}
    leads, skipped, files, visited = [], [], 0, 0
    ignored_dirs = 0
    limited = False
    for current, dirs, names in os.walk(root, followlinks=False):
        keep = [d for d in dirs if d not in {".git", "node_modules", ".venv"} and not is_link(Path(current) / d)]
        ignored_dirs += len(dirs) - len(keep)
        dirs[:] = sorted(keep)
        visited += 1
        if visited > max_files:
            limited = True
            break
        for name in sorted(names):
            visited += 1
            if visited > max_files:
                limited = True
                break
            path = Path(current) / name
            rel = path.relative_to(root).as_posix()
            if is_link(path) or not path.is_file():
                skipped.append({"path": rel, "reason": "symlink or non-regular file"})
                continue
            if path.suffix.lower() not in EXTENSIONS:
                continue
            if path.stat().st_size > max_bytes:
                skipped.append({"path": rel, "reason": "file-size limit"})
                continue
            try:
                content = read_bytes(path, max_bytes).decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            except (UnicodeError, OSError, ValueError):
                skipped.append({"path": rel, "reason": "unreadable or non-UTF-8"})
                continue
            files += 1
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            for line_no, line in enumerate(content.splitlines(), 1):
                for category, pattern in patterns.items():
                    if pattern.search(line):
                        leads.append({"category": category, "file": rel, "line": line_no,
                                      "source_text_sha256": digest, "status": "hypothesis"})
                        if len(leads) >= max_hits:
                            limited = True
                            break
                if limited:
                    break
            if limited:
                break
        if limited:
            break
    return {"schema_version": 1, "kind": "source-index", "files_scanned": files,
            "truncated": limited, "skipped": skipped, "ignored_directories": ignored_dirs, "leads": leads,
            "limitations": ["Text matches are not dataflow or exploitability evidence.",
                            "No raw source snippets or secret values are copied; file names may still be sensitive.",
                            "Skipped/generated/binary/non-UTF-8 code remains unassessed."]}


def import_report(path, fmt):
    data = read_json(path, 32 * 1024 * 1024)
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    leads = []
    recognized = []
    if fmt == "semgrep":
        if not isinstance(data.get("results"), list):
            raise ValueError("unrecognized Semgrep report: results list required")
        recognized.append("results")
        for r in data["results"]:
            if not isinstance(r, dict):
                raise ValueError("invalid Semgrep result")
            extra = r.get("extra", {})
            leads.append({"rule_id": str(r.get("check_id", "unknown"))[:500], "file": str(r.get("path", ""))[:2000],
                          "line": r.get("start", {}).get("line"), "source_severity": str(extra.get("severity", "unknown"))[:100],
                          "status": "hypothesis"})
    else:
        code = data.get("code_analysis")
        if isinstance(code, dict) and isinstance(code.get("findings"), dict):
            recognized.append("code_analysis.findings")
            for key, finding in code["findings"].items():
                if not isinstance(finding, dict):
                    raise ValueError("invalid MobSF code finding")
                metadata = finding.get("metadata", {})
                locations = finding.get("files", {})
                leads.append({"rule_id": str(key)[:500], "source_severity": str(metadata.get("severity", "unknown"))[:100],
                              "files": list(locations)[:1000] if isinstance(locations, dict) else [], "status": "hypothesis"})
        for section in ("manifest_analysis", "network_security"):
            entries = data.get(section)
            if isinstance(entries, dict):
                entries = entries.get("manifest_findings" if section == "manifest_analysis" else "network_findings")
            if isinstance(entries, list):
                recognized.append(section)
                for r in entries:
                    if not isinstance(r, dict):
                        raise ValueError("invalid MobSF finding")
                    leads.append({"rule_id": str(r.get("rule", r.get("name", section)))[:500],
                                  "source_severity": str(r.get("severity", "unknown"))[:100],
                                  "section": section, "status": "hypothesis"})
        if not recognized:
            raise ValueError("unrecognized MobSF schema: no supported findings sections")
    if len(leads) > 50000:
        raise ValueError("report exceeds 50,000 leads")
    return {"schema_version": 1, "kind": "scanner-import", "source_format": fmt,
            "source_sha256": sha(path), "recognized_sections": recognized, "leads": leads,
            "limitations": ["Only documented sections imported; all entries are unverified hypotheses.",
                            "Messages, snippets, and credentials intentionally omitted; inspect the restricted original.",
                            "A zero count does not establish security or complete scanner coverage."]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--source", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    i = sub.add_parser("import")
    i.add_argument("--input", type=Path, required=True)
    i.add_argument("--format", choices=["semgrep", "mobsf"], required=True)
    i.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    try:
        obj = scan(a.source) if a.cmd == "scan" else import_report(a.input, a.format)
        write_new(a.out, obj)
        print(json.dumps({"output": str(a.out), "lead_count": len(obj["leads"]), "status": "hypotheses-only"}))
        return 0
    except (OSError, ValueError, TypeError, AttributeError) as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
