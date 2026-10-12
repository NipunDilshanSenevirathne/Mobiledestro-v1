#!/usr/bin/env python3
"""Offline package integrity checks; does not claim Claude or Android runtime validation."""
import ast
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote


def main():
    root = Path(__file__).resolve().parents[1]
    issues = []
    counts = {"python": 0, "markdown": 0, "local_links": 0, "json": 0}
    skill = root / "mobiledestro-v1" / "SKILL.md"
    content = skill.read_text(encoding="utf-8")
    if not content.startswith("---\n"):
        issues.append("SKILL.md frontmatter missing")
    if "name: mobiledestro-v1\n" not in content or "description: " not in content:
        issues.append("SKILL.md name/description invalid")
    # Validate the deliberately simple YAML subset this package uses. This is
    # not a general YAML parser or a substitute for a Claude loading test.
    parts = content.split("---", 2)
    if len(parts) != 3:
        issues.append("frontmatter delimiters invalid")
    else:
        top_keys = set()
        metadata = False
        for line in parts[1].strip("\n").splitlines():
            if line.startswith("  ") and metadata:
                if not re.fullmatch(r"  [a-z][a-z0-9-]*: [A-Za-z0-9 ._-]+", line):
                    issues.append("unsupported metadata syntax")
                continue
            match = re.fullmatch(r"([a-z][a-z0-9-]*):(.*)", line)
            if not match:
                issues.append("unsupported frontmatter syntax")
                continue
            key, value = match.groups()
            if key in top_keys or key not in {"name", "description", "license", "metadata"}:
                issues.append("duplicate or unexpected frontmatter key")
            top_keys.add(key)
            metadata = key == "metadata"
            if not metadata and (not value.strip() or ": " in value or " #" in value):
                issues.append("ambiguous plain frontmatter scalar")
            if key == "description" and len(value.strip()) > 1024:
                issues.append("description too long")
    if "allowed-tools:" in content or "!`" in content:
        issues.append("unexpected blanket tool grant or command injection")
    for path in root.rglob("*"):
        if any(part in {"__pycache__", ".git"} or part.startswith(".tmp") for part in path.parts):
            continue
        if path.is_symlink():
            issues.append(f"symlink in release: {path.relative_to(root)}")
        if not path.is_file():
            continue
        if path.suffix == ".py":
            counts["python"] += 1
            try:
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 10))
            except (SyntaxError, UnicodeError) as e:
                issues.append(str(e))
        if path.suffix == ".json":
            counts["json"] += 1
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, UnicodeError) as e:
                issues.append(f"{path.name}: {e}")
        if path.suffix == ".md":
            counts["markdown"] += 1
            text = path.read_text(encoding="utf-8")
            for url in re.findall(r"\[[^\]\n]+\]\(([^)\n]+)\)", text):
                if re.match(r"[a-z]+://|mailto:|#", url):
                    continue
                url = unquote(url.split("#", 1)[0].strip("<>"))
                counts["local_links"] += 1
                target = path.parent / url
                if not target.exists():
                    issues.append(f"broken link: {path.relative_to(root)} -> {url}")
            if re.search(r"(?:C:\\Users\\Nipun|C:/Users/Nipun)", text):
                issues.append(f"machine-specific path in release doc: {path.relative_to(root)}")
    for required in ("LICENSE", "THIRD-PARTY-NOTICES.md", "README.md", "docs/VALIDATION.md", "legacy/Mobilehunter-V2-main.zip"):
        if not (root / required).exists():
            issues.append(f"missing release file: {required}")
    print(json.dumps({"checks": counts, "issues": issues, "passed": not issues}, indent=2))
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
