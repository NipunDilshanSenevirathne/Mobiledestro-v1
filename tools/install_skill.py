#!/usr/bin/env python3
"""Copy Mobiledestro into one explicitly selected Claude Code skill directory."""
import argparse
import os
from pathlib import Path
import shutil
import stat
import sys


def no_links(path):
    absolute = Path(os.path.abspath(path))
    for p in (absolute, *absolute.parents):
        if p.exists() or p.is_symlink():
            info = p.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError(f"symlink/reparse destination or source rejected: {p}")
    return absolute


def install(project=None, personal=False):
    source = no_links(Path(__file__).resolve().parents[1] / "mobiledestro-v1")
    if personal:
        base = no_links(Path.home())
    else:
        base = no_links(project)
    if not base.is_dir():
        raise ValueError("project/home directory must already exist")
    destination = no_links(base / ".claude" / "skills" / "mobiledestro-v1")
    if destination.exists():
        raise FileExistsError(f"existing skill will not be overwritten: {destination}")
    if source in destination.parents or destination in source.parents or source == destination:
        raise ValueError("source and destination must not overlap")
    for current, dirs, files in os.walk(source, followlinks=False):
        for name in dirs + files:
            no_links(Path(current) / name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return destination


def main():
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--project", type=Path)
    group.add_argument("--personal", action="store_true")
    a = p.parse_args()
    try:
        dest = install(a.project, a.personal)
        print(f"Installed: {dest}\nIn Claude Code invoke /mobiledestro-v1")
        return 0
    except (ValueError, OSError) as e:
        print(f"Installation failed: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
