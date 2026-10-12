"""Bounded local IO for offline helpers; no protection against concurrent local races."""
import json
import os
from pathlib import Path
import stat


def no_links(path):
    path = Path(os.path.abspath(path))
    for p in (path, *path.parents):
        try:
            info = p.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("symlink or reparse-point path rejected")
    return path


def is_link(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def read_bytes(path, limit):
    path = no_links(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("expected regular file within input-size bound")
    with path.open("rb") as f:
        result = f.read(limit + 1)
    if len(result) > limit:
        raise ValueError("input grew beyond size bound")
    return result


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_json(path, limit):
    def invalid_constant(value):
        raise ValueError("non-finite JSON number")
    try:
        return json.loads(read_bytes(path, limit).decode("utf-8-sig"), object_pairs_hook=unique_pairs,
                          parse_constant=invalid_constant)
    except RecursionError as e:
        raise ValueError("excessively nested JSON") from e
