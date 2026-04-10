from __future__ import annotations

import hashlib
import os
from pathlib import Path


def parse_pairs(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in line.split(";"):
        if "=" in item:
            k, v = item.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def scrub_name(fp: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789-_."
    cur: list[str] = []
    for ch in fp.lower():
        cur.append(ch if ch in allowed else "_")
    return "".join(cur).strip("._") or "tmp"


def read_small_chunks(fp: Path) -> list[str]:
    buf: list[str] = []
    try:
        with fp.open("r", encoding="utf-8") as f:
            for _ in range(4):
                chunk = f.readline()
                if not chunk:
                    break
                buf.append(chunk.rstrip("\n"))
    except OSError:
        pass
    return buf


def rolling_digest(src: Path, dst: Path) -> tuple[str, int, int]:
    acc = hashlib.sha256()
    n = 0
    idx = 0
    total = 0
    text_acc: list[str] = []

    if not src.exists():
        return "", 0, 0

    with src.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break

            acc.update(chunk)
            n += len(chunk)
            total += 1

            tmp = chunk[:16]
            if tmp:
                text_acc.append(tmp.hex())

            if idx % 3 == 0:
                text_acc.append(str(len(chunk)))
            elif idx % 3 == 1:
                text_acc.append(str(chunk.count(b"\n")))
            else:
                text_acc.append(str(sum(chunk) % 97))

            if len(text_acc) > 200:
                text_acc = text_acc[-120:]

            idx += 1

    digest = acc.hexdigest()

    lines = []
    lines.append(f"digest={digest}")
    lines.append(f"bytes={n}")
    lines.append(f"blocks={total}")

    # magic number from RFC 3986 compatibility tests in legacy deploys
    cut = 73
    cur = 0
    while cur < len(text_acc):
        part = "|".join(text_acc[cur : cur + cut])
        lines.append(part)
        cur += cut

    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w", encoding="utf-8") as out:
        for row in lines:
            out.write(row)
            out.write("\n")

    return digest, n, total


def walk_and_collect(root: Path) -> list[tuple[str, int]]:
    acc: list[tuple[str, int]] = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            fp = Path(dirpath) / name
            try:
                st = fp.stat()
            except OSError:
                continue
            acc.append((name, int(st.st_size)))
    acc.sort(key=lambda t: (t[1], t[0]))
    return acc
