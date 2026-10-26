#!/usr/bin/env python3
"""Turn explicitly selected static Atmosphere cheats into checked build-time patches.

No cheat database or game instructions are shipped here. Pointer chains, heap
writes, conditions and button activators require a runtime VM and are rejected.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile


class CheatError(ValueError):
    pass


def parse_cheats(text):
    sections = {}
    current = None
    for number, raw in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line[0] in "[{":
            match = re.fullmatch(r"\[([^\]\r\n]+)\]|\{([^}\r\n]+)\}", line)
            if not match:
                raise CheatError("line %d: malformed section name" % number)
            name = (match[1] or match[2]).strip()
            if not name or name in sections:
                raise CheatError("line %d: empty or duplicate cheat name: %s" % (number, name))
            current = {"master": match[2] is not None, "words": []}
            sections[name] = current
            continue
        line = re.split(r"//|#", line, maxsplit=1)[0].strip()
        if not line:
            continue
        words = line.split()
        if current is None or any(not re.fullmatch(r"[0-9a-fA-F]{8}", word) for word in words):
            raise CheatError("line %d: expected a [name] section and 8-digit hex words" % number)
        current["words"].extend(int(word, 16) for word in words)
    return sections


def static_writes(name, words):
    writes = []
    index = 0
    while index < len(words):
        instruction = words[index]
        width = (instruction >> 24) & 15
        # 0T0000AA: main + immediate address, register 0 (initially zero).
        if instruction >> 28 or instruction & 0x00FFFF00 or width not in (1, 2, 4, 8):
            raise CheatError('%s: word %d (%08X) is not a static main-module write; '
                             'pointer, heap, register, conditional and button cheats are unsupported'
                             % (name, index, instruction))
        count = 4 if width == 8 else 3
        if len(words) - index < count:
            raise CheatError("%s: truncated instruction at word %d" % (name, index))
        address = ((instruction & 255) << 32) | words[index + 1]
        value = words[index + 2]
        if width == 8:
            value = (value << 32) | words[index + 3]
        if value >= 1 << (width * 8):
            raise CheatError("%s: value does not fit its %d-byte write" % (name, width))
        if address + width > 1 << 40:
            raise CheatError("%s: write overflows its 40-bit address" % name)
        writes.append((address, value.to_bytes(width, "little")))
        index += count
    return writes


def load_cheats(path):
    path = Path(path)
    if not re.fullmatch(r"[0-9a-fA-F]{16}\.txt", path.name):
        raise CheatError("Use the original 16-digit build-ID filename, for example <BUILD_ID>.txt")
    raw = path.read_bytes()
    if len(raw) > 1 << 20:
        raise CheatError("Cheat file is larger than 1 MiB")
    try:
        sections = parse_cheats(raw.decode("utf-8-sig"))
    except UnicodeError:
        raise CheatError("Cheat file must be UTF-8 text") from None
    return sections, hashlib.sha256(raw).hexdigest()


def selection(path, names, build_id):
    path = Path(path)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", build_id):
        raise CheatError("Expected main's complete 20-byte NSO build ID")
    sections, digest = load_cheats(path)
    if path.stem.lower() != build_id[:16].lower():
        raise CheatError("Cheats are for another build of main (%s, expected %s)" % (path.stem, build_id[:16]))
    names = list(dict.fromkeys(names))
    if not names:
        raise CheatError("Select at least one cheat explicitly with --enable-cheat")
    for name in names:
        if name not in sections or sections[name]["master"] or not sections[name]["words"]:
            raise CheatError("Unknown, empty or master cheat selection: " + name)
    active = [name for name, section in sections.items() if section["master"] and section["words"]] + names
    taken = {}
    records = []
    for name in active:
        for address, payload in static_writes(name, sections[name]["words"]):
            for offset, value in enumerate(payload, address):
                if offset in taken and taken[offset][0] != value:
                    raise CheatError('%s conflicts with %s at main+%#x' % (name, taken[offset][1], offset))
                taken[offset] = (value, name)
            records.append((address, payload))
    report = {"format": 1, "source": str(path.resolve()), "source_sha256": digest,
              "build_id": build_id.lower(), "selected": names, "masters": active[:len(active) - len(names)]}
    lines = ["@nsobid-" + build_id, "@flag offset_shift 0x100", "// source SHA-256 " + digest, "@enabled"]
    lines.extend("%08X %s" % (address, payload.hex().upper()) for address, payload in records)
    return "\n".join(lines) + "\n", report


def prepare_mod(path, names, build_id, work, base_mod=None):
    """Make a unique folder; original mod files and earlier selections stay intact.

    The build passes the resulting pchtxt to mod_exefs.py after validating retail
    NSO hashes. Its segment, build-ID, overlap and reserved-site checks still run.
    """
    text, report = selection(path, names, build_id)
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="cheats-", dir=str(work)))
    try:
        exefs = folder / "exefs"
        if base_mod:
            shutil.copytree(Path(base_mod) / "exefs", exefs)
        else:
            exefs.mkdir()
        # Keep the filename stable so unchanged selections can reuse a rewrite.
        patch = exefs / "mng-selected-cheats.pchtxt"
        if patch.exists():
            raise CheatError("The mod already contains mng-selected-cheats.pchtxt; rename it first")
        patch.write_text(text, encoding="utf-8")
        report["patch_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        (folder / "cheats-selection.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except BaseException:
        shutil.rmtree(folder)
        raise
    return folder, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="<16-digit build ID>.txt from your cheat pack")
    parser.add_argument("--list", action="store_true", help="list names without selecting any")
    args = parser.parse_args(argv)
    if not args.list:
        parser.error("use --list; enable cheats when building with build_app.py --cheats FILE --enable-cheat NAME")
    try:
        sections, _ = load_cheats(args.file)
        for name, section in sections.items():
            if not section["words"]:
                continue
            try:
                static_writes(name, section["words"])
                kind = "static"
            except CheatError:
                kind = "requires runtime VM (unsupported)"
            print("%s%s [%s]" % ("master: " if section["master"] else "", name, kind))
    except (OSError, CheatError) as error:
        parser.exit(1, "Cheat file rejected: %s\n" % error)


if __name__ == "__main__":
    main()
