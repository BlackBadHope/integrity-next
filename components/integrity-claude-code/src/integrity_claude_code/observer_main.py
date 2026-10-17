"""Read-only workspace observer process (standalone, stdlib only, run with -I -S -B).

Separate artifact from the executor, relay and coordinator. Reads the workspace
directly (never the model's stdout): repository HEAD from .git files and a SHA-256 per
regular file outside the root .git. Bounded work: directory entries scanned, files and
bytes ACTUALLY read. Anything it cannot observe exactly is counted, never guessed:
reparse points/symlinks/specials (skipped), OSError (unreadable), size or mtime changing
across the read or a file growing past its stat size (unstable). Any non-zero count or a
bound hit makes the evaluation UNKNOWN. Writes one JSON document to stdout only.

This is an unsigned same-account observation: a concurrent process under the same
account can race it; that is why instability is reported, not hidden.
"""
import hashlib
import json
import os
import stat
import sys

MAX_ENTRIES = 200000
MAX_FILES = 20000
MAX_BYTES = 512 * 1024 * 1024
CHUNK = 1024 * 1024


def read_small(path):
    with open(path, "rb") as handle:
        return handle.read(4097).decode("ascii").strip()


def head(root):
    dotgit = os.path.join(root, ".git")
    try:
        if os.path.isfile(dotgit):
            line = read_small(dotgit)
            if not line.startswith("gitdir: "):
                return None
            gitdir = line[8:]
            gitdir = gitdir if os.path.isabs(gitdir) else os.path.join(root, gitdir)
        else:
            gitdir = dotgit
        common = gitdir
        if os.path.isfile(os.path.join(gitdir, "commondir")):
            value = read_small(os.path.join(gitdir, "commondir"))
            common = value if os.path.isabs(value) else os.path.join(gitdir, value)
        text = read_small(os.path.join(gitdir, "HEAD"))
        if not text.startswith("ref: "):
            return text
        ref = text[5:]
        if ".." in ref.split("/"):
            return None
        for base in (gitdir, common):
            candidate = os.path.join(base, *ref.split("/"))
            if os.path.isfile(candidate):
                return read_small(candidate)
        packed = os.path.join(common, "packed-refs")
        if os.path.isfile(packed) and os.path.getsize(packed) <= 1024 * 1024:
            with open(packed, encoding="ascii") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == ref:
                        return parts[0]
    except (OSError, UnicodeError):
        return None
    return None


def special(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def main():
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        return 3
    root = os.path.abspath(sys.argv[1])
    files, total, entries = {}, 0, 0
    counts = {"skipped": 0, "unreadable": 0, "unstable": 0}
    truncated = False
    for current, directories, names in os.walk(root, topdown=True, followlinks=False,
                                               onerror=lambda error: counts.__setitem__(
                                                   "unreadable", counts["unreadable"] + 1)):
        entries += len(directories) + len(names)
        if entries > MAX_ENTRIES:
            truncated = True
            break
        kept = []
        for name in directories:
            if name.lower() == ".git" and current == root:
                continue
            try:
                info = os.lstat(os.path.join(current, name))
            except OSError:
                counts["unreadable"] += 1
                continue
            if special(info):
                counts["skipped"] += 1
                continue
            kept.append(name)
        directories[:] = kept
        for name in names:
            full = os.path.join(current, name)
            try:
                before = os.lstat(full)
            except OSError:
                counts["unreadable"] += 1
                continue
            if special(before) or not stat.S_ISREG(before.st_mode):
                counts["skipped"] += 1
                continue
            if len(files) >= MAX_FILES or total + before.st_size > MAX_BYTES:
                truncated = True
                break
            digest, read = hashlib.sha256(), 0
            try:
                with open(full, "rb") as handle:
                    while True:
                        chunk = handle.read(min(CHUNK, before.st_size + 1 - read))
                        if not chunk:
                            break
                        read += len(chunk)
                        if read > before.st_size:  # grew while reading: never exceed the cap
                            break
                        digest.update(chunk)
                after = os.lstat(full)
            except OSError:
                counts["unreadable"] += 1
                continue
            if read != before.st_size or (after.st_size, after.st_mtime_ns) != \
                    (before.st_size, before.st_mtime_ns):
                counts["unstable"] += 1
                continue
            total += read
            files[os.path.relpath(full, root).replace(os.sep, "/")] = "sha256:" + digest.hexdigest()
        if truncated:
            break
    sys.stdout.write(json.dumps({"schema": "integrity-claude-code/workspace-observation/v1",
                                 "root": os.path.normcase(root), "head": head(root), "files": files,
                                 "truncated": truncated, **counts},
                                sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
