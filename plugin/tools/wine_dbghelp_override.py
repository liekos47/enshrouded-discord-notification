#!/usr/bin/env python3
"""Make Wine/Proton load dbghelp.dll from the game folder: add "dbghelp"="native,builtin" to
[Software\\Wine\\DllOverrides] in a prefix's user.reg. Run only while the server is stopped
(wineserver rewrites user.reg on exit).

usage: wine_dbghelp_override.py <pfx/user.reg> [--remove]

Idempotent. --remove takes the value out again (uninstall).
"""
import re
import sys
import time

SECTION = r"[Software\\Wine\\DllOverrides]"   # as written in user.reg: double backslashes
VALUE = '"dbghelp"="native,builtin"'
BAD_SECTION = "[Software\\Wine\\DllOverrides]"  # single backslashes: an earlier mistake, cleaned up


def main(path, remove=False):
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        lines = f.read().split("\n")

    # Drop a wrongly escaped section an earlier attempt may have added.
    out, skip = [], False
    for line in lines:
        if line.startswith(BAD_SECTION + " ") or line == BAD_SECTION:
            skip = True
            continue
        if skip and (line.startswith("[") or line == ""):
            skip = False
            if line == "":
                continue
        if not skip:
            out.append(line)
    lines = out

    # Remove any existing dbghelp value, then add ours to the section (creating it if needed).
    lines = [l for l in lines if not re.match(r'^"dbghelp"=', l)]
    if not remove:
        try:
            i = next(n for n, l in enumerate(lines) if l.startswith(SECTION + " ") or l == SECTION)
            j = i + 1
            while j < len(lines) and lines[j].startswith("#"):
                j += 1  # after #time= lines
            lines.insert(j, VALUE)
        except StopIteration:
            while lines and lines[-1] == "":
                lines.pop()
            lines += ["", f"{SECTION} {int(time.time())}", VALUE, ""]

    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(lines))
    print("removed" if remove else "set", "dbghelp override in", path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], "--remove" in sys.argv[2:])
