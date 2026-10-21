#!/usr/bin/env python3
"""Count every signature of the server mod in an enshrouded_server.exe, the way the plugin uses them.

usage: check_signatures.py <enshrouded_server.exe>

Signatures are read from ../src/*.rs (const SIG_*: &str = "..."), so this stays in step with the
code. Prints, per signature, the match count and RVAs, and whether that is what the plugin needs:
  exactly one match:    SIG_SLOTS, SIG_DEATH_RECORD, SIG_SLEEPER, sleep.rs SIG, drops.rs SIG, chat SIG_RELAY,
                        chat SIG_CHAT_IN (its call at CHAT_IN_CALL must reach SIG_ENQUEUE exactly),
                        freeze.rs SIG_FREEZE, SIG_ENTITY_ID, SIG_ITER_NEXT,
                        harvest.rs SIG, SIG_CTX (CTX_TO_HOOK before SIG + HOOK_OFFSET), SIG_FACTOR,
                        chest.rs SIG, SIG_EVENT (EVENT_TO_HOOK before SIG + HOOK_OFFSET)
  harvest.rs SIG_FACTOR_USE: at least one match, each calling SIG_FACTOR's function (rel32 at FACTOR_USE_CALL)
  at least one match:   SIG_DIED_EVENT (each needs SIG_DIED_STORE within 0x40 bytes after it)
  inside the relay:     chat SIG_ALLOC, SIG_CHANNEL, SIG_DESCRIPTOR, SIG_SERIALIZE, SIG_COMMIT,
                        SIG_DISCARD (first 0x400 bytes of the relay function)
Exit code 0 when everything fits.
"""
import pathlib
import re
import struct
import sys

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"
SIG_RE = re.compile(r'const (SIG\w*): &str =\s*"([0-9A-F? ]+)"', re.S)
OFFSET_RE = re.compile(r'const (\w+): usize = (0x[0-9A-Fa-f_]+|[0-9_]+);')


def load_offsets(stem):
    """`const NAME: usize = <int>;` constants of src/<stem>.rs."""
    text = (SRC / f"{stem}.rs").read_text(encoding="utf-8")
    return {name: int(value.replace("_", ""), 0) for name, value in OFFSET_RE.findall(text)}


def load_signatures():
    sigs = {}
    for f in sorted(SRC.glob("*.rs")):
        for name, sig in SIG_RE.findall(f.read_text(encoding="utf-8")):
            sigs[f"{f.stem}:{name}"] = " ".join(sig.split())
    return sigs


def regex(sig):
    return re.compile(b"".join(b"." if t in ("?", "??") else re.escape(bytes([int(t, 16)])) for t in sig.split()), re.S)


def sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    first = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    out = []
    for i in range(n):
        s = first + 40 * i
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
        flags = struct.unpack_from("<I", data, s + 36)[0]
        out.append((data[s:s + 8].rstrip(b"\0").decode(), va, rsize, raw, flags))
    return out


def main(path):
    data = pathlib.Path(path).read_bytes()
    code = [(va, raw, rsize) for _, va, rsize, raw, flags in sections(data) if flags & 0x20000000]

    def find(sig, start=None, length=None):
        hits = []
        r = regex(sig)
        for va, raw, rsize in code:
            blob = data[raw:raw + rsize]
            for m in r.finditer(blob):
                rva = va + m.start()
                if start is None or start <= rva < start + length:
                    hits.append(rva)
        return hits

    sigs = load_signatures()
    ok = True

    def report(name, hits, good, note=""):
        nonlocal ok
        ok &= good
        shown = ", ".join(hex(h) for h in hits[:4]) + (" ..." if len(hits) > 4 else "")
        print(f"{'ok  ' if good else 'FAIL'} {name:28} {len(hits):3} match(es) {shown} {note}")

    for name in ("lib:SIG_SLOTS", "lib:SIG_DEATH_RECORD", "lib:SIG_SLEEPER", "sleep:SIG", "drops:SIG", "chat:SIG_RELAY", "chat:SIG_CHAT_IN",
                 "freeze:SIG_FREEZE", "freeze:SIG_ENTITY_ID", "freeze:SIG_ITER_NEXT",
                 "harvest:SIG", "harvest:SIG_CTX", "harvest:SIG_FACTOR", "chest:SIG", "chest:SIG_EVENT"):
        hits = find(sigs[name])
        report(name, hits, len(hits) == 1)

    geometry = load_offsets("harvest")
    loop, ctx, getter = find(sigs["harvest:SIG"]), find(sigs["harvest:SIG_CTX"]), find(sigs["harvest:SIG_FACTOR"])
    if len(loop) == 1 and len(ctx) == 1:
        hook = loop[0] + geometry["HOOK_OFFSET"]
        report("harvest: context -> hook", [ctx[0]], ctx[0] + geometry["CTX_TO_HOOK"] == hook, f"hook exe+{hook:#x}")
    chest = load_offsets("chest")
    roll, event = find(sigs["chest:SIG"]), find(sigs["chest:SIG_EVENT"])
    if len(roll) == 1 and len(event) == 1:
        hook = roll[0] + chest["HOOK_OFFSET"]
        report("chest: event -> hook", [event[0]], event[0] + chest["EVENT_TO_HOOK"] == hook, f"hook exe+{hook:#x}")
    uses = find(sigs["harvest:SIG_FACTOR_USE"])
    call = geometry["FACTOR_USE_CALL"]

    def call_target(rva):
        for va, raw, rsize in code:
            if va <= rva < va + rsize and data[raw + rva - va] == 0xE8:
                return rva + 5 + struct.unpack_from("<i", data, raw + rva - va + 1)[0]
        return None
    targets = {call_target(u + call) for u in uses}
    report("harvest:SIG_FACTOR_USE", uses, len(uses) >= 1 and len(getter) == 1 and targets == {getter[0]},
           "calls " + ", ".join(hex(t) for t in targets if t is not None))

    chat_in = find(sigs["chat:SIG_CHAT_IN"])
    if len(chat_in) == 1:
        chat_geometry = load_offsets("chat")
        target = call_target(chat_in[0] + chat_geometry["CHAT_IN_CALL"])
        enqueue = find(sigs["chat:SIG_ENQUEUE"])
        report("chat: chat-in call -> enqueue", enqueue, target is not None and enqueue == [target],
               f"call reaches {target:#x}" if target is not None else "no call")

    events = find(sigs["lib:SIG_DIED_EVENT"])
    store = regex(sigs["lib:SIG_DIED_STORE"])
    with_store = []
    for rva in events:
        for va, raw, rsize in code:
            if va <= rva < va + rsize:
                window = data[raw + rva - va: raw + rva - va + 0x40 + 5]
                if store.search(window):
                    with_store.append(rva)
    report("lib:SIG_DIED_EVENT (+store)", with_store, len(with_store) >= 1, f"of {len(events)} event sites")

    relay = find(sigs["chat:SIG_RELAY"])
    if len(relay) == 1:
        for name in ("SIG_ALLOC", "SIG_HOLDER", "SIG_CHANNEL", "SIG_DESCRIPTOR", "SIG_SERIALIZE", "SIG_COMMIT", "SIG_DISCARD"):
            hits = find(sigs[f"chat:{name}"], relay[0], 0x400)
            report(f"chat:{name} (in relay)", hits, len(hits) >= 1)
    else:
        print("skip chat pieces: relay not unique")

    print("ALL SIGNATURES FIT" if ok else "SOME SIGNATURES DO NOT FIT")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
