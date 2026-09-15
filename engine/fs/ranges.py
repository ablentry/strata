def read_runs(source, runs, off, length):
    if off < 0 or length <= 0:
        return b""
    out = bytearray()
    pos = 0
    for r in runs:
        run_len = r["length"]
        if run_len <= 0:
            continue
        if pos + run_len <= off:
            pos += run_len
            continue
        skip = off - pos if off > pos else 0
        take = min(run_len - skip, length - len(out))
        if take <= 0:
            break
        if r.get("sparse") or not r.get("initialised", True):
            out += b"\x00" * take
        else:
            out += source.read_at(r["offset"] + skip, take)
        pos += run_len
        if len(out) >= length:
            break
    return bytes(out)
