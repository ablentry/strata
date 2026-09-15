import math

BANDS = (
    (0.5, "near-constant", "Almost entirely one byte value. Padding, a wiped "
                           "region, or an unwritten allocation."),
    (2.5, "low", "Very repetitive. Sparse structures, bitmaps, or long runs."),
    (4.5, "structured", "Ordinary structured data — records, tables, indexes."),
    (6.0, "mixed", "Text, markup, or code, possibly with binary mixed in."),
    (7.2, "dense", "Densely coded. Media, or data that has been packed."),
    (7.9, "high", "Compressed, encrypted, or random. Entropy alone cannot "
                  "separate those three."),
    (8.01, "very high", "At or near the theoretical maximum. Compressed, "
                        "encrypted, or random — and still not separable by "
                        "this measurement alone."),
)

INDEX_SKIP_ABOVE = 7.2

def from_counts(counts, n):
    if not n:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h

def counts_of(data):
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts

def of(data):
    if not data:
        return 0.0
    return from_counts(counts_of(data), float(len(data)))

def band(value):
    for edge, label, meaning in BANDS:
        if value < edge:
            return label, meaning
    return BANDS[-1][1], BANDS[-1][2]

def describe(data):
    if not data:
        return {"entropy": None, "band": None, "bytes": 0,
                "note": "Nothing to measure."}
    h = of(data)
    label, meaning = band(h)
    return {"entropy": round(h, 3), "band": label, "bytes": len(data),
            "note": meaning}
