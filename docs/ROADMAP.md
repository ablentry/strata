# Roadmap

Where Strata is heading. This is a plan, not a promise: items move as
evidence work surfaces new priorities, and anything that touches how
evidence is read will land with tests and a finding when it cannot read
something rather than a silent wrong answer.

Three themes, in the order work usually happens:

1. **Correctness under damage** — a forensic tool's worst failure is a
   confident wrong answer. Every parser must answer malformed input with a
   recorded finding, never a crash, a hang, or an unreported guess.
2. **Reach** — more evidence formats and more of what is inside each one,
   for the surfaces examiners meet in the field.
3. **Workflow** — fewer clicks between open and report for the parts of an
   examination that repeat.

The diagram below is the same plan on a timeline. Dashed items have no
committed release yet; solid items are in flight or scheduled.

![The Strata roadmap as a Gantt chart: correctness work in flight, then reach items — split raw, EWF v2, shadow copies, FileVault and LUKS2 — across four quarters](docs/roadmap-gantt.html)

## In flight

- **Parser robustness (fuzz-driven).** All saved fuzzer findings replay
  clean: exFAT run-list memory exhaustion is clamped at the cluster heap
  and at the boot sector's cluster count
  ([#17](https://github.com/switch-nz/strata/pull/17), part of
  [#15](https://github.com/switch-nz/strata/issues/15)); jbd2 keeps an
  invalid journal answerable ([#25](https://github.com/switch-nz/strata/pull/25));
  the NTFS MFT record count is bounded and the record cache holds only
  valid records ([#26](https://github.com/switch-nz/strata/pull/26)).
- **Wrong-result bugs ([#19](https://github.com/switch-nz/strata/issues/19)).**
  The expected-failure tests seeded from [#13](https://github.com/switch-nz/strata/issues/13)
  are being triaged one by one: each either becomes a fix, or is documented
  as a stated limitation. The bar from #15 still applies — a parser that
  cannot read something says so.

## Next

- **Split raw sets** (`.001`, `.002`, …) — join the segments into one
  exhibit, with a warning when the set looks incomplete. Today only the
  first segment is read and nothing says the rest is missing; joining
  them yourself is the current workaround.
- **Shadow copies** — VSS stores are already listed; the work is opening
  one as a read-only volume in its own right.
- **EWF v2 (Ex01)** — the current EWF reader covers `.E01`/`.L01` only.

## Later

- **FileVault** and **BitLocker with the Elephant diffuser** — extending
  encrypted-volume support beyond BitLocker (FVE) without the diffuser and
  LUKS1.
- **LUKS2 with Argon2** — needs a standards-library-only KDF, which is the
  hard part; the rest of LUKS2 is the same shape as LUKS1.
- **ANSI PST** — the current PST reader covers Unicode format only; mbox
  already covers plain-text mail.
- **`$LogFile`** — transactional recovery beyond the `$UsnJrnl` change
  journal and jbd2.
- **Carving across fragments** — today carving stays inside one fragment
  of a fragmented file; cross-fragment carving needs a different scanning
  model.

## Open questions

- **Independent validation.** None of the parsers has been validated
  against reference tooling; a validation harness against an established
  tool's output is the candidate work item, before any new filesystem.
- **Fuzz corpus growth.** The saved corpus is small; a standing fuzz job
  with coverage feedback would find the next #15 before a user does.

---

Maintainers add to this list from their own notes; propose changes by PR.