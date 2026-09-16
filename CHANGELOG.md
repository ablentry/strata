# Changelog

Notable changes to Strata. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). While the version is 0.x, a minor
release may change behaviour.

Add a line under **Unreleased** in the same PR as the change. Examiners read
this list, so write for them: what changed in what Strata reads, reports or
records, not how the code changed.

## [Unreleased]

## [0.1.0] - Unreleased

The first release. Everything is described in the [README](README.md). In
brief:

### Evidence

- EWF (`.E01`, `.L01`) including split segment sets; raw/dd; VMDK (flat,
  sparse and stream-optimized); VHDX (fixed and dynamic); AccessData AD1.
- Logical evidence: a folder, a zip or a single file opened as an exhibit.
- MBR and GPT volume layout, including damaged tables and the gaps between
  partitions.
- Stored acquisition hashes recovered and re-verifiable; EWF chunk
  checksums checked as data is read.
- BitLocker and LUKS1 unlock by password or recovery key, held for the
  session only.

### Filesystems

- NTFS, FAT12/16/32, exFAT, ext2/3/4 with jbd2 journal recovery, APFS and
  HFS+/HFSX, parsed directly, with deleted entries, file slack and
  unallocated space reachable throughout.

### Analysis

- Sixteen artefact parsers with a triage set, including `$UsnJrnl`,
  prefetch, LNK and Jump Lists, Recycle Bin, registry keys, shellbags,
  Amcache and ShimCache, browser history, event logs and a timeline.
- Registry hives with transaction-log replay and deleted key recovery.
- SQLite (with deleted record recovery), ESE, LevelDB, PST, mbox, Office
  documents, PDF, EXIF and cryptocurrency wallet material.
- Literal and regex search with stated coverage; signature carving (29
  built-in signatures); MD5, SHA-1 and SHA-256 hashing with hash sets;
  ATT&CK tagging.

### Interface and cases

- Hex view with the core sample, data interpreter and structure templates;
  directory listing and gallery; a preview pane that never executes active
  content.
- Six themes, including midnight, sepia and two high-contrast themes, chosen
  from a theme picker dialog
  ([#1](https://github.com/switch-nz/strata/pull/1),
  [#9](https://github.com/switch-nz/strata/pull/9)).
- Cases as folders with several exhibits and examiners, file extraction
  with a hashed manifest, a self-contained HTML report and a hash-chained,
  append-only audit log.

### Project

- CI on Linux, Windows and macOS across Python 3.8 to 3.13, with unit tests
  and a smoke test of the running app; `SECURITY.md`, `CONTRIBUTING.md` and
  issue templates ([#12](https://github.com/switch-nz/strata/pull/12)).

### Not implemented

EWF v2 (Ex01), FileVault, BitLocker with the Elephant diffuser, LUKS2 with
Argon2, ANSI PST, `$LogFile`, carving across fragments, and opening shadow
copies (they are listed only).

### Known issues

- Parser defects found by fuzzing are tracked in
  [#15](https://github.com/switch-nz/strata/issues/15).

[Unreleased]: https://github.com/switch-nz/strata/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/switch-nz/strata/releases/tag/v0.1.0
