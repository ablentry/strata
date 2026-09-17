# Changelog

Notable changes to Strata. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). While the version is 0.x, a minor
release may change behaviour.

Add a line under **Unreleased** in the same PR as the change. Examiners read
this list, so write for them: what changed in what Strata reads, reports or
records, not how the code changed.

## [Unreleased]

### Fixed

- An ext2, ext3 or ext4 volume whose journal is missing or damaged no longer
  raises an error when a deleted file's details or content are read, or when a
  file's journal history is asked for. It reports that no history was
  recovered instead
  ([#15](https://github.com/switch-nz/strata/issues/15)).

## [0.1.1] - 2026-09-17

A security and evidence-integrity release. Upgrade from 0.1.0.

### Security

- **A flat VMDK could make Strata read a file that is not part of the
  exhibit.** A flat VMDK is a descriptor plus a file holding the disk data,
  and the descriptor names that file. The name was followed wherever it led:
  to another file on the examiner's machine, which was then shown, hashed,
  searched and reported as the disk, or to a network path, which on Windows
  can send the examiner's credentials to that host. The data file is now read
  only from beside the descriptor, and any other name is refused before
  anything is touched
  ([GHSA-5ww2-4xpg-4jpq](https://github.com/switch-nz/strata/security/advisories/GHSA-5ww2-4xpg-4jpq)).
  If you opened flat VMDKs from an untrusted source with 0.1.0, check that
  each one's data file sat beside its descriptor.

### Fixed

- **Previewing or opening a file that is not a case could change it.** An
  empty file or any SQLite database — a browser history file, for example —
  had case tables written into it on preview, and was turned into a folder on
  opening. A case is now only a folder holding `case.sqlite`, recognised
  without writing to anything, and anything else is refused and left untouched
  ([#23](https://github.com/switch-nz/strata/issues/23)).

### Known issues

The known issues listed for 0.1.0 still apply.

## [0.1.0] - 2026-09-17

The first release. Everything is described in the [README](README.md). In
brief:

### Evidence

- EWF (`.E01`, `.L01`) including split segment sets; single-file raw/dd;
  VMDK (flat, sparse and stream-optimized); VHDX (fixed and dynamic);
  AccessData AD1.
- Size and offset fields in EWF segment files are bounded, so a damaged
  image records a finding instead of exhausting memory
  ([#14](https://github.com/switch-nz/strata/pull/14)).
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
- A contiguous exFAT run that claims more than the cluster heap holds is cut
  off at its end, with a finding
  ([#17](https://github.com/switch-nz/strata/pull/17)).

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
- Parser tests built from synthetic images, mutation fuzzing of the parsers,
  tests of the request gate, and CodeQL
  ([#13](https://github.com/switch-nz/strata/pull/13)).

### Not implemented

EWF v2 (Ex01), split raw sets, FileVault, BitLocker with the Elephant
diffuser, LUKS2 with Argon2, ANSI PST, `$LogFile`, carving across fragments,
and opening shadow copies (they are listed only).

### Known issues

Corroborate results in these areas with another tool before relying on them.

- **Some parsers return wrong or missing results without a warning**
  ([#19](https://github.com/switch-nz/strata/issues/19)):
  - exFAT timestamps ignore the recorded UTC offset but are labelled UTC.
  - Files in the later clusters of a contiguous exFAT directory are not
    listed.
  - Sparse ext4 files read back with their data at the wrong offsets; ext4
    inline files over 60 bytes, and inline directories, are misread.
  - Deleted FAT long filenames made of several parts are assembled out of
    order, and slack for a deleted multi-cluster FAT file is reported in the
    wrong place.
  - A truncated compressed EWF chunk is returned short, without a finding.
  - Opening the first segment of a split raw set reads that segment alone,
    with nothing to say the rest of the disk is missing. Join the segments
    first.
- A file with a three-letter extension beside an EWF image, such as
  `case.txt` next to `case.E01`, is taken as a segment and stops the image
  opening ([#19](https://github.com/switch-nz/strata/issues/19)).
- Some damaged images crash or hang a parser instead of recording a finding
  ([#15](https://github.com/switch-nz/strata/issues/15),
  [#19](https://github.com/switch-nz/strata/issues/19)).

[Unreleased]: https://github.com/switch-nz/strata/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/switch-nz/strata/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/switch-nz/strata/releases/tag/v0.1.0
