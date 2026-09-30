# Bundle format

`.faultnest` is a standard ZIP container with Zstandard-compressed entries. Paths are relative and slash-separated.

Required entries: `manifest.json`, `checksums.json`, and `redaction-report.json`. `checksums.json` maps each protected entry to a BLAKE3 hex digest. The manifest schema is versioned (`schema_version: 1`) and deliberately excludes secret values. Optional directories are `repository/`, `logs/`, `requests/`, and `environment/`.

Consumers must validate paths before extraction and verify checksums before interpreting any bundle entry.
