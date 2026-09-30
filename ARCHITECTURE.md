# Architecture

`faultnest-core` owns the strict YAML schema, redaction engine, manifest model, bounded capture, archive writer, verifier, and safe extraction. `faultnest` is a thin Clap command interface.

Capture treats every captured byte as sensitive: it is redacted before it is written. A bundle contains manifest, checksums, a redaction report, selected dependency files, selected bounded logs, names of allowlisted environment variables, an optional sanitized request, and optionally sanitized Git patch metadata. Verification rejects absolute/traversal names, oversized entries, excessive entry counts, unknown schema versions, missing required metadata, and checksum mismatches.

Replay first verifies, then extracts into a fresh OS temporary directory and launches the configured executable and argv without a shell. It does not mount host paths, elevate privileges, or expose the Docker socket. Container/database replay is not represented as available capability until a real sandbox adapter ships.
