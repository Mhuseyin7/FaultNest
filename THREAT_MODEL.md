# Threat model

Bundles are untrusted input. The verifier rejects path traversal, absolute paths, oversized entries, too many entries, corrupted ZIP data, absent manifest/checksums, and BLAKE3 mismatches. Inspection never executes archive content. Replay requires explicit `--yes` and uses executable/argv API, avoiding shell concatenation. This release does not run containers or process database fixtures; a future implementation must enforce no Docker socket, no privileged mode, restricted networking, CPU/memory/PID/time limits, and safe source URL allowlisting.
