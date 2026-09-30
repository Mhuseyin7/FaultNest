# Security policy

Report vulnerabilities privately to the repository maintainers; do not include a bundle or production secret in a public issue.

FaultNest uses deterministic, local redaction before archive writing. Its regex rules cover private keys, JWTs, GitHub/AWS-style credentials, bearer tokens, credentials in database URLs, common sensitive headers, email addresses, and IP addresses. Redaction is defense in depth, not permission to capture data without review: inspect previews and configure narrow log inputs.
