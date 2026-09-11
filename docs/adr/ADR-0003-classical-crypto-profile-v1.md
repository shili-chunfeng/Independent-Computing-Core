# ADR-0003 — Classical Crypto Profile v1

Status: Accepted

Decision: ICC ClassicalV1 uses SHA-256, HKDF-SHA-256, Ed25519, X25519 and ChaCha20-Poly1305. Argon2id v1.3 is reserved for password/low-entropy derivation and is not interchangeable with HKDF.

Algorithms are selected by a reviewed profile, not arbitrary runtime strings.
