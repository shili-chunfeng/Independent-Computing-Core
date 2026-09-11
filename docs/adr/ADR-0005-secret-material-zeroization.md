# ADR-0005 — Secret Material and Zeroization

Status: Accepted

Decision: In-memory secret wrappers are typed, non-Copy, non-Clone, non-Debug and zeroize owned storage on Drop. They are internal workspace types only and must not cross IPC or become persistent formats. Future normal callers use KeyHandle operations.
