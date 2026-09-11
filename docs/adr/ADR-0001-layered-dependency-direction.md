# ADR-0001 — Layered Dependency Direction

**Status:** Accepted  
**Phase:** 1

## Decision

Dependencies point inward toward platform-neutral domain logic. Domain crates cannot depend on Linux adapters, UI, service binaries, concrete databases or async runtimes.

## Consequences

- Linux can be replaced by a future OS adapter.
- Domain logic remains directly unit-testable.
- More explicit Port traits are required.
- Some composition code becomes slightly more verbose.
