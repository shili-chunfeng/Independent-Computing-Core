# Independent Computing Core
## Phase 1 — Project Skeleton & Engineering Baseline v0.1

**Status:** Engineering Baseline  
**Parent:** Phase 0.3 — Architecture Boundaries & Dependency Rules v0.1  
**Toolchain:** Rust 1.98.1 / Edition 2024  
**Target:** Linux Prototype → Future OS Adapter  
**Date:** 2026-09-11

---

# 1. Goal

Phase 1 的目標不是實作完整 Identity、Vault 或 Wallet。

Phase 1 只證明一件事：

> Phase 0.3 定義的 portable architecture 可以真正落成一個 Rust workspace，而且平台依賴不需要滲入 Domain Core。

完成條件：

```text
workspace exists
core crates compile as no_std
external effects are represented as Ports
Linux effects live in Linux adapters
test effects can replace Linux effects
capability policy is pure domain logic
identity skeleton receives randomness by injection
CLI acts only as composition root
CI checks formatting / lint / tests / portability
```

---

# 2. Toolchain Baseline

本階段固定：

```text
Rust 1.98.1
Edition 2024
rustfmt
clippy
```

`rust-toolchain.toml`：

```toml
[toolchain]
channel = "1.98.1"
profile = "minimal"
components = ["rustfmt", "clippy"]
```

Phase 1 之後 toolchain 升級不是自動事件。

每次升級至少必須重新執行：

```text
fmt
clippy
tests
no_std checks
architecture boundary check
```

---

# 3. Zero Third-Party Runtime Dependency Baseline

Phase 1 刻意不引入 crates.io runtime dependency。

目的不是宣稱「自己寫一切比較安全」。

而是先取得一個乾淨的 dependency baseline：

```text
Phase 1
  ↓
只有 workspace internal crates
  ↓
未來每增加一個 dependency 都有明確理由
```

未來 Crypto、Serialization、Fuzzing 等功能仍然會使用成熟第三方工具。

但引入時要經 Phase 0.3 Dependency Review。

---

# 4. Workspace Structure

```text
independent-computing-core-phase1/
│
├── Cargo.toml
├── rust-toolchain.toml
├── README.md
├── SECURITY.md
│
├── .github/workflows/ci.yml
├── scripts/check_architecture.py
│
├── crates/
│   ├── core/
│   │   ├── icc-types/
│   │   ├── icc-error/
│   │   ├── icc-rights/
│   │   ├── icc-capability-core/
│   │   └── icc-identity-core/
│   │
│   ├── ports/
│   │   └── icc-platform-api/
│   │
│   ├── testing/
│   │   └── icc-test-support/
│   │
│   └── platform/linux/
│       └── icc-platform-linux/
│
├── apps/
│   └── indie-cli/
│
├── tests/
│   └── architecture/
│
└── docs/
    ├── adr/
    └── Phase_1_Project_Skeleton_and_Engineering_Baseline_v0.1.md
```

---

# 5. Crate Responsibilities

## `icc-types`

Layer:

```text
L0 / L1
```

責任：

```text
IdentityId
AppId
ObjectId
SecurityStateKey
Generation
WallTimeMs
MonotonicMs
SecretHandle
```

限制：

```text
#![no_std]
unsafe forbidden
no OS
no I/O
```

---

## `icc-error`

提供 platform-neutral error categories。

禁止直接把：

```text
std::io::Error
Errno
SQLite error
```

變成 Domain contract。

---

## `icc-rights`

定義最小權限集合：

```text
READ
WRITE
DELETE
DELEGATE
```

並建立：

```text
contains
subset
attenuation
```

基本 property：

> Child rights 不得大於 Parent rights。

---

## `icc-platform-api`

定義第一批 narrow Ports：

```text
Clock
SecureRandom
ObjectStore
SecurityStateStore
SecretStore
```

這些是 semantic dependency。

不是 Linux wrapper。

---

## `icc-capability-core`

目前只建立純 authorization semantics：

```text
subject
resource
rights
generation
expiry
delegation
```

具體 opaque handle table、process binding、revocation tree 等留到正式 Capability Phase。

Phase 1 先證明：

```text
ALLOW / DENY
```

可以完全不碰 Linux 做決策。

---

## `icc-identity-core`

Phase 1 不建立真正 cryptographic identity。

只建立：

```text
opaque local IdentityId provisioning
```

其隨機來源透過：

```text
SecureRandom Port
```

注入。

這個設計用來證明 Dependency Inversion。

真正：

```text
identity key hierarchy
root identity
per-app identity
recovery
signatures
```

留到 Crypto / Identity Phase。

---

## `icc-test-support`

提供 deterministic / in-memory adapters：

```text
FakeClock
DeterministicRandom
InMemoryObjectStore
InMemorySecurityStateStore
FakeSecretStore
```

目的不是模擬 Production security。

而是：

```text
state-machine testing
failure injection foundation
repeatable test
platform independence
```

---

## `icc-platform-linux`

Phase 1 Linux adapter 只做真正目前需要的：

```text
LinuxClock
LinuxSecureRandom
```

目前不急著建立 Linux filesystem / database adapter。

遵循：

> Abstract from evidence, not imagination.

LinuxSecureRandom 第一版直接使用 Linux `/dev/urandom`。

這是 Platform Adapter 細節，Domain 不知道它存在。

後續可改成更適合的 Linux syscall/backend，而不改 Domain API。

---

## `indie-cli`

CLI 是 Composition Root。

可以：

```text
選 Linux adapter
建立 concrete dependency
呼叫 Core
輸出 diagnostics
```

不可以：

```text
成為 permission authority
偷偷建立 global identity
把 UI validation 當 security validation
```

Phase 1 commands：

```bash
indie-cli doctor
indie-cli demo
```

---

# 6. First Capability Semantics

Phase 1 `CapabilityGrant`：

```text
subject
resource
rights
generation
expires_at
delegable
```

Authorization：

```text
caller matches subject?
resource matches?
generation current?
not expired?
rights sufficient?
        ↓
ALLOW
```

任何一項失敗：

```text
DENY
```

這符合：

```text
Fail Closed
Naming != Authority
No Authority Amplification
Revocation Generation
```

---

# 7. Generation-Based Revocation Skeleton

Phase 1 使用最小：

```text
grant.generation == current_generation
```

來表示 revocation skeleton。

例如：

```text
Grant Generation = 7
Current Generation = 7
→ potentially valid
```

若 authority 將 generation 提升：

```text
Current Generation = 8
```

舊 grant：

```text
Generation 7
→ REVOKED
```

這不是最終 revocation architecture。

Phase 6 仍需比較：

```text
revocation tree
generation table
epoch
indirection
hybrid
```

---

# 8. Time Semantics Baseline

Phase 1 已開始區分：

```text
WallTimeMs
MonotonicMs
```

Capability expiry 使用：

```text
MonotonicMs
```

而不是 wall clock。

原因：

```text
使用者可以改系統日期
NTP 可以改 wall time
wall time 可能向後跳
```

真正跨 restart / snapshot 的 security freshness 留待 Security State 設計。

---

# 9. Secret Store Baseline

`SecretStore` 只暴露：

```text
generate_secret
 destroy_secret
```

而不是：

```text
export_private_key
```

Phase 1 尚未建立 signing / decrypt operation，因為 crypto algorithms 尚未選定。

這只是先確立：

> Secret 應以 handle 使用，而不是把 raw bytes 當正常 API。

---

# 10. Architecture Enforcement Script

`scripts/check_architecture.py` 目前檢查：

Domain Core 是否出現：

```text
std::fs
std::net
std::env
std::process
std::os
tokio::
rusqlite
reqwest
libc::
```

Port definitions 是否洩漏：

```text
std::fs
std::net
tokio::
std::os
```

並確認所有 `crates/core/*` library：

```text
#![no_std]
```

這不是完整 Rust AST linter。

它是 Phase 1 的第一道低成本 architecture guard。

未來再升級成更嚴格的 dependency graph / lint tooling。

---

# 11. CI Baseline

GitHub CI 的 checkout action 固定到 `actions/checkout` v7.0.1 的 commit SHA，而不是只使用可移動 tag。

GitHub CI 執行：

```text
architecture boundary check
cargo fmt
cargo clippy -D warnings
cargo test
portable no_std cargo check
```

CI 的目的不是「有綠勾」。

真正目的：

> 每次 commit 都重新驗證 Phase 0.3 的一部分架構假設。

---

# 12. Unsafe Policy

Phase 1 所有 crate：

```rust
#![forbid(unsafe_code)]
```

目前沒有任何理由需要 unsafe。

未來只有：

```text
kernel
FFI
memory mapping
hardware
small audited primitive
```

才可能提出 ADR 開放。

---

# 13. Dependency Policy

Phase 1 production graph：

```text
external runtime crates = 0
```

GitHub Actions 本身屬 CI infrastructure，不算 production binary dependency。

後續 dependencies 要遵守 Phase 0.3：

```text
purpose
maintenance
unsafe footprint
transitive graph
build.rs
proc macro
no_std support
replaceability
security history
license
```

---

# 14. Architecture Acceptance Cases

Phase 1 必須證明：

```text
A-01 icc-types = no_std
A-02 icc-error = no_std
A-03 icc-rights = no_std
A-04 icc-platform-api = no_std + alloc
A-05 icc-capability-core = no_std
A-06 icc-identity-core = no_std
A-07 identity-core accepts deterministic test random adapter
A-08 identity-core accepts Linux random adapter through same Port
A-09 capability authorization needs no Linux API
A-10 Linux-specific APIs only exist in platform/application edge
```

---

# 15. Security Acceptance Cases

目前測試至少覆蓋：

```text
right attenuation cannot add WRITE
valid READ grant allows READ
generation change revokes grant
expired grant denies
child lifetime cannot exceed parent lifetime
identity random source can be replaced in tests
```

後續 Phase 仍需要：

```text
fuzzing
handle guessing
ABA/stale handle
cross-process identity binding
persistent revocation
crash consistency
```

Phase 1 不宣稱已解決這些問題。

---

# 16. Local Validation Status

本次生成環境沒有安裝：

```text
rustc
cargo
```

且工作容器無法直接存取外網安裝 Rust。

因此本次已執行的驗證為：

```text
TOML syntax parsing
workspace path existence
architecture boundary static script
forbidden-token scan
project structure verification
```

沒有假稱已在本機完成：

```text
cargo check
cargo test
cargo clippy
```

真正 Rust compiler verification 已寫入 `.github/workflows/ci.yml`，並應在第一個有 Rust 1.98.1 的開發環境或 CI 上執行。

這個限制必須保留在工程記錄中，直到 compiler checks 真正通過。

---

# 17. Phase 1 Definition of Done

Phase 1 可以進入下一階段的條件：

```text
[done] workspace structure created
[done] toolchain pinned
[done] layer boundaries represented by crates
[done] no_std declarations established
[done] Port traits established
[done] deterministic test adapters established
[done] Linux Clock/Random adapter established
[done] capability pure semantics skeleton established
[done] identity injection skeleton established
[done] architecture guard script established
[done] CI workflow established
[pending external compiler] cargo fmt passes
[pending external compiler] cargo clippy passes
[pending external compiler] cargo test passes
[pending external compiler] no_std cargo checks pass
```

因此目前狀態應精確稱為：

```text
Phase 1 Engineering Baseline — Generated / Static-Validated
Compiler Verification — Pending
```

而不是假稱：

```text
Phase 1 Fully Compiler-Verified
```

---

# 18. Next Technical Phase

Phase 1 compiler checks 通過後，下一個核心階段是：

# Phase 2 — Cryptographic Foundation

但 Phase 2 不會立刻做 cryptocurrency。

先建立：

```text
Crypto Provider Boundary
Secure Random Requirements
Hashing
Digital Signatures
AEAD
KDF
Key Handles
Algorithm identifiers
Canonical cryptographic encoding
Test vectors
Key lifecycle
Zeroization policy
```

並正式選擇成熟 cryptographic primitives / libraries。

Phase 2 之前禁止開始：

```text
wallet
blockchain
messaging encryption
root identity key hierarchy
```

因為它們全部依賴 Crypto Foundation。

---

# 19. Phase 1 Engineering Principle

這個階段真正留下來的最重要成果不是 CLI。

而是：

```text
Linux is an implementation.
It is not the architecture.
```

如果未來：

```text
icc-platform-linux
```

被刪掉，換成：

```text
icc-platform-youros
```

我們希望：

```text
icc-types
icc-rights
icc-capability-core
icc-identity-core
```

仍然存在。

這就是 Phase 1 成功的真正標準。

---

**End of Phase 1 — Project Skeleton & Engineering Baseline v0.1**
