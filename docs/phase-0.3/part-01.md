# Independent Computing Core
## Phase 0.3 — Architecture Boundaries & Dependency Rules v0.1

**Status:** Architecture Baseline  
**Stage:** Phase 0.3  
**Parent Documents:**  
- Phase 0 — System Constitution v0.1  
- Phase 0.2 — Threat Model v0.1  

**Target:** Linux/VM Prototype → Minimal OS → Dedicated Hardware OS  
**Primary Language:** Rust  
**Date:** 2026-09-11

---

# 0. Purpose

本文件定義 Independent Computing Core 的「程式碼邊界憲法」。

Phase 0 定義我們相信什麼。

Phase 0.2 定義我們要防誰。

Phase 0.3 定義：

> **哪些程式碼可以知道哪些事情、哪些 crate 可以依賴哪些 crate、哪些層能接觸作業系統，以及哪些架構跨界行為一律禁止。**

這份文件的目的不是追求漂亮的資料夾結構。

目的是防止專案在 Linux Prototype 階段逐漸變成：

```text
"Portable Core"
      ↓
其實到處都是
std::fs
std::net
SystemTime
Unix socket
Linux path
Tokio type
SQLite type
```

如果發生這種事，未來移植自己的 OS 時，我們實際上仍然必須重寫核心。

因此 Phase 0.3 建立：

```text
Architecture Boundary
Dependency Direction
Platform Port
Effect Boundary
Unsafe Boundary
Protocol Boundary
Persistence Boundary
Runtime Boundary
```

並要求 CI 能自動檢查其中一部分規則。

---

# 1. Core Architecture Principle

整體依賴方向固定為：

```text
                 ┌─────────────────────┐
                 │  L6 UI / Apps / CLI │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ L5 Service Processes│
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │    L4 Runtime       │
                 └──────────┬──────────┘
                            │
             ┌──────────────┴──────────────┐
             ▼                             ▼
   ┌──────────────────┐          ┌──────────────────┐
   │ L3 Platform Ports │          │ L3 Wire Protocol │
   └─────────┬────────┘          └─────────┬────────┘
             │                             │
             └──────────────┬──────────────┘
                            ▼
                 ┌─────────────────────┐
                 │ L2 Domain Cores     │
                 └──────────┬──────────┘
                            ▼
                 ┌─────────────────────┐
                 │ L1 Core Types       │
                 └──────────┬──────────┘
                            ▼
                 ┌─────────────────────┐
                 │ L0 Pure Primitives  │
                 └─────────────────────┘

Platform implementation is attached from the side:

L4 Runtime
    │
    ▼
L3 Port Traits
    ▲
    │ implements
L4/L5 Linux Adapter
```

最重要的規則：

> **Dependency 只能朝內、朝下流。**

低層永遠不能知道高層實作。

---

# 2. Layer Definitions

---

## L0 — Pure Primitives

用途：

```text
IDs
small value objects
rights bitsets
version types
bounded numeric wrappers
canonical low-level types
pure algorithms
```

要求：

```text
#![no_std]
no alloc where practical
no OS
no filesystem
no network
no time
no random
no threads
no environment
no process
no IPC
no logging backend
```

允許：

```text
core
small no_std dependencies after review
```

例：

```text
icc-types
icc-rights
icc-version
```

---

## L1 — Core Types / Core Data Model

用途：

```text
Identity data model
Capability data model
Vault object model
Package domain types
Protocol-independent security state types
```

要求：

```text
#![no_std]
alloc allowed where required
```

允許：

```text
core
alloc
L0
reviewed no_std libraries
```

禁止：

```text
std::*
OS error types
PathBuf as authority model
SocketAddr as domain authority
SystemTime
thread IDs
Linux file descriptors
```

---

## L2 — Domain Cores

這是我們最重要的可移植邏輯。

預定：

```text
icc-identity-core
icc-capability-core
icc-vault-core
icc-keystore-core
icc-package-core
icc-update-core
icc-sync-core
```

其中每個 crate：

```text
domain rules
state machine
validation
authorization logic
pure transitions
cryptographic orchestration
```

但不直接執行外部 I/O。

基本要求：

```text
no_std + alloc compatible
```

若某模組確實需要 `std`：

必須建立 ADR 解釋原因。

不能因為：

```text
"方便"
```

而改成 std-only。

---

## L3 — Platform Ports

定義 Core / Runtime 需要的外部能力。

例：

```text
Clock
SecureRandom
ObjectStore
SecurityStateStore
SecretStore
Transport
IpcTransport
ProcessLauncher
MemoryRegionProvider
AuditSink
EntropySource
```

Port 是：

> **需求的介面。**

Adapter 是：

> **某平台提供需求的方式。**

例如：

```text
icc-platform-api::SecureRandom
               ▲
               │ implements
icc-platform-linux::LinuxSecureRandom
```

Core 只知道：

```text
SecureRandom
```

不能知道：

```text
getrandom()
```

---

## L3 — Wire Protocol

Wire protocol 與 Platform Port 同級，但責任不同。

它負責：

```text
versioned messages
explicit encoding
bounded decoding
canonical representation
compatibility rules
```

預定：

```text
icc-wire
icc-ipc-protocol
icc-sync-protocol
icc-package-format
```

它不能依賴：

```text
Linux socket
Tokio TcpStream
UnixStream
Android Binder
```

Protocol 是資料規格。

Transport 是平台實作。

---

## L4 — Runtime

Runtime 可以使用 `std`。

用途：

```text
service orchestration
session management
capability table
resource accounting
service lifecycle
request dispatch
runtime state
```

可能包括：

```text
icc-runtime
icc-capability-runtime
icc-service-runtime
```

Runtime 仍不得直接散落 OS calls。

OS-specific operation 必須經：

```text
Platform Port
```

---

## L4/L5 — Platform Adapters

實際接觸 OS。

例如：

```text
icc-platform-linux
icc-ipc-linux
icc-storage-linux
icc-process-linux
```

這一層可以使用：

```text
std::fs
std::os::unix
Linux syscalls
Unix domain sockets
mmap
getrandom
epoll/io_uring where justified
```

但 Linux-specific type 不能向 Core 洩漏。

---

## L5 — Service Processes

真正執行：

```text
identity-service
vault-service
capability-service
package-service
```

它們負責：

```text
process boundary
IPC endpoint
service startup
runtime composition
adapter injection
resource limits
```

Service binary 可以高度 platform-specific。

但 domain logic 必須留在 L2。

---

## L6 — UI / CLI / Applications

例：

```text
indie-cli
demo-app
future-settings-ui
future-store-ui
```

UI 可以快速替換。

它不是 architecture authority。

禁止把安全政策只寫在 UI。

例如：

```text
UI:
if allowed { ... }
```

不構成真正安全。

真正 authorization 必須在 authority-side 執行。

---

# 3. Proposed Workspace

Phase 1 初始 workspace 預定：

```text
indie/
│
├── Cargo.toml
├── rust-toolchain.toml
│
├── crates/
│   │
│   ├── core/
│   │   ├── icc-types/
│   │   ├── icc-rights/
│   │   ├── icc-identity-core/
│   │   ├── icc-capability-core/
│   │   ├── icc-vault-model/
│   │   └── icc-error/
│   │
│   ├── ports/
│   │   └── icc-platform-api/
│   │
│   ├── protocol/
│   │   ├── icc-wire/
│   │   └── icc-ipc-protocol/
│   │
│   ├── runtime/
│   │   ├── icc-runtime/
│   │   └── icc-capability-runtime/
│   │
│   └── platform/
│       └── linux/
│           ├── icc-platform-linux/
│           └── icc-ipc-linux/
│
├── services/
│   ├── identity-service/
│   ├── vault-service/
│   └── capability-service/
│
├── apps/
│   ├── indie-cli/
│   └── demo-app/
│
├── tests/
│   ├── architecture/
│   ├── security/
│   └── integration/
│
├── fuzz/
│
└── docs/
    ├── architecture/
    ├── threat-model/
    └── adr/
```

這只是 Phase 1 skeleton 的預定樣式。

實作時可以調整名稱，

但 layer 與依賴規則不可私自改變。

---

# 4. Dependency Direction Rule

正式規則：

```text
L6 → L5 → L4 → L3 → L2 → L1 → L0
```

允許跳過中間層向下依賴：

```text
L6 → L2
```

在合理情況下可以。

但禁止反向：

```text
L1 → L4
L2 → L5
L2 → Linux Adapter
L3 Protocol → Runtime
```

---

# 5. Dependency Matrix

`✓` = 可依賴  
`R` = 經 review 才允許  
`✗` = 禁止

| From \ To | L0 | L1 | L2 | L3 Ports | L3 Protocol | L4 Runtime | Platform | Services | Apps |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| L0 | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| L1 | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| L2 | ✓ | ✓ | ✓ | R | R | ✗ | ✗ | ✗ | ✗ |
| L3 Ports | ✓ | ✓ | R | ✓ | R | ✗ | ✗ | ✗ | ✗ |
| L3 Protocol | ✓ | ✓ | R | R | ✓ | ✗ | ✗ | ✗ | ✗ |
| L4 Runtime | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗* | ✗ | ✗ |
| Platform | ✓ | ✓ | R | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| Services | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| Apps | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | R | R | ✓ |

`*` Runtime 不能直接依賴具體 Platform crate；必須透過 Port，由 composition root 注入實作。

---

# 6. The Dependency Inversion Rule

禁止：

```rust
// identity-core
use icc_platform_linux::LinuxSecureRandom;
```

必須：

```text
identity-core
      │
      ▼
SecureRandom Port
      ▲
      │ implements
LinuxSecureRandom
```

概念：

```rust
pub trait SecureRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError>;
}
```

真正 Linux implementation：

```text
Linux Adapter
```

才知道如何呼叫 host entropy API。

---

# 7. `no_std` Policy

我們不採：

```text
"所有 crate 都必須 no_std"
```

也不採：

```text
"先用 std，以後再處理"
```

正式分級：

---

## NS-0 — Strict `core` Only

目標：

```text
icc-types
icc-rights
critical tiny primitives
```

理想上：

```rust
#![no_std]
```

且不需要 `alloc`。

---

## NS-1 — `no_std + alloc`

大部分 Domain Core：

```text
identity
capability
vault model
package state
protocol model
```

允許：

```rust
extern crate alloc;
```

可以使用：

```text
Vec
String
Box
Arc
```

若平台提供 allocator。

---

## NS-2 — Dual Mode

部分 library 可採：

```rust
#![cfg_attr(not(feature = "std"), no_std)]
```

CI 必須同時測：

```text
cargo check --no-default-features
cargo check --features std
```

但 `std` feature 不得改變核心安全 semantics。

---

## NS-3 — std Runtime

Runtime、Linux Adapter、CLI：

```text
std allowed
```

但仍需遵守 effect boundary。

---

# 8. Why We Do Not Force `no_std` Everywhere

`#![no_std]` 的真正作用是停止自動連結 Rust `std`，並使用 `core`；需要 heap allocation 時仍可顯式連結 `alloc`。

因此：

```text
no_std
```

不是：

```text
"沒有 heap"
```

也不是：

```text
"自動安全"
```

它對我們的主要價值是：

```text
避免 Core 不知不覺依賴 host OS runtime
提高 bare-metal / future OS portability
迫使外部能力顯式化
```

Reference:

https://doc.rust-lang.org/nightly/std/attribute.no_std.html

---

# 9. External Effect Rule

以下操作都視為 External Effect：

```text
Current time
Randomness
Filesystem
Persistent storage
Secret storage
Network
IPC
Process creation
Thread creation
Memory mapping
Device access
Environment variables
Logging output
System configuration
```

Domain Core 不得自行執行 External Effect。

它必須：

```text
receive input
compute decision
return command/result
```

或使用明確 Port。

---

# 10. Time Boundary

禁止 Domain Core：

```rust
SystemTime::now()
Instant::now()
```

改用：

```text
Clock Port
```

至少區分：

```text
WallClock
MonotonicClock
```

未來可能加入：

```text
TrustedFreshnessSource
SecurityEpoch
```

原因：

```text
wall clock may move backwards
user may change clock
network may lie about time
VM snapshot may restore time-related state
```

Expiry authorization 必須清楚說明依賴哪種 time semantics。

---

# 11. Randomness Boundary

禁止：

```text
Core randomly chooses entropy source.
```

所有 security-sensitive randomness 透過：

```text
SecureRandom Port
```

用途包括：

```text
keys
nonces
opaque identifiers
session secrets
randomized capability identifiers if used
```

測試時可注入：

```text
DeterministicRandom
```

Production 禁止使用 deterministic provider。

---

# 12. Storage Boundary

Domain Core 不直接：

```rust
std::fs::read
std::fs::write
File::open
```

而是使用 domain-oriented Port：

```text
ObjectStore
SecurityStateStore
SecretStore
```

不要建立一個過度抽象的：

```text
GenericFilesystem
```

讓整個 Core 又回到 path-based authority。

---

# 13. Separate Storage Domains

至少概念上分成：

```text
User Data Store
Security State Store
Secret Store
Temporary Runtime Store
```

原因：

Phase 0.2 已確定：

> Security State 與 User Data 不得共用相同 rollback / recovery semantics。

例如：

```text
Photo backup rollback
```

可能合法。

但：

```text
Revocation generation rollback
```

可能是安全漏洞。

---

# 14. Secret Store Boundary

`SecretStore` 必須使用：

```text
KeyHandle
SecretHandle
```

而不是一般情況返回：

```text
Vec<u8> private_key
```

應優先提供 operation：

```text
sign(handle, message)
decrypt(handle, ciphertext)
derive(handle, context)
destroy(handle)
```

而不是：

```text
export_private_key(handle)
```

需要 export 的特殊情境必須另設明確 protocol。

---

# 15. Network Boundary

Domain Core 不得知道：

```text
TcpStream
UdpSocket
UnixStream
HTTP client type
DNS resolver
Tokio socket
```

使用：

```text
Transport
PeerTransport
RepositoryTransport
RelayTransport
```

等高階介面。

網路 transport 不應自己決定：

```text
identity trust
authorization
capability grants
```

---

# 16. Protocol Is Not Transport

正式區分：

```text
Protocol
=
what bytes mean

Transport
=
how bytes move
```

例如：

```text
SyncMessage
```

不能知道自己經：

```text
QUIC
TCP
Bluetooth
USB
Local IPC
```

傳輸。

這能讓未來：

```text
Linux network
↓
OurOS network
```

不改 protocol。

---

# 17. IPC Boundary

Domain Core 不直接知道：

```text
Unix socket
pipe
Binder
Zircon channel
shared-memory implementation
```

而是：

```text
IPC Protocol
+
IPC Transport
```

Future OS 可以替換 Transport，

Protocol 與 domain semantics 保留。

---

# 18. Capability Transfer Boundary

