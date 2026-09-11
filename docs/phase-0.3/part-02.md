IPC 必須預留「message + capability」概念：

```text
IpcEnvelope
{
    message
    attached_capabilities
}
```

但 wire protocol 不得單純序列化 local opaque handle：

```text
handle = 0x4217
```

跨 security domain 後仍當有效 authority。

Local handle 的真正轉移必須由：

```text
Runtime / Kernel authority
```

重新建立 recipient-side handle。

---

# 19. Process Boundary

Domain Core 不呼叫：

```text
Command::new()
fork()
exec()
clone()
```

由：

```text
ProcessLauncher / Runtime
```

負責。

原因：

Process 建立本身就是安全事件：

```text
identity
capability inheritance
environment
open descriptor inheritance
resource limits
```

都必須被控制。

---

# 20. Thread / Async Boundary

Domain Core 優先保持：

```text
synchronous deterministic logic
```

不要讓：

```text
tokio::*
async_std::*
smol::*
```

等 runtime type 進入 Core API。

原因：

```text
executor is implementation detail
```

未來 OurOS 不應被今天選擇的 async runtime 綁架。

若 Domain 真正需要 concurrency abstraction，

應使用自己定義的最小語義介面。

---

# 21. Tokio Rule

Linux Prototype 未來可以使用 Tokio。

但 Tokio 只能存在於：

```text
Runtime
Linux Adapter
Service binary
```

禁止：

```text
icc-identity-core public API returns tokio type
icc-capability-core requires Tokio executor
icc-wire knows AsyncRead from Tokio
```

換 async runtime 不應迫使 domain model 重寫。

---

# 22. Filesystem Rule

只有 Platform / Service composition layer 可以直接接觸 physical path。

Core 可以使用：

```text
ObjectId
StoreKey
PackageId
BlobId
```

而不是：

```text
/home/user/file
```

Path 只是 backend implementation detail。

符合 Phase 0：

```text
Naming != Authority
Logical Data Model != Physical Storage
```

---

# 23. Environment Variable Rule

Core 禁止：

```rust
std::env::var(...)
```

Environment configuration 由 process composition layer 讀取，

解析成 validated configuration，

再注入 Runtime。

原因：

```text
environment is ambient authority/input
```

---

# 24. Configuration Rule

禁止各 crate 自行搜尋：

```text
config.toml
.env
HOME
XDG_CONFIG_HOME
registry
```

只有 composition root 決定 configuration source。

Core 接收：

```text
validated typed configuration
```

而不是自己找設定檔。

---

# 25. Logging Boundary

Core 可以產生：

```text
structured security event
diagnostic event
error code
```

但不能決定：

```text
write to stdout
syslog
journald
cloud telemetry
file
```

由：

```text
AuditSink
DiagnosticSink
```

處理。

Security Audit 與 Debug Logging 必須分離。

---

# 26. Error Boundary

Core error 不得直接暴露：

```text
std::io::Error
Errno
Linux error string
SQLite error
```

必須轉換：

```text
DomainError
PortError
```

例如：

```text
StoreError::Unavailable
StoreError::Corrupt
StoreError::PermissionDenied
StoreError::OutOfSpace
```

Platform-specific details 可以留在 diagnostic chain，

但不能成為 Core protocol contract。

---

# 27. Error Stability Rule

跨 component 的 error code：

```text
must be versioned and explicit
```

禁止把：

```text
Rust Display string
```

當作機器可解析 protocol。

---

# 28. Rust ABI Rule

Rust native ABI、struct memory layout、enum representation：

```text
NOT a protocol
NOT a persistent storage format
NOT a stable ABI
```

禁止：

```text
write raw Rust struct bytes to disk
send Rust struct memory over IPC
rely on usize width in persistent format
```

---

# 29. Wire Type Rules

任何 persisted / IPC / network type：

必須使用：

```text
fixed-width integers where required
defined byte order
explicit length limits
explicit version
explicit unknown-field policy
canonicalization rules if signatures depend on encoding
```

避免：

```text
usize
isize
platform pointer
raw enum discriminant
native endian
```

成為 wire contract。

---

# 30. Serialization Rule

禁止：

> 「把 domain struct derive Serialize 後直接當永久 protocol。」

Domain model 與 Wire model 分離：

```text
Domain Type
    │
explicit conversion
    ▼
Wire Type
    │
explicit codec
    ▼
Bytes
```

原因：

Domain struct 改欄位不應無意間：

```text
break protocol
break signature
break persistent data
```

---

# 31. Canonical Encoding Rule

任何需要被：

```text
signed
hashed as identity
content-addressed
```

的資料，

必須有唯一 canonical representation。

不允許兩種合法 encoding 代表同一 signed semantic object，

除非 signature scheme 明確定義 normalization。

---

# 32. Versioning Rule

所有跨 boundary data 都必須可演進。

需要：

```text
protocol version
message version
package format version
vault format version
security-state schema version
```

但避免建立一個全系統：

```text
global version = 17
```

導致所有元件一起更新。

不同 protocol 可獨立演進。

---

# 33. Unknown Field Rule

每個 protocol 必須明確定義：

```text
ignore
preserve
reject
```

未知欄位。

不能讓 parser 自己猜。

Security-sensitive field 若未知：

預設：

```text
reject / fail closed
```

除非 protocol 特別證明忽略安全。

---

# 34. Memory Allocation Rule

Core 可以使用 allocation，

但需避免無界 input 造成：

```text
Vec::with_capacity(attacker_length)
```

所有來自 untrusted input 的 allocation：

必須先做：

```text
length bound
resource quota
overflow check
```

`alloc` 可用不代表 allocation 無成本。

---

# 35. Resource Ownership Rule

資源型別優先採：

```text
owned handle
RAII lifetime
non-clone by default
explicit duplicate
```

不要讓 capability/resource handle：

```text
#[derive(Clone)]
```

只因為方便。

如果 duplicate 具有 authority 意義：

必須透過顯式 API：

```text
duplicate_with(rights)
```

---

# 36. Capability Type Rule

不同資源 capability 應盡量 typed。

不要所有東西都是：

```text
Capability(u64)
```

並在 runtime 到處比較 magic type number。

理想方向：

```text
ObjectCapability
IpcCapability
MemoryCapability
KeyOperationCapability
```

底層可能共享 common handle，

但 API 應減少 type confusion。

---

# 37. Authority-Side Validation Rule

禁止只在 client SDK：

```text
check permission
```

真正 authoritative service 必須再次驗證。

流程：

```text
Client validation
    optional convenience
         ↓
IPC
         ↓
Authority-side validation
    mandatory
         ↓
Operation
```

---

# 38. Composition Root Rule

只有少數位置可以決定：

```text
which adapter
which store
which clock
which runtime
which transport
which config
```

稱為：

```text
Composition Root
```

例如：

```text
identity-service/main.rs
```

可以建立：

```text
LinuxSecureRandom
LinuxSecurityStore
LinuxClock
IdentityCore
IdentityRuntime
```

Core 自己不能偷偷 instantiate concrete backend。

---

# 39. Dependency Injection Rule

我們不採用大型 runtime DI framework。

優先：

```text
constructor injection
generic parameter
trait object where justified
```

目的：

```text
explicit dependency
easy test replacement
low magic
low reflection/runtime machinery
```

---

# 40. Global State Rule

核心禁止可變 global singleton：

```text
static mut
global registry
global current user
global current capability set
```

除非極低階平台原因且經 ADR。

原因：

```text
hidden dependency
test contamination
authority confusion
concurrency risk
```

---

# 41. Singleton Service Rule

即使 runtime 中只有一個：

```text
CapabilityManager
```

也不能靠：

```text
global get_instance()
```

取得。

應經明確 reference / service endpoint。

---

# 42. Unsafe Rust Policy

本專案不是：

```text
unsafe = forbidden everywhere
```

因為 Future Kernel、FFI、memory mapping 等必然可能需要 unsafe。

但正式規則：

---

## U-001

L0 / L1 / L2 預設：

```rust
#![forbid(unsafe_code)]
```

除非該 crate 有專門 ADR。

---

## U-002

需要 unsafe 時，

必須集中在：

```text
platform
ffi
low-level memory
kernel
small audited wrapper
```

不能散落在 business/domain logic。

---

## U-003

每個 unsafe block 必須回答：

```text
What invariant makes this safe?
Who establishes it?
Who maintains it?
Can attacker-controlled input violate it?
```

並具有 `SAFETY:` 註解。

---

## U-004

禁止用 unsafe 只是為了：

```text
benchmark 比較快
```

除非 profiling 證明瓶頸，

並有 correctness tests。

---

## U-005

安全 wrapper 對上層暴露 safe API。

---

# 43. FFI Rule

未來若需要 C / kernel / hardware API：

FFI 只能存在於專門 crate：

```text
icc-platform-linux-sys
icc-hardware-xxx-sys
```

再由 safe adapter 包裝。

禁止 Domain Core 直接：

```text
extern "C"
```

---

# 44. Third-Party Dependency Policy

Dependency 不是免費程式碼。

每個 dependency 都增加：

```text
supply-chain risk
build complexity
attack surface
future portability risk
maintenance dependency
```

因此 Core 採：

> **Dependency-minimal, not dependency-zero.**

---

# 45. Dependency Classes

---

## Class D0 — Core-Critical

會進入：

```text
L0/L1/L2
security-critical parser
crypto
```

要求最高審查。

---

## Class D1 — Runtime-Critical

例如：

```text
serialization
async runtime
database client
IPC support
```

可接受，但需要 audit。

---

## Class D2 — Tooling

例如：

```text
test
benchmark
CLI dev tool
code generation
```

不進 production TCB。

---

# 46. Dependency Review Checklist

引入 production dependency 前回答：

```text
Why do we need it?
Can standard/core/alloc already do it?
Is it maintained?
What is its unsafe footprint?
Does it support no_std if Core needs it?
Does it pull large transitive dependencies?
Does it execute build.rs?
Does it use proc macros?
Does it perform network access at build time?
Does it expose platform types into public API?
Can we replace it later?
Is security history acceptable?
Is license compatible?
```

---

# 47. Build Script Rule

Security-critical Core 原則上避免複雜：

```text
build.rs
```

尤其禁止 build 時：

```text
download executable
download source without pinned verification
contact external network
execute arbitrary downloaded code
```

Build 必須能：

```text
offline
reproducibly where practical
```

---

# 48. Git Dependency Rule

Production release 禁止依賴 floating Git branch：

```toml
git = "..."
branch = "main"
```

如暫時需要 Git dependency：

必須 pin：

```text
exact revision
```

正式版本應優先使用可驗證 release artifact。

---

# 49. Feature Flag Rule

Cargo features 不得偷偷改變安全模型。

禁止：

```text
feature = "fast"
→ disables signature verification
```

如果存在 security-relevant feature，

必須：

```text
explicitly named
documented
not enabled silently
CI tested
```

---

# 50. Default Feature Rule

核心 dependency 引入時，

不要假設：

```text
default-features = true
```

永遠合理。

需確認 default feature 是否拉入：

```text
std
network
filesystem
runtime
large parser
```

等不必要能力。

---

# 51. Crypto Dependency Boundary

Cryptographic primitive 不自行實作。

Crypto crate 由專門 wrapper 封裝：

```text
icc-crypto-provider-api
          ▲
          │
icc-crypto-rust-provider
```

Domain 不應到處直接綁：

```text
specific Ed25519 crate type
specific AEAD crate type
```

Public domain type 使用自己的：

```text
PublicKeyId
SignatureBytes
KeyHandle
AlgorithmId
```

但也不能為「可抽換」建立錯誤的 lowest-common-denominator crypto API。

每個 algorithm 使用場景仍需明確。

---

# 52. Cryptographic Agility Rule

Crypto agility 不代表：

```text
algorithm = arbitrary string
```

安全 protocol 必須限制：

```text
supported algorithm set
allowed transitions
downgrade behavior
```

禁止 attacker negotiation 導致：

```text
downgrade
```

---

# 53. Database Boundary

如果 Linux Prototype 使用：

```text
SQLite
RocksDB
LMDB
```

它們只能位於 Storage Adapter。

禁止：

```text
Vault domain API returns SQL row
Identity core knows table name
Capability core writes SQL
```

未來換 storage engine 不影響 Domain。

---

# 54. Schema Migration Rule

Persistent schema migration 屬 security-sensitive operation。

必須：

```text
versioned
transactional where possible
crash-tested
rollback behavior defined
security-state migration reviewed
```

不能只靠 ORM 自動 migration 而無安全設計。

---

# 55. Test Adapter Rule

每個重要 Port 都應有 deterministic test implementation：

```text
FakeClock
DeterministicRandom
InMemoryObjectStore
InMemorySecurityStateStore
LoopbackTransport
FakeSecretStore
```

這些不是 production implementation。

它們的目的：

```text
reproducible state-machine test
failure injection
crash simulation
revocation test
rollback test
```

---

# 56. Failure Injection Rule

Port interface 應允許測：

```text
I/O unavailable
short write
corruption
out of space
clock change
random source failure
transport drop
timeout
service restart
```

如果 API 設計成永遠成功，

代表 Threat Model 沒有真正進入 architecture。

---

# 57. Panic Policy

Domain Core：

```text
untrusted input must not cause panic
```

預期錯誤使用：

```text
Result
validated types
explicit rejection
```

Panic 只代表：

```text
internal invariant violation / programmer bug
```

不能用 panic 作為正常 authorization flow。

---

# 58. Integer Rule

對 attacker-controlled：

```text
length
offset
count
version
size
```

必須使用：

```text
checked arithmetic
bounded conversion
```

禁止依賴 release build overflow 行為來維持安全。

---

# 59. String Rule

Security-sensitive identifier 優先 typed binary/value object。

不要把：

```text
"root"
"admin"
"read"
"camera"
```

等任意 string 當唯一 authorization ontology。

String 適合：

```text
display
human-readable labels
extension namespace with explicit validation
```

核心權限應使用明確 type / ID。

---

# 60. Public API Stability Levels

每個 public interface 標記：

---

## A0 — Internal

可以自由修改。

---

## A1 — Workspace Stable

workspace 內其他 crate 可依賴，

但不承諾外部相容。

---

## A2 — Platform Stable

Service / App SDK 開始依賴。

修改需要 migration。

---

## A3 — Protocol Stable

跨版本 / 跨裝置 / package format。

最難修改。

任何 A3 介面修改必須 ADR。

---

# 61. Internal Rust API Is Not Automatically Platform API

`pub` 只代表 Rust visibility。

不能因某個 function：

```rust
pub fn ...
```

就被視為正式 OS ABI。

Platform API 必須另外明確列入：

```text
docs/api/
```

並有 stability level。

---

# 62. Compatibility Layer Boundary

未來：

```text
Linux App
Android App
WASM App
```

若支援，

必須：

```text
Legacy Application
       │
       ▼
Compatibility Runtime
       │
       ▼
Capability Translation
       │
       ▼
Native Runtime
```

禁止 compatibility code 進入：

```text
identity-core
capability-core
vault-core
```

Compatibility 是邊緣層。

不是 Core。

---

# 63. WASI Position

WASI 的 capability-based sandbox 值得參考，

但 Phase 0.3 不決定：

```text
WASI = our app model
```

它可能成為：

```text
one application runtime backend
```

而不是：

```text
platform constitution
```

因此核心 API 不得依賴 WASI-specific type。

Reference:

https://wasi.dev/

---

# 64. Future Kernel Boundary

我們現在就預留 Future Kernel Port：

```text
Platform Interface
      │
      ├── Linux
