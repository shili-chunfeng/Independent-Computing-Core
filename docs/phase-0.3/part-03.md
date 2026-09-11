      └── OurOS
```

但不要建立空洞的：

```text
our_os/
    500 fake interfaces
```

只在 Linux Prototype 真正遇到 external effect 時，

才抽出必要 Port。

原則：

> **Abstract from evidence, not imagination.**

---

# 65. Avoid Premature Universal HAL

禁止現在試圖設計：

```text
Universal OS Interface
supporting every possible hardware forever
```

我們的策略：

```text
Build Linux implementation
       ↓
identify true dependency
       ↓
extract narrow semantic Port
       ↓
build test adapter
       ↓
later implement OurOS adapter
```

這比一開始模仿 POSIX API 更可靠。

---

# 66. Platform Port Design Rule

Port 應描述：

```text
what Core needs
```

而不是：

```text
what Linux happens to provide
```

錯誤：

```text
trait LinuxFileDescriptor {
    fn ioctl(...)
}
```

如果 Domain 真正需要的是：

```text
SecureObjectStore
```

就定義：

```text
SecureObjectStore
```

---

# 67. Narrow Port Rule

避免：

```text
trait Platform {
    fn read_file(...)
    fn socket(...)
    fn random(...)
    fn time(...)
    fn spawn(...)
    fn mmap(...)
    ...
}
```

這會形成 God Interface。

應拆：

```text
Clock
SecureRandom
ObjectStore
SecretStore
Transport
ProcessLauncher
```

讓每個 component 只取得自己需要的 capability/dependency。

---

# 68. Service Boundary Rule

是否拆成 Service，依 Phase 0 C-014：

只有在以下至少一項明確成立時：

```text
privilege separation
fault isolation
independent lifecycle
resource accounting
attack-surface containment
```

才值得支付 IPC 成本。

---

# 69. Initial Service Boundary Proposal

Prototype 初期建議：

```text
Identity / KeyStore
Capability Manager
Vault
Package/Update
```

逐步成為獨立安全 domain。

但第一版可以先以：

```text
same process + explicit interfaces
```

驗證 domain logic。

之後再移到 process boundary。

重要的是：

> Domain API 不能因第一版同 process 而假設共享記憶體是永久架構。

---

# 70. Shared Memory Rule

Future zero-copy 需要 shared memory。

但：

```text
shared memory != shared authority
```

Memory region 必須有：

```text
owner
mapping rights
lifetime
recipient
read/write/execute rights
```

共享 buffer 不能成為跨 App 任意溝通後門。

---

# 71. Zero-Copy Boundary

大型 payload 未來允許：

```text
IPC metadata
+
shared object handle
```

而不是：

```text
serialize entire video frame
```

但 control plane 仍需 authorization。

---

# 72. Executable Memory Rule

Future Runtime 原則上：

```text
W^X
```

即 memory 不應同時：

```text
Writable + Executable
```

除非 JIT 等特殊功能有獨立 security design。

Prototype 階段不一定自己 enforce，

但 API 不應假設 RWX 是正常需求。

---

# 73. File Descriptor Inheritance Rule

Linux Service 啟動 App 時，

必須避免 ambient descriptor inheritance。

只有明確授予的 descriptor/handle 可以被繼承或傳遞。

未來 capability kernel 同理。

---

# 74. Namespace Rule

知道 global service namespace 不能等於能呼叫 service。

例如：

```text
/service/vault
```

只是 naming。

真正 access 需要：

```text
IPC endpoint capability
```

---

# 75. Security-Sensitive Caching Rule

可以 cache：

```text
data
computed results
```

但 cache authorization decision 時需非常小心。

例如：

```text
capability valid = true
```

不能無限 cache，

否則 revocation 可能失效。

任何 security cache 必須有：

```text
generation
epoch
lifetime
invalidation semantics
```

---

# 76. Revocation Boundary

Capability revocation 的 authoritative state：

必須存在於：

```text
Capability Manager / Kernel equivalent
```

而不是每個 App 自行追蹤。

Client-side：

```text
"我覺得還有效"
```

沒有安全意義。

---

# 77. Security Epoch Concept

Phase 0.2 已提出 rollback 問題。

Phase 0.3 預留：

```text
SecurityEpoch
Generation
MonotonicSecurityState
```

型別空間，

但現在不決定 persistent implementation。

真正設計：

```text
Phase Capability / Storage / Future Kernel
```

---

# 78. User Data vs Security State API

禁止使用同一個泛型：

```text
save_blob()
```

讓 caller 隨便保存：

```text
photo
revocation root
signing trust
```

至少 API 層應區分：

```text
UserObjectStore
SecurityStateStore
```

即使 Linux Prototype 最後都落在同一顆 SSD。

---

# 79. Build Reproducibility Direction

Production architecture 應避免：

```text
build depends on current time
uncontrolled environment
network fetched artifact
random build identifiers
machine path leakage
```

目標是在後續 Package phase 逐步做到 reproducible build。

Phase 0.3 先確立：

```text
Core build should be deterministic where practical.
```

---

# 80. Architecture Enforcement in CI

Phase 1 開始後，CI 至少需要：

```text
cargo fmt --check
cargo clippy
cargo test
cargo check for no_std targets/core crates
dependency audit
license policy
forbidden dependency checks
```

後續逐步加入：

```text
cargo deny
cargo machete / unused dependency checks
cargo audit or equivalent advisory checking
Miri where useful
fuzzing
sanitizers where platform supports
```

工具名稱可以改，

但 enforcement 目標不能消失。

---

# 81. `std` Leakage CI Gate

所有 NS-0 / NS-1 crate 必須有 CI job：

```text
build/check without std
```

若某次 commit 因 dependency 更新導致：

```text
std required
```

CI 必須 fail。

不能等到幾年後移植 OS 才發現。

---

# 82. Platform Leakage Review

Code review 必須搜尋：

```text
std::fs
std::net
std::env
std::process
std::os
SystemTime
Instant
UnixStream
TcpStream
PathBuf
tokio::
libc::
```

在不應出現的 crate。

這可以逐步自動化。

---

# 83. Forbidden Dependency Examples

以下一律是架構錯誤：

```text
identity-core → icc-platform-linux

capability-core → tokio

vault-core → rusqlite

icc-wire → UnixStream

package-core → reqwest

identity-core → std::fs

capability-core → SystemTime::now()

vault-model → Linux file descriptor

sync-protocol → HTTP response type
```

---

# 84. Allowed Dependency Examples

可以：

```text
identity-core → icc-types

capability-core → icc-rights

runtime → icc-capability-core

runtime → icc-platform-api

icc-platform-linux → icc-platform-api

vault-service → icc-vault-core

vault-service → icc-platform-linux

indie-cli → service client SDK
```

---

# 85. Architecture Review Questions

每新增 crate / module 前回答：

```text
Which layer is this?

What authority does it hold?

What external effects does it need?

Which Port provides them?

Can it compile without Linux?

Does it need std?

Does it need alloc?

Does it introduce unsafe?

Does it introduce a parser?

Does it create persistent format?

Does it create wire format?

Does it add stable API?

Does it add new trusted code?

What happens if this component is compromised?
```

---

# 86. Crate Creation Rule

禁止：

```text
"功能很多，所以新增 crate"
```

crate boundary 應至少服務其中一個目標：

```text
security boundary
portability boundary
dependency isolation
API stability
compile-time separation
independent testing
```

避免產生數百個沒有實際意義的小 crate。

---

# 87. Module vs Crate vs Process

選擇規則：

```text
Code organization only
        ↓
      module

Dependency / portability / unsafe boundary
        ↓
       crate

Security / privilege / fault boundary
        ↓
      process/service
```

這條規則直接延續 Phase 0 的：

```text
Security boundary 才值得支付 IPC 成本
```

---

# 88. TCB Dependency Rule

任何進入 Trusted Computing Base 的 dependency：

需要比普通 utility 更嚴格審查。

尤其：

```text
unsafe code
parser
crypto
IPC
storage
update verification
boot/kernel
```

TCB 大小將作為效率與安全指標之一。

---

# 89. Testing Boundary

單元測試：

```text
Domain logic
```

不能只靠 Linux integration test。

我們需要：

```text
pure state-machine tests
property tests
failure injection
test adapters
```

這能證明：

> Core semantics 不依賴 Linux 恰好怎麼運作。

---

# 90. Property Testing Targets

優先 property：

```text
child rights never exceed parent rights
revoked capability cannot authorize future operation
invalid wire input never creates authority
decode(encode(x)) preserves canonical domain semantics
unknown security state never becomes Allow
cross-app handle cannot authorize
```

---

# 91. Cross-Layer Data Conversion

每個 boundary 應有顯式 conversion：

```text
Platform Error
      ↓
Port Error
      ↓
Domain Decision
```

或：

```text
Wire Message
      ↓ validate
Validated Request
      ↓ authorize
Domain Command
```

禁止：

```text
deserialize bytes
↓
directly mutate domain state
```

---

# 92. Validation Stages

Untrusted input 流程：

```text
Bytes
 ↓
Bounded Parse
 ↓
Structural Validation
 ↓
Semantic Validation
 ↓
Identity / Caller Binding
 ↓
Authorization
 ↓
State Transition
 ↓
External Effect
```

不能跳過其中安全相關步驟。

---

# 93. No Client-Controlled Authority Metadata

例如 client 送：

```text
{
    "caller": "admin",
    "rights": ["read", "write"]
}
```

Runtime 不能因為 JSON 說自己是 admin 就相信。

Caller identity 與已有 rights 必須由：

```text
execution domain / runtime / kernel
```

提供。

---

# 94. Naming Conventions

預定：

```text
*-core       portable domain logic
*-model      domain data types
*-protocol   wire semantics
*-api        stable port/interface
*-runtime    orchestration/stateful runtime
*-linux      Linux implementation
*-service    executable security service
*-client     client SDK
*-sys        raw FFI/platform binding
```

這不是美學。

名稱應幫助 code reviewer 看出：

```text
dependency 是否跨界
```

---

# 95. Feature Completeness vs Boundary Integrity

如果某功能為了完成 Demo 需要：

```text
Core imports Linux adapter directly
```

選擇：

```text
Demo 暫時不完成
```

而不是：

```text
破壞 boundary
```

Prototype 可以缺功能。

不能先欠 architecture debt 再假設未來會修。

---

# 96. Exceptions

任何違反 Phase 0.3 的例外：

必須 ADR。

至少記錄：

```text
why
scope
security impact
portability impact
removal plan if temporary
tests
owner
```

Temporary exception 必須有：

```text
expiry / review milestone
```

---

# 97. Architecture Decision: no Universal `Platform` Object

正式決定：

```text
D-ARCH-001
```

我們不建立一個包含所有 OS 能力的：

```rust
trait Platform { ... everything ... }
```

而使用 narrow ports。

理由：

```text
least authority
better testing
better portability
smaller interfaces
clearer dependencies
```

---

# 98. Architecture Decision: Domain / Wire Separation

```text
D-ARCH-002
```

Domain struct 不直接作為 persistent / IPC wire format。

理由：

```text
protocol stability
canonical encoding
validation boundary
security review
migration
```

---

# 99. Architecture Decision: Runtime Executor Is Replaceable

```text
D-ARCH-003
```

Async runtime 不進 Domain public API。

Linux Prototype 可選 Tokio 或其他 executor，

但不能成為 platform contract。

---

# 100. Architecture Decision: Core Uses `no_std` Selectively but Enforced

```text
D-ARCH-004
```

L0/L1/L2 應盡量支援：

```text
no_std
```

需要 heap 時使用：

```text
alloc
```

而不是強迫所有程式碼無 heap。

CI 驗證 portability。

---

# 101. Architecture Decision: OS Effects Enter Through Ports

```text
D-ARCH-005
```

Time、Random、Storage、Network、IPC、Process、Secret Storage 等：

全部視為 external dependency。

不得散落於 Domain Core。

---

# 102. Architecture Decision: Unsafe Concentration

```text
D-ARCH-006
```

unsafe code 優先集中在：

```text
platform / FFI / kernel / audited low-level wrapper
```

Domain Core 預設：

```rust
#![forbid(unsafe_code)]
```

---

# 103. Architecture Decision: Security State Is a Distinct Persistence Domain

```text
D-ARCH-007
```

User data 與 Security state 不使用相同語義的 persistence API。

這是對 Phase 0.2 rollback threat 的直接架構回應。

---

# 104. Architecture Decision: Security Authority Is Server-Side

```text
D-ARCH-008
```

Client SDK 可以做 UX validation，

但正式權限判斷一定由：

```text
authority-owning runtime/service/kernel
```

執行。

---

# 105. Architecture Decision: Local Handle Is Not Wire Authority

```text
D-ARCH-009
```

Local opaque handle：

```text
process/session scoped
```

不得直接 serialized 後在：

```text
network
persistent storage
other device
```

成為有效 authority。

---

# 106. Architecture Decision: Abstract From Real Dependencies

```text
D-ARCH-010
```

不預先發明龐大 HAL。

先建立 Linux Prototype，

每遇到真正 platform dependency：

```text
extract narrow semantic Port
```

再實作 Linux / Test / Future OurOS adapter。

---

# 107. Minimum Architecture Acceptance Test

Phase 1 workspace 建立後，必須能證明：

```text
1. icc-types compiles no_std

2. icc-capability-core compiles without Linux

3. icc-capability-core cannot import Linux adapter

4. FakeClock can replace production clock

5. DeterministicRandom can be injected in tests

6. LinuxSecureRandom can be injected in production

7. InMemoryObjectStore can run domain tests

8. Linux storage backend can be replaced without changing Vault domain API

9. Protocol crate contains no socket/runtime dependency

10. Linux IPC implementation can be replaced without changing IPC message semantics
```

---

# 108. Initial Port Set for Phase 1

不要現在一次做完所有 Port。

第一批只建立真正馬上需要的：

```text
Clock
SecureRandom
SecurityStateStore
ObjectStore
SecretStore
```

IPC/Network Port：

等 Phase 6/7 真正開始 runtime/service separation 時加入。

避免 speculative architecture。

---

# 109. Initial Phase 1 Crates

最小第一批建議：

```text
icc-types
icc-rights
icc-error
icc-platform-api
icc-capability-core
icc-identity-core
icc-test-support
icc-platform-linux
indie-cli
```

Vault / Package / IPC 暫不一次建立空 crate。

每個 crate 在真正需要時加入。

---

# 110. First Rust Coding Order

Phase 1 實際順序：

```text
01 Cargo workspace
02 lint / format / CI baseline
03 icc-types
04 icc-error
05 icc-rights
06 icc-platform-api
07 test adapters
08 Linux Clock / Random adapter
09 capability domain skeleton
10 identity domain skeleton
11 CLI composition root
```

先證明：

```text
portable dependency direction works
```

再增加功能。

---

# 111. Reference Notes

## Rust `no_std`

Rust 官方文件說明：

`#![no_std]` 會停止自動連結 `std`，改以 `core` 為基礎；若需要 heap-backed collections，可另外顯式使用 `alloc`。

Reference:

https://doc.rust-lang.org/nightly/std/attribute.no_std.html

---

## Rust Conditional Compilation

Rust 官方支援 `cfg` / `cfg_attr` 做 conditional compilation，可用來維持 dual-mode crate，例如在非 `std` feature 下套用 `no_std`。

Reference:

https://doc.rust-lang.org/reference/conditional-compilation.html

---

## Embedded / Bare-Metal Rust

Rust Embedded Book 展示 bare-metal Rust 使用 `#![no_std]`、自訂 entry point / panic handling，證明核心 Rust 程式可脫離一般 host `std` runtime。

Reference:

https://doc.rust-lang.org/embedded-book/

---

## WASI

WASI 的 capability-based sandbox 與 no ambient authority 概念可作為未來 application runtime 的參考，但本專案不綁定 WASI。

Reference:

https://wasi.dev/

---

## Fuchsia / Zircon

