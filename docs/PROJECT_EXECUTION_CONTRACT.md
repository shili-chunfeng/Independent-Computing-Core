# Independent Computing Core — Project Execution Contract & Master Roadmap

**Status:** Proposed Project-Level Development Contract  
**Scope:** Entire Independent Computing Core program  
**Authority:** Execution/orchestration contract subordinate to the System Constitution, Threat Model, Architecture Boundaries, and accepted ADRs  
**Target:** Linux/VM Prototype → Portable Independent Computing Core → Minimal OS → Dedicated Hardware OS → Stable Personal Computing Platform  
**Initial adoption baseline:** `main` after Phase 2 Cryptographic Hardening  

---

# 0. Why This Document Exists

本文件不是單純的產品願景，也不是「最後想做一個 OS」的摘要。

它是 Independent Computing Core（ICC）專案的：

```text
Product Definition
+ Master Roadmap
+ Development State Machine
+ AI Execution Contract
+ Phase Ordering Rules
+ Merge Governance Contract
```

目的只有一個：

> **任何新的 AI / engineer，只要讀取本文件、repository 的正式文件與目前 `main` 原始碼，就必須能判斷目前做到哪裡、下一個 mandatory milestone 是什麼、應該修改哪些層、哪些工作禁止提前做、要取得哪些證據，並在 PR ready for review 時停止。**

正常開發不得依賴舊聊天內容、人的記憶、未 merge branch、下載過的 ZIP 或本機暫存副本來決定下一步。

Owner 原則上只需要在以下時機介入：

1. 審查 Pull Request；
2. 要求修改或拒絕 proposed ADR；
3. 手動 merge；
4. 遇到本文件明確列為 **Owner Decision Gate** 的不可逆、法律、治理或實體硬體決策。

AI 不得自行 merge。

---

# 1. Authority and Precedence

若文件之間有衝突，優先順序如下：

```text
1. Phase 0 — System Constitution
2. Phase 0.2 — Threat Model
3. Phase 0.3 — Architecture Boundaries & Dependency Rules
4. Accepted ADRs merged into main
5. This Project Execution Contract
6. Current Phase specification / hardening report
7. README / implementation notes
8. Source code implementation details
```

本文件可以決定：

```text
what comes next
what a phase must deliver
how AI works
when a phase is complete
when to stop for review
```

但本文件不能繞過：

```text
Constitutional security rules
Threat-model invariants
Architecture dependency rules
Accepted ADRs
```

若未來需要改變上述高優先級決策，必須建立 ADR / constitution amendment proposal，放入 feature branch，由 owner 在 PR merge 前審查。

---

# 2. Source of Truth

GitHub repository 的 **merged `main`** 是唯一正式 implementation state。

以下都不是正式狀態：

```text
local checkout
local ZIP
chat attachment
assistant memory
unmerged branch
unmerged PR
failed CI artifact
old completion report outside main
```

每次工作開始前，AI 必須重新取得：

```text
default branch
main HEAD
repository tree
open PRs
relevant branches
latest Actions status
```

不得假設上次看到的 SHA 仍然有效。

---

# 3. Definition of the Final Product

ICC 最終不是單一 library，也不是 Linux 上的 security toolkit。

最終產品是一套 **user-sovereign personal computing platform**，其核心能力可以先在 Linux/VM 驗證，再遷移到自主 OS 與特定硬體，而不重寫核心安全模型。

最終系統概念：

```text
┌──────────────────────────────────────────────┐
│                User Experience               │
│ Settings / Apps / Communication / Wallet    │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│           Native Application Runtime         │
│ App identity / sandbox / capability set     │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│          Independent Computing Core          │
│                                              │
│ Identity      Capability      Vault          │
│ KeyStore      Crypto          Package Trust  │
│ Sync          Messaging       Wallet         │
│ Audit         Runtime         Update Trust   │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│             Portable Platform Ports          │
└──────────────────────┬───────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
┌──────────────────┐      ┌────────────────────┐
│ Linux Adapter     │      │ OurOS Adapter      │
│ Prototype         │      │ Final platform     │
└──────────────────┘      └──────────┬─────────┘
                                     │
                                     ▼
                          ┌────────────────────┐
                          │   Minimal / OurOS  │
                          │ Kernel + services  │
                          └──────────┬─────────┘
                                     │
                                     ▼
                          ┌────────────────────┐
                          │ Dedicated Hardware │
                          └────────────────────┘
```

最終平台必須能支撐：

- User-controlled Identity
- Device identity and device authorization
- App-specific pseudonymous identities
- Secure Key Storage
- Personal Vault / logical object storage
- Capability-based resource authorization
- Explicit IPC and capability transfer
- Application isolation / sandboxing
- Package signing, update verification and software trust
- Local-first encrypted sync
- End-to-end secure communication
- Wallet / financial protocol integration
- Software repository / app distribution
- Local audit and transparent permission state
- Optional compatibility environments above the native security model
- Offline-first normal operation
- Replaceable network/cloud infrastructure
- Migration from Linux adapter to OurOS adapter without rewriting Domain Core

---

# 4. What ICC Is Not

ICC 不以以下項目為終局：

```text
an Android ROM
an Android privacy skin
a Linux distribution
an Apple clone
an app-store-only project
a blockchain-first project
a cloud SaaS
a wallet-only product
a browser-only platform
```

不得為了快速展示而把產品方向縮成其中任何一項。

同樣，不應在基礎安全架構尚未完成時優先開發：

```text
pretty GUI
social feed
recommendation engine
advertising system
NFT features
mainnet tokenomics
AI assistant
custom browser
office suite
```

---

# 5. Final User-Control Model

最終平台的基礎 ownership 必須保持：

```text
User
├── Identity
├── Keys
├── Data
├── Devices
└── Capabilities
     │
     └── selectively granted to Apps / Services
```

App 不因為：

```text
installed
running
first-party
signed by official repository
```

就自然取得資源。

最終使用者必須能回答：

```text
Who is acting?
On which resource?
With which rights?
Why?
For how long?
Who granted it?
How can it be revoked?
```

---

# 6. Required End-to-End Product Flows

第一代完整平台至少必須能真正完成以下 end-to-end flows。

## 6.1 Device Ownership Flow

```text
Boot device
→ establish local owner
→ initialize identity root/recovery state
→ initialize KeyStore
→ enroll current device
→ enter normal offline-capable state
```

不得要求 cloud account 才能完成基本初始化。

## 6.2 App Installation Flow

```text
Acquire package
→ verify package integrity/signature/provenance
→ display requested capabilities
→ install into isolated execution domain
→ create app-specific identity/namespace
→ initial capability set = minimal/none
→ launch
```

## 6.3 Personal Data Flow

```text
User stores object in Vault
→ App knows object reference
→ App has no capability
→ DENIED
→ User grants scoped capability
→ ALLOWED
→ User revokes
→ DENIED
```

## 6.4 Secret Operation Flow

```text
App/service requests SIGN / DECRYPT / DERIVE
→ caller identity validated
→ operation capability validated
→ KeyStore uses non-exported key material
→ only result is returned
```

Raw private key bytes must not be the normal application API.

## 6.5 Capability Delegation Flow

```text
App A has READ(Object X)
→ policy permits delegation
→ App A delegates narrower temporary READ(Object X) to App B
→ App B cannot expand to WRITE
→ parent revoke/expiry propagates according to defined semantics
```

## 6.6 Sync Flow

```text
local change
→ authenticated encrypted sync state
→ untrusted relay / replaceable transport
→ peer device validation
→ replay/order/conflict handling
→ local state convergence
```

Loss of relay availability must not destroy local usability.

## 6.7 Messaging Flow

```text
select peer identity
→ establish authenticated secure session/group
→ send encrypted message through untrusted transport
→ receive/verify
→ store locally under user policy
```

Content encryption must not be misrepresented as complete metadata anonymity.

## 6.8 Wallet Flow

```text
wallet intent
→ validate transaction object
→ obtain explicit signing authority
→ KeyStore signs
→ network adapter broadcasts
→ local audit records intent/result
```

Wallet must not require exporting private keys to application code.

## 6.9 Update Flow

```text
obtain update metadata/package
→ verify signer/trust state/version/freshness/integrity
→ compare capability changes
→ require policy/user action where necessary
→ transactional migration
→ preserve rollback/security-state invariants
```

## 6.10 Recovery Flow

```text
loss/failure event
→ authenticate recovery authority
→ rotate/re-authorize as defined
→ invalidate obsolete sessions/devices where required
→ recover availability without silently bypassing trust
```

---

# 7. Mandatory Development Tracks

專案有兩條 mandatory tracks，最後必須匯流。

## Track A — Independent Computing Core

建立可移植的：

```text
Crypto
Identity
KeyStore
Vault
Capability Authority
IPC / Runtime
Package Trust
App Runtime
Sync
Messaging
Wallet
Repository
Compatibility
```

## Track B — Minimal OS / OurOS Lab

建立：

```text
Boot
Serial diagnostics
Memory management
Allocator
Task/scheduler model
Kernel objects / handles
IPC primitives
Address spaces / user processes
Capability transfer
Driver / storage foundations
Service lifecycle
Boot/update trust
ICC platform adapter
Dedicated hardware port
```

Track B 不能等 Track A 全部完成才開始。

原因：如果 Core 在 Linux 上發展太久而沒有第二平台驗證，Linux-specific assumptions 會逐漸滲入設計。

因此，本文件定義一個 interleaved execution queue。

---

# 8. Deterministic Next-Work Algorithm

任何 AI 開始新工作時，不得問 owner：「接下來要做什麼？」除非遇到 Owner Decision Gate。

必須依以下演算法自行判斷。

## Step 1 — Re-read GitHub

取得：

```text
default branch
main HEAD
repository tree
open PRs
relevant branches
Actions status
```

## Step 2 — Read mandatory documents

至少讀：

```text
README.md
SECURITY.md
Phase 0 Constitution
Phase 0.2 Threat Model
Phase 0.3 Architecture Boundaries
this PROJECT_EXECUTION_CONTRACT.md
all accepted ADRs
current/previous Phase specification and completion evidence
CI workflow
architecture checker
workspace manifests
relevant source code
```

## Step 3 — Open PR rule

若存在針對 `main` 的 open PR，且該 PR 對應目前最早未完成 mandatory milestone：

```text
DO NOT start the next milestone.
```

應先審查 / 修復 / 完成該 PR。

只有該 PR 被 owner 手動 merge 後，後續 milestone 才能從新的 `main` 開始。

## Step 4 — Find the first unfinished mandatory milestone

從 §9 的 Ordered Execution Queue 自上而下檢查。

某 milestone 只有在以下全部成立時才算 **Merged Complete**：

```text
required implementation exists in main
required docs/evidence exist in main
required tests exist in main
latest relevant merge had green required CI
no completion blocker is explicitly recorded
```

Branch green 但未 merge：

```text
NOT COMPLETE
```

PR green 但未 merge：

```text
READY FOR OWNER REVIEW
NOT COMPLETE
```

第一個不滿足 Merged Complete 的 mandatory milestone，就是下一個工作。

## Step 5 — Build the milestone, not later features

AI 只做該 milestone 與其必要 prerequisite hardening。

禁止「順便」做後面的 feature。

## Step 6 — Autonomous verification loop

AI 必須自行：

```text
implement
→ commit
→ push
→ read actual Actions logs
→ fix
→ commit
→ push
→ repeat
```

直到 required CI 成功，或確認為 Owner Decision Gate / external blocker。

## Step 7 — PR and stop

建立 PR、取得最新 PR HEAD CI 成功後：

```text
STOP IMPLEMENTATION
STATE = READY FOR OWNER REVIEW
```

不得 merge。

---

# 9. Ordered Execution Queue

這是單一 AI / sequential development 的預設 mandatory 順序。

Multi-agent development 可以平行準備獨立工作，但 merge 順序仍需遵守 dependency gates。

目前 adoption baseline 已完成：

```text
Phase 0   System Constitution
Phase 0.2 Threat Model
Phase 0.3 Architecture Boundaries
Phase 1   Engineering Baseline
Phase 2   Cryptographic Foundation + Hardening
```

接下來依序：

```text
Phase 3   Identity Core
Phase 4   KeyStore & Secret Operations
Phase 5   Personal Vault & Object Storage
Phase 6   Capability Authority & Revocation
OS-0      Minimal OS Boot / Serial / Build Baseline
Phase 7   Service Runtime & Explicit IPC
OS-1      Memory / Allocator / Task-Time Foundations
OS-2      Kernel Object / Handle / IPC Primitive Model
Phase 8   Package, Update & Software Trust
Phase 9   Application Model, Runtime & Sandbox
OS-3      User Processes / Address Spaces / Capability Transfer
Phase 10  Local-First Sync
Phase 11  Secure Messaging
Phase 12  Wallet & Financial Protocol
Phase 13  Software Repository & App Distribution
OS-4      Storage / Driver / Service Foundations + ICC Port
Phase 14  Compatibility Environments
Phase 15  Full VM System Integration
Phase 16  Dedicated Hardware Selection & Bring-up
Phase 17  Developer Preview Hardening
Phase 18  Stable 1.0 Platform / API / Security Review
```

Optional Ledger / Currency work is **not** in the mandatory queue. See §28.

---

# 10. Phase 3 — Identity Core

## Goal

建立不依賴 global public user ID 的 portable identity domain。

## Build

至少包含：

```text
Root / Recovery Identity domain model
Device Identity
App-specific pseudonymous Identity
Communication / Financial identity separation hooks
identity identifiers and typed references
device enrollment state machine
identity/key reference binding
rotation state
revocation state
recovery authority model
cross-app correlation resistance semantics
serialization/wire separation where persistence is introduced
```

Root Identity 必須是 trust/recovery anchor，不是 App login ID。

## Required architecture

- Domain Core remains portable / `no_std + alloc` where required.
- Private key bytes do not become identity-domain public API.
- Identity refers to KeyStore/crypto through typed references/ports, not Linux implementation.
- App-specific identity derivation/disclosure must not silently expose a global stable identifier.

## Do Not Build

```text
Vault
full KeyStore persistence
Messaging protocol
Wallet
cloud account system
App Store
```

只有為 Identity tests 所需的 fake/in-memory crypto/key references 可以存在。

## Security evidence

至少覆蓋 Phase 0.2：

```text
T-ID-001 Root Identity Exposure
T-ID-002 Cross-App Identity Correlation
T-ID-003 Unauthorized Device Enrollment
T-ID-004 Recovery Channel Takeover
INV-013 Root Identity is not public identity
```

## Exit Gate

必須有：

```text
identity specification
state-machine tests
negative enrollment/revocation tests
rotation/recovery-state tests
no global identifier exposure in normal App API
portable target check
architecture CI
completion report
PR latest HEAD CI green
```

---

# 11. Phase 4 — KeyStore & Secret Operations

## Goal

建立 application 不取得 raw private key 的正式 secret-operation boundary。

## Build

```text
KeyHandle / SecretHandle model
key generation lifecycle
sign operation
decrypt operation where required
derive operation where required
key destruction
key rotation hooks
algorithm/type binding
software KeyStore reference backend
SecretStore Port
crash/error semantics
zeroization ownership rules
security-state persistence
```

若 password-derived protection 確實需要，在此 Phase 才評估/實作既有 `Argon2idV13` identifier 所對應的正式 KDF policy。

## Required property

正常流程必須是：

```text
caller
→ authorized operation request
→ KeyStore
→ operation result
```

不是：

```text
caller
← private key bytes
```

## Future backend compatibility

API 必須允許未來替換：

```text
Software KeyStore
TPM
Secure Element
Custom hardware-backed implementation
```

而不重寫上層 Domain APIs。

## Exit Gate

包含 secret-material negative tests、restart/crash tests、raw-export boundary tests、portable API checks 與實際 CI 證據。

---

# 12. Phase 5 — Personal Vault & Object Storage

## Goal

建立 user-owned logical object model，而不是 App-owned filesystem model。

## Build

```text
ObjectId
owner
object type
metadata
content reference
policy/integrity fields
logical ObjectStore interface
UserObjectStore
SecurityStateStore separation
atomic write/commit model
corruption detection
crash recovery
schema/versioning
metadata-access policy
```

可使用 Linux storage backend 作 prototype，但 Domain API 不得暴露 Linux path / SQLite row 等 backend details。

## Required tests

```text
unauthorized read/write
object-ID enumeration not equal authority
corrupted data/metadata
partial write
crash during commit
rollback scenarios
wrong owner/context
```

## Do Not Build

不要在此 Phase 建完整 capability delegation system；可以使用 narrow authorization boundary/fakes，正式 authority 在 Phase 6。

---

# 13. Phase 6 — Capability Authority & Revocation

## Goal

把 Phase 0 最重要的 capability security model 做成 authoritative runtime semantics。

## Build

```text
opaque local handles
typed capability/resource classes
caller binding
rights
scope
expiry
attenuation
delegation policy
revocation generation/tree semantics
parent-child revocation behavior
handle lifetime
ABA/stale-handle defense
security-state persistence
restart semantics
TOCTOU strategy
resource accounting hooks
```

## Mandatory acceptance flow

至少能完整執行：

```text
Create user / object / App A / App B
App A no capability → DENIED
App A guesses object ID → DENIED
random/stale handle → DENIED
grant READ(X) → ALLOWED
attempt WRITE(X) → DENIED
attenuated temporary delegation → only permitted scope
attempt authority expansion → DENIED
revoke parent
App A → DENIED
App B derived authority follows defined revocation semantics
restart runtime
revoked authority remains DENIED
```

## Threat coverage

T-CAP-001 through T-CAP-008 and Gate S2 become mandatory evidence.

---

# 14. OS-0 — Minimal OS Boot / Serial / Build Baseline

This milestone starts Track B.

## Goal

證明專案不會永遠依賴 Linux host assumptions。

## Build

```text
reproducible OS build target
bootable VM image
minimal boot path
serial console / deterministic diagnostic output
panic/fault reporting
architecture documentation
CI build of image
QEMU or equivalent automated smoke boot
```

選擇第一個 architecture（例如 x86_64 或 another target）必須以 tooling/debuggability/portability evidence 建 ADR。

## Do Not Build

```text
GUI
full drivers
network stack
filesystem ecosystem
Android compatibility
```

---

# 15. Phase 7 — Service Runtime & Explicit IPC

## Goal

把重要 security domain 從 library-only composition 推進到可隔離 service boundary。

## Build

```text
versioned IPC protocol
bounded parser
caller identity binding
service endpoint authority
request/response errors
service lifecycle
restart semantics
queue/resource limits
Linux IPC transport adapter
capability attachment/transfer model
composition root
```

Protocol 與 transport 必須分離。

Local opaque handle 不能直接序列化成跨 domain/network authority。

## Service split rule

只有以下原因可支持 process boundary：

```text
privilege separation
fault isolation
independent lifecycle
resource accounting
attack-surface containment
```

## Exit Gate

包括 malformed IPC/fuzz targets、service restart、queue exhaustion、caller spoofing、unauthorized endpoint tests。

---

# 16. OS-1 — Memory / Allocator / Task-Time Foundations

## Build

```text
physical/virtual memory foundations
allocator
basic address-space plan
task abstraction
scheduler prototype
monotonic time/timer source
interrupt/fault foundations
resource ownership documentation
```

此 milestone 不需要完整 user processes，但 API 不得阻礙後續 isolation。

---

# 17. OS-2 — Kernel Objects / Handles / IPC Primitive Model

## Goal

建立未來 OurOS capability/runtime 能依賴的最小 kernel authority primitives。

## Build

```text
kernel object identity
process-local handle table
rights model
handle duplication with attenuation
channel/IPC primitive
object lifetime
wait/signal semantics where needed
resource accounting hooks
```

此處需要專門 Threat Model delta，因 kernel 開始成為真正 TCB。

不得直接複製 seL4/Fuchsia ABI；可以比較其設計後建立自己的 ADR。

---

# 18. Phase 8 — Package, Update & Software Trust

## Goal

讓 repository/distribution 不等於 trust root。

## Build

```text
versioned package format
manifest
application/developer identity binding
signatures
integrity verification
capability declaration
dependency declaration
source/build provenance fields
update metadata
signer rotation/revocation
rollback defense
freeze/freshness policy
transactional update/migration hooks
permission-delta detection
```

## Required threat coverage

```text
T-PKG-001 through T-PKG-007
```

TLS + single signing key 不得成為唯一 trust model。

任何 TUF/SLSA-like idea 只能作研究參考，實際採用的角色/metadata 必須由本專案 ADR 定義。

---

# 19. Phase 9 — Application Model, Runtime & Sandbox

## Goal

建立 native application execution model。

## Build

```text
AppId / package identity
execution domain
App-specific identity
storage namespace
initial capability set
capability injection
process/runtime launch
CPU/memory/handle/IPC/storage quota hooks
crash isolation
explicit network/device access
lifecycle
```

## Runtime choice gate

Native / WASM / WASI / hybrid 等選擇在此 Phase 必須根據：

```text
security model
startup cost
memory cost
IPC model
capability integration
portability
future OurOS fit
debuggability
compatibility needs
```

建立 ADR。

AI 可以提出並實作一個 preferred design 在 PR 中，不需要開發中途等待 owner；owner 在 merge review 時可以拒絕該 ADR。

---

# 20. OS-3 — User Processes / Address Spaces / Capability Transfer

## Build

```text
user-mode process/domain
separate address spaces
controlled mapping rights
syscall/service boundary
kernel-backed caller identity
IPC endpoint handles
capability/handle transfer
process termination cleanup
resource accounting baseline
```

## Convergence test

至少一個 ICC portable component 必須能針對 OurOS target 編譯或執行 smoke integration，證明 Platform Port 的方向真的成立。

---

# 21. Phase 10 — Local-First Sync

## Goal

跨裝置同步不得讓 cloud provider 成為 identity owner 或 plaintext authority。

## Build

```text
device-authenticated sync
versioned sync protocol
object/state identifiers
encrypted transport/content policy
replay protection
reordering handling
duplicate handling
conflict model
sync journal
resume/retry
offline queue
replaceable relay/provider
cross-device authorization
revocation interaction
```

## Privacy requirement

Content privacy、metadata privacy、relationship privacy 必須分開描述，不得以 E2EE 宣稱所有 metadata 都受到保護。

---

# 22. Phase 11 — Secure Messaging

## Goal

在既有 identity/keystore/sync/network boundaries 上建立通訊能力。

## Cryptographic protocol rule

不得自行發明新的訊息加密 primitive 或未經充分研究的新 secure-messaging protocol。

Phase 開始時必須比較既有標準/成熟 protocol families，記錄：

```text
identity binding
forward secrecy
post-compromise security
group semantics
multi-device behavior
metadata implications
key backup/recovery interactions
licensing/implementation maturity
```

以 ADR 選擇使用/組合方式。

## Build

```text
peer/contact identity binding
session/group state
message envelope
local message store
untrusted relay adapter
offline send/receive
replay/order handling
device changes
revocation behavior
```

---

# 23. Phase 12 — Wallet & Financial Protocol

## Goal

讓 financial operations 使用 KeyStore/capability model，而不是在 wallet UI 持有 raw keys。

## Build

```text
wallet identity/account model
transaction intent model
network/protocol adapter boundary
address/account derivation policy
signing authorization
KeyStore signing integration
broadcast abstraction
transaction status
local audit
backup/recovery interaction
hardware-backed migration path
```

第一個 reference network/protocol 的選擇需 ADR，但 wallet architecture 不應因此被單一鏈永久綁死。

不得在此 Phase 自動建立自有 token/mainnet。

---

# 24. Phase 13 — Software Repository & App Distribution

## Goal

建立 discovery/distribution infrastructure，但 repository 本身不是 ultimate trust authority。

## Build

```text
package index
metadata serving
mirror/cache model
search/discovery API
signed package publication
publisher verification information
build/provenance display
capability declaration display
update distribution
revocation information
sideload-equivalent runtime security
repository replacement/mirroring
```

官方與 sideloaded App 在 native runtime security model 上不得有隱藏特權差異。

---

# 25. OS-4 — Storage / Driver / Service Foundations + ICC Port

## Build

```text
minimal persistent storage path
block/storage abstraction required by ICC
basic driver isolation direction
service manager/lifecycle
secure random source
clock implementation
ICC Platform Port implementations
boot-time service composition
```

## Required convergence

至少將：

```text
crypto portable crates
identity core
capability core
selected runtime/service path
```

的一部分從 Linux adapter 切換到 OurOS adapter，並證明 Domain Core 不需要重寫。

如果必須大量重寫 Domain Core，視為 architecture portability failure，需回頭建立 ADR/修復，而不是接受 forked core。

---

# 26. Phase 14 — Compatibility Environments

Compatibility 永遠位於 Native Security Model 之上。

可能包含：

```text
Web/WASM environment
Linux compatibility
Android compatibility
other legacy runtime
```

但不是全部都必須在第一代實作。

## Rule

```text
Legacy Environment
→ Capability Translation
→ Native Security Model
```

不得為 compatibility 引入：

```text
global unrestricted filesystem
ambient network
root daemon authority
global user identifier
unrestricted IPC
```

若 legacy app 必須有較弱環境，該弱化必須被 containment，而不是污染 native model。

---

# 27. Phase 15 — Full VM System Integration

## Goal

在 VM 中形成第一個可連續操作的完整平台 prototype。

至少整合：

```text
boot
identity
keystore
vault
capabilities
services/IPC
app install
app launch
package verification
local data access
permission grant/revoke
sync prototype
messaging prototype
wallet reference flow
update path
recovery path
```

## System acceptance

必須建立 automated end-to-end suite，而不是只靠 individual crate unit tests。

至少測：

```text
fresh install
normal offline boot
app isolation
grant/revoke
service crash/restart
corrupted state
failed update
recovery event
network unavailable
malformed package
malicious App attempts
```

---

# 28. Optional Track C — Ledger / Currency

自有 currency / ledger / blockchain **不是 mandatory core path**。

原因：

- 它會引入 consensus、economic policy、network governance、regulatory/legal considerations；
- 不應阻塞 personal computing platform 的完成；
- wallet architecture 應能先存在，而不要求自有鏈。

只有以下任一條件成立才啟動：

```text
owner explicitly requests it
or
an accepted ADR adds it to the mandatory roadmap
```

若啟動，先做：

```text
research / threat model / local testnet
```

不得直接從概念跳到 mainnet、token sale 或不可逆 economic commitment。

這是 **Owner Decision Gate**。

---

# 29. Phase 16 — Dedicated Hardware Selection & Bring-up

## Goal

從通用 VM / reference machine 進入針對特定硬體深度最佳化的正式平台。

## Selection criteria

AI 必須先建立候選比較與 ADR，至少分析：

```text
boot openness
firmware control
IOMMU / memory isolation
secure boot flexibility
TPM / Secure Element availability
GPU/display support
storage
network/modem isolation
driver/documentation availability
power management
repairability
supply longevity
cost
physical security
updateability
manufacturing availability
```

## Owner Decision Gate

選定需要實際購買、長期綁定或大量 driver investment 的 dedicated hardware，是重大不可逆決策。

AI 可以完成研究、推薦與 ADR proposal，但在 owner merge 該 ADR 前不得把不可逆硬體假設擴散到 Core。

## After approval

進行：

```text
boot port
drivers
power management
storage/network/display integration
security root integration
performance profiling
energy profiling
hardware-backed KeyStore integration where available
```

---

# 30. Phase 17 — Developer Preview Hardening

## Goal

把「能跑」提升到外部 developer 可以使用且不會被頻繁破壞的 platform preview。

## Build / harden

```text
SDK/API documentation
stable capability vocabulary
app/package tooling
debug tooling
local audit UI/tooling
crash diagnostics
resource accounting
API compatibility tests
upgrade/migration tests
reproducible builds
supply-chain policy
security review
fuzzing campaigns
performance baselines
energy baselines
```

不得因 developer convenience 恢復 ambient authority。

---

# 31. Phase 18 — Stable 1.0 Platform

1.0 不代表「所有想像中的功能都有」。

它代表核心 contract 可以被長期依賴。

## 1.0 Required properties

```text
stable documented native API/protocol set
version/migration policy
portable Core proven on Linux + OurOS
capability model enforced end-to-end
identity/keystore/vault integrated
package/update trust integrated
application isolation operational
local-first normal operation
sync/messaging/wallet reference flows operational
repository distribution operational
recovery operational
system-level negative/security tests
upgrade tests
supported dedicated hardware target
measured performance/energy baseline
explicit known limitations
security response/governance process defined
```

## 1.0 non-claim

1.0 不等於：

```text
unhackable
anonymous against every adversary
formal verification of entire stack
tamper-proof hardware
kernel-compromise-proof secrets
```

任何安全宣稱必須對應具體 threat scope 與證據。

---

# 32. Phase Specification Contract

從 Phase 3 起，每個 mandatory milestone 開始實作前，branch 中必須新增/更新 Phase specification。

Specification 至少包含：

```text
Goal
In scope
Out of scope
Architecture boundaries
Assets
Threat IDs
Security invariants
Public/internal API plan
Persistence/wire plan
Dependencies
Unsafe policy impact
Test plan
Fuzz plan if parser exists
Failure/restart plan
Migration/compatibility implications
Exit criteria
```

AI 不需要 owner 先核准 ordinary phase spec 才開始 implementation；它可以在同一 branch 完成 spec + implementation，最後一起交 PR review。

只有 Owner Decision Gate 例外。

---

# 33. Completion Report Contract

每個 milestone PR 必須包含 Completion Report。

至少列出：

```text
Base HEAD
Branch HEAD
Changed files
Architecture consequences
Threat IDs addressed
Dependencies added/removed
ADRs added/changed
Commands actually executed
CI run IDs/URLs
Tests passed
Tests NOT VERIFIED
Remaining risks
Out-of-scope features explicitly not implemented
PR status
Merge status = NOT MERGED
```

禁止把「程式碼看起來正確」寫成 verified。

---

# 34. Standard AI Development Workflow

AI 在一般 Phase 中必須自主完成：

```text
1. Fetch latest main
2. Read mandatory docs/source
3. Determine next milestone
4. Inspect existing branch/PR
5. Create phase branch from exact main HEAD
6. Write/update phase spec
7. Threat/architecture delta review
8. Implement smallest coherent slice
9. Add tests first/with implementation where practical
10. Commit single-purpose changes
11. Push
12. Read actual CI logs
13. Fix all relevant failures
14. Repeat until push CI green
15. Create PR
16. Read PR-triggered CI
17. Fix until latest PR HEAD CI green
18. Write/update completion evidence
19. STOP — READY FOR OWNER REVIEW
```

Owner/other reviewer：

```text
review PR
→ request changes or approve
→ manually merge
```

AI 不得執行最後 merge。

---

# 35. Git Rules

## Never directly develop on main

所有 implementation / docs change 使用 branch。

## Branch names

預設：

```text
phase-3-identity-core
phase-4-keystore
phase-5-vault
phase-6-capability-authority
os-0-boot-baseline
...
```

若 branch 已存在：

```text
inspect it first
never force push unknown work
continue only if provenance/scope is understood
otherwise create -v2 branch
```

## Commits

應 single-purpose，例如：

```text
phase3(identity): add device enrollment state machine
phase3(test): add cross-app identity correlation tests
docs(phase3): record identity threat coverage
```

不要把整個 Phase 塞成一個不透明巨型 commit。

---

# 36. Pull Request Governance

每個 mandatory milestone 必須經 PR。

PR 必須描述：

```text
problem/context
scope
architecture impact
security/threat IDs
dependency changes
ADRs
test evidence
CI URLs
remaining risks
explicit non-goals
phase completion decision
```

PR 最新 HEAD 必須有 required CI 成功證據。

沒有 PR CI 成功：

```text
NOT READY
```

CI 成功但未 merge：

```text
READY FOR OWNER REVIEW
```

只有 owner/manual merge 後：

```text
MERGED COMPLETE
```

---

# 37. What AI May Decide Without Asking

為了避免每個小決策都中斷 owner，AI 可以自行決定：

```text
internal naming
module factoring
private helper APIs
ordinary test structure
error enum organization
small dependency-free implementation details
reversible refactors
CI fixes consistent with policy
which negative cases to add
performance implementation after profiling
```

如果是 architecture-relevant decision，AI 可以自行建立 ADR proposal 並在 branch 中實作 preferred option，最後交 PR 審核。

---

# 38. Owner Decision Gates

只有下列類型應在不可逆 implementation 前阻塞並要求 owner 在 PR/ADR merge 層級決定：

```text
project license selection
private vulnerability reporting channel ownership
permanent cryptographic trust-root policy change
destructive/migration-incompatible data format reset
dedicated hardware commitment / purchase target
legal/regulatory commitment
economic/token/ledger governance
repository ownership/governance change
security policy intentionally weakened for compatibility
private key export policy expansion
```

普通 architecture tradeoff 不需要在開發中途反覆詢問；應以 ADR proposal + PR review 解決。

---

# 39. Dependency Rules for Future AI

任何新 production dependency 都要回答：

```text
Why is it necessary?
Can core/std/alloc already solve this?
Exact version?
Source?
License?
Default features?
Actual enabled features?
no_std impact?
Unsafe footprint?
Build script?
Proc macro?
Transitive graph?
Known advisories?
Maintenance?
Replaceability?
Does it enter TCB?
```

對無法真正驗證的欄位寫：

```text
NOT VERIFIED
```

不得捏造「沒有 unsafe」「沒有漏洞」。

---

# 40. Security Testing Contract

只要 Phase 新增 parser/protocol/untrusted input，就必須評估：

```text
malformed input
truncated input
oversized input
unknown version
unknown field
invalid enum
integer overflow
allocation exhaustion
replay
duplicate
reordering
partial write
restart
corruption
```

若 parser 是 security-relevant，應建立 fuzz target。

Fuzz success 不只是 no crash；還需要考慮：

```text
no unauthorized state transition
no authority creation
no secret disclosure
bounded resource use
```

---

# 41. Failure Semantics Contract

Security-relevant uncertainty 預設：

```text
UNKNOWN     → DENY
CORRUPTED   → DENY
EXPIRED     → DENY
UNREACHABLE → DENY for authority decisions
ERROR       → DENY unless explicit reviewed fail-open policy exists
```

Service crash/restart 不得：

```text
restore revoked authority
create default broad authority
forget trust revocation
silently accept stale session
```

---

# 42. Persistence Contract

AI 必須持續區分：

```text
User Data State
Security State
Secret State
Temporary Runtime State
```

不能因為底層都存在同一顆 SSD 就給它們相同 rollback/recovery semantics。

典型例子：

```text
restore old photo       may be valid
restore revoked key     may be security vulnerability
restore old capability  may be security vulnerability
```

---

# 43. Protocol / ABI Contract

禁止：

```text
Rust struct memory layout = wire format
usize = persistent protocol integer
Display error string = machine protocol
local opaque handle = network authority
```

跨 component / disk / network 的資料必須有：

```text
explicit version
fixed representation
length bounds
unknown-field policy
canonical encoding when signed/hashed
migration policy
```

---

# 44. Portability Contract

每個新 external effect 都要先問：

```text
Is this a Domain concern or a platform effect?
```

Time、random、storage、network、process、IPC、device、secret storage 等不得直接滲入 portable Core。

不要建立巨型：

```text
trait Platform { everything... }
```

而使用 narrow semantic Ports。

Linux 只是第一個 adapter，不是 permanent contract。

---

# 45. Performance Contract

最佳化順序：

```text
correctness
security invariants
measured bottleneck
then optimization
```

效率衡量包括：

```text
CPU
memory
wakeups
context switches
copies
IPC overhead
storage I/O
energy
latency
attack surface
TCB size
code complexity
```

不要只用 microbenchmark 決定 architecture。

---

# 46. Documentation Must Evolve With Code

每個 Phase PR 必須同步更新受影響的：

```text
README
SECURITY
Phase specification
ADRs
Threat mapping
API docs
Completion report
```

如果 implementation 與 documentation 不一致：

```text
phase is not complete
```

---

# 47. Avoiding Roadmap Drift

AI 不得因為某個 feature 比較有趣，就跳過 mandatory prerequisite。

例：

```text
Messaging before Identity/KeyStore → prohibited
Wallet before KeyStore → prohibited
App Store before Package Trust → prohibited
OurOS app runtime before process/IPC authority → prohibited
Cloud sync as identity root → prohibited
Compatibility weakening native model → prohibited
```

若新的研究顯示 roadmap dependency 順序必須改，建立：

```text
Roadmap ADR / contract amendment PR
```

在 merge 前，仍以本文件現行順序為準。

---

# 48. Current Baseline at Initial Adoption

本文件最初提出時，正式 `main` 已合併：

```text
Phase 0
Phase 0.2
Phase 0.3
Phase 1
Phase 2 Cryptographic Foundation
Phase 2 Cryptographic Hardening
```

因此當本文件本身 merge 進 `main`，且在此期間沒有新的 milestone merge，**下一個 mandatory development milestone 是：**

```text
Phase 3 — Identity Core
```

這一段只是 adoption snapshot。

未來 AI **不得只看這段來判斷 current phase**；仍必須執行 §8 的 Deterministic Next-Work Algorithm。

---

# 49. Final Definition of Success

專案成功不是「做出可以開機的 OS」而已。

也不是「功能數量很多」。

成功必須同時滿足：

```text
User owns identity/data/keys/devices/capabilities
No ambient authority as default
Explicit and revocable authorization
Small trust relationships
Strong application isolation
Portable Core proven beyond Linux
Replaceable infrastructure
Offline-normal operation
Secure key-operation boundary
Auditable package/update trust
Explicit IPC
Efficient data movement
Recoverability without server-held master authority
Dedicated hardware deployment
Stable developer platform
Documented security limits
```

最終原則保持：

> **Applications should live inside the user's computer; users should not have to live inside applications' ecosystems.**

---

# 50. AI Stop Condition

正常 Phase 開發中，AI 不應在每一步詢問 owner。

它應持續工作，直到以下其中之一：

## A. Ready for Review

```text
implementation complete
required tests complete
latest branch CI green
PR created
latest PR HEAD CI green
completion evidence written
```

然後停止：

```text
READY FOR OWNER REVIEW
DO NOT MERGE
```

## B. Owner Decision Gate

遇到 §38 類型的不可逆決策。

## C. External Blocker

例如：

```text
required GitHub permission unavailable
upstream service unavailable
required hardware unavailable
legal information unavailable
CI infrastructure failure unrelated to code
```

此時必須準確報告 blocker，不得偽造 completion。

---

# 51. Rule for the Next AI Session

新的 AI session 被指派「繼續 Independent Computing Core」時，預設任務不是等待 owner 指定 feature。

它應：

```text
read this document
read current main
run §8 algorithm
identify first unfinished mandatory milestone
perform §34 workflow
open PR
stop at READY FOR OWNER REVIEW
```

除非 owner 明確指定：

```text
security audit only
documentation only
review only
hotfix only
roadmap amendment
```

否則這就是預設 continuation behavior。

---

**End — Independent Computing Core Project Execution Contract & Master Roadmap**
