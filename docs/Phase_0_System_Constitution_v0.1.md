# Independent Computing Core
## Phase 0 — System Constitution v0.1

**Status:** Architecture Baseline  
**Stage:** Phase 0  
**Target:** Linux/VM prototype → Minimal OS → Dedicated Hardware OS

---

# 1. Project Mission

本專案的目標不是建立另一個 Android App，也不是重新包裝 Linux。

目標是建立一套：

> 不依賴特定商業 OS、以使用者為權力中心、以 capability 為資源授權基礎、可逐步移植到自主 OS 的個人運算平台核心。

最終平台必須能支撐：

- Identity
- Secure Key Storage
- Personal Data
- Capability Security
- Application Runtime
- Software Distribution
- Device Sync
- Communication
- Wallet / Financial Protocol
- Future OS Services

---

# 2. Fundamental Ownership Model

系統的基本關係為：

```text
User
 │
 ├── Identity
 ├── Data
 ├── Keys
 ├── Devices
 └── Capabilities
          │
          ▼
         App
```

不是：

```text
App
 └── owns user data
```

也不是：

```text
Cloud Account
 └── owns user identity
```

## Constitutional Rule C-001

**使用者是資料與數位身分的最高控制者。**

Application、Server、Developer、OS service 都只能取得被授予的能力。

---

# 3. Default Trust Model

系統預設：

```text
Application        = UNTRUSTED
Network            = UNTRUSTED
Remote Server      = UNTRUSTED
Package Repository = UNTRUSTED
Developer          = NOT AUTOMATICALLY TRUSTED
Peripheral Device  = UNTRUSTED
Input Data         = UNTRUSTED
```

甚至：

```text
Our own application = UNTRUSTED
```

官方 App 不得因為是官方開發而獲得隱藏權限。

---

# 4. No Ambient Authority

任何 Application 啟動時，預設擁有：

```text
Filesystem   NONE
Network      NONE
Camera       NONE
Microphone   NONE
Contacts     NONE
Location     NONE
Bluetooth    NONE
USB          NONE
Clipboard    NONE
Identity     NONE
Other Apps   NONE
```

Application 必須透過明確 capability 取得資源。

## C-002

**不存在「因為程式正在執行，所以自然可以使用某資源」的權利。**

權利必須可追蹤至一個明確授權來源。

---

# 5. Capability Model

初期 prototype 採：

```text
Capability
{
    resource
    rights
    scope
    owner
    recipient
    expiry
    delegation_policy
    revocation_generation
}
```

Capability 不應只是：

```text
camera = true
```

而應能描述：

```text
Resource:
camera/rear

Rights:
READ_STREAM

Scope:
resolution <= 1920×1080

Expires:
30 seconds

Network forwarding:
DENIED

Delegation:
DENIED
```

## C-003

Capability 必須具有以下性質：

**不可偽造**

Application 不可自行製造有效 capability。

**可縮減**

擁有：

```text
READ + WRITE
```

可以授予另一程序：

```text
READ
```

但不能因此增加：

```text
DELETE
```

**可撤銷**

授權者撤銷後，舊 capability 不得繼續有效。

**可限制時間**

Capability 可以自動失效。

**可限制範圍**

權限應能作用於單一 Object，而不是必須授權整個資料類別。

---

# 6. Capability Representation

第一代 Linux prototype 不使用「Application 自己持有完整簽章 Token」作為主要本機權限機制。

採：

```text
Application
    │
    ▼
opaque handle
    │
    ▼
Runtime capability table
    │
    ▼
Resource
```

例如：

```text
Handle 0x4217
```

只在該 Application / session 中有意義。

Application 看不到真正的內部 capability state。

原因：

```text
容易撤銷
容易限制
減少 token 洩漏
降低解析成本
能直接對映未來 OS handle
```

未來跨裝置 capability 才另外設計 cryptographic representation。

## C-004

**Local Capability 與 Network Capability 必須是兩種不同的安全問題。**

不得為了未來跨網路使用方便，而讓本機架構承擔不必要複雜度。

---

# 7. Identity Model

系統不得存在一個所有 App 都能看到的：

```text
Global User ID
```

預設採：

```text
Human
 │
 ├── Device Identity
 ├── App-specific Identity
 ├── Communication Identity
 ├── Financial Identity
 └── Anonymous/Pseudonymous Identity
```

不同 Identity 原則上不能由第三方輕易關聯。

例如：

```text
App A sees:
user = D82F...

App B sees:
user = 19AC...
```

不得因為兩個 App 都安裝在同一台手機，就自然知道：

```text
D82F == 19AC
```

## C-005

**Identity disclosure 必須遵守資料最小化原則。**

例如服務只需要確認：

```text
age >= 18
```

未來應允許提供：

```text
age_over_18 = true
```

而不必提供：

```text
姓名
生日
地址
完整身分證明
```

---

# 8. Root Identity Must Not Become a Tracking Identifier

Master / Recovery Identity 的存在目的為：

```text
Key recovery
Device authorization
Ownership recovery
Critical trust operation
```

不是：

```text
App login ID
Advertising ID
Public username
Network identifier
```

## C-006

Root Identity 不得直接暴露給一般 Application。

---

# 9. Personal Data Model

Application 不直接擁有使用者資料。

邏輯架構：

```text
Personal Vault
      │
      ├── Object A
      ├── Object B
      └── Object C
             ▲
             │ Capability
             │
            App
```

Object 的邏輯模型：

```text
Object
{
    object_id
    owner
    type
    metadata
    content
    policy
    integrity_information
}
```

底層可以使用 filesystem、database 或其他儲存技術。

但 Application 不應依賴：

```text
/home/user/...
C:\Users\...
/sdcard/...
```

## C-007

**Logical Data Model 與 Physical Storage Model 必須分離。**

---

# 10. Path Is Not Authority

知道：

```text
photo://AB72
```

不能代表有權讀取它。

知道 Object ID：

```text
AB72
```

也不能代表可以存取。

必須同時具有：

```text
valid capability
```

## C-008

**Naming ≠ Authority**

「知道東西在哪裡」與「有權操作它」是兩件完全不同的事情。

---

# 11. Key Security

Application 原則上不得取得 private key raw bytes。

應採：

```text
Application
    │
    │ SIGN(data)
    ▼
Crypto Service
    │
    ▼
KeyStore
```

返回：

```text
Signature
```

而不是：

```text
Private Key
```

## C-009

秘密金鑰應盡可能：

```text
generate inside
use inside
remain inside
destroy inside
```

KeyStore。

未來底層可以替換：

```text
Software KeyStore
        ↓
TPM
        ↓
Secure Element
        ↓
Custom Hardware Security Module
```

而上層 API 不需要重新設計。

---

# 12. Cryptography Rule

本專案可以創新：

```text
Key architecture
Trust architecture
Identity architecture
Permission architecture
Protocol architecture
Recovery architecture
```

但禁止自行發明未經充分分析的新：

```text
Encryption algorithm
Hash algorithm
Digital signature primitive
Random number generator
```

## C-010

**Invent systems, not cryptographic primitives.**

---

# 13. Platform Independence

核心程式不得直接假設：

```text
Linux
Android
Windows
Darwin
POSIX
```

架構必須為：

```text
Core
 │
 ▼
Platform Interface
 │
 ├── Linux Adapter
 ├── Test Adapter
 └── Future OS Adapter
```

例如：

```text
Core requests:
RandomSource.random()

Linux:
getrandom()

Future OS:
our_sys_random()
```

Core 不知道下層是哪一個。

---

# 14. Core Portability Levels

核心程式分成：

```text
Level 0
Pure algorithms / types

Level 1
no_std + alloc where practical

Level 2
Portable runtime services

Level 3
Platform adapter

Level 4
UI / Application
```

我們不強迫所有 Rust code 都 `no_std`。

但最低層：

```text
identity-core
capability-core
protocol-core
crypto-domain
data-model
```

應盡量避免對 host OS 的依賴。

## C-011

「方便 Linux 開發」不能成為讓 Core 永久依賴 Linux 的理由。

---

# 15. Time Is a Dependency

Core 不允許隨意：

```text
SystemTime::now()
```

必須：

```text
Clock.now()
```

原因是未來需要：

```text
monotonic clock
secure time
simulation
testing
VM
hardware clock
```

## C-012

Time、Random、Storage、Network、Process、IPC 都視為 external capability/interface。

---

# 16. Application Isolation

每個 Application 預設具有獨立：

```text
Execution Domain
Identity
Storage namespace
Capability set
IPC endpoints
```

Application A 不得僅因 Application B 存在於同裝置就取得：

```text
memory
storage
IPC
identity
process information
```

---

# 17. Explicit IPC

Application 之間不能依靠：

```text
global namespace
shared temp directories
magic localhost ports
environment variables
hidden shared files
```

建立隱性通訊。

應採：

```text
Process A
   │
capability
   │
   ▼
IPC endpoint
   │
   ▼
Process B
```

## C-013

**Communication itself is a capability.**

---

# 18. IPC Must Support Capability Transfer

未來 IPC 不只是：

```text
send(bytes)
```

還應可以：

```text
send(
    message,
    restricted_capability
)
```

例如：

```text
Photo App
   │
   │ temporary READ capability
   ▼
Editor App
```

Editor 得到照片存取權，但不需要得到整個 Photo Library 權限。

---

# 19. Service-Oriented, Not Microservice-Oriented

我們不會因為「服務化」而把任何東西都拆成 process。

只有當以下需求存在時才建立安全邊界：

```text
Privilege separation
Fault isolation
Independent lifecycle
Attack surface reduction
Resource accounting
```

否則可以放在相同 trust domain。

## C-014

**Security boundary 才值得支付 IPC 成本。**

避免：

```text
Architecture purity
        ↓
大量 context switching
        ↓
效率下降
```

---

# 20. Efficiency Principle

效率不是只有 benchmark。

我們同時衡量：

```text
CPU time
memory
wakeups
context switches
copies
IPC overhead
storage I/O
energy
latency
attack surface
code complexity
```

例如：

```text
最快
```

但 Trusted Computing Base 大兩倍，

不一定叫更有效率。

---

# 21. Zero-Copy Direction

大型資料：

```text
Video
Image
Audio
Model
Large document
```

原則上不應不停：

```text
App → Service → App → Service
```

複製整份資料。

未來應支援：

```text
Shared Memory Object
        +
Capability
        +
Rights
```

例如：

```text
Camera Service
      │
 shared buffer
      │
      ▼
    App
```

App 只有：

```text
READ
```

而沒有：

```text
WRITE
```

---

# 22. Local First

系統基本功能不得依賴 Internet。

以下功能至少必須能離線：

```text
boot
identity
data access
key operations
applications
permissions
package inspection
local communication
local device management
```

Cloud 可以提供額外功能，但不能成為系統生存條件。

## C-015

**Offline is a normal operating state, not an error state.**

---

# 23. Cloud Is Replaceable

不得設計：

```text
Our Cloud
   =
System Identity
```

應為：

```text
System
 │
 ├── Local
 ├── Peer-to-peer
 ├── Relay A
 ├── Relay B
 └── Self-hosted relay
```

使用者更換同步供應商，不應需要建立新的數位人生。

---

# 24. Repository Is Not Authority

Package repository 只負責：

```text
Discovery
Distribution
Metadata
Caching
```

不能因 package 來自：

```text
Official Store
```

就自動被信任。

Application 信任依據應來自：

```text
Developer signature
Package integrity
Source provenance
Build information
Permission declaration
Verification
Policy
```

---

# 25. Package Transparency

未來 Package Metadata 必須能揭露：

```text
developer
source
version
requested capabilities
network requirements
dependencies
signature
build information
update policy
```

安裝行為不能偷偷增加 capability。

如果更新版本要求：

```text
v1:
photo.read

v2:
photo.read
microphone.read
network.connect
```

必須被視為安全模型變化。

---

# 26. No Special Privilege for Store Apps

官方 Repository 的 App 與 sideloaded App 在 runtime security model 上不得有兩套標準。

系統可以：

```text
warn
verify
score risk
require confirmation
```

但不能因為 App 不來自官方市場，就故意破壞正常 security API。

---

# 27. Updates Are Security Events

更新必須驗證：

```text
Identity continuity
Signature
Version transition
Package integrity
Capability changes
Migration behavior
```

不能只做：

```text
new version > old version
→ install
```

---

# 28. Stable Interfaces, Replaceable Implementations

例如：

```text
Vault API
```

可以保持穩定。

而後端：

```text
SQLite
↓
Custom object store
↓
Future OS storage service
```

可以更換。

## C-016

**Protocol/interface 比 implementation 更長壽。**

---

# 29. Version Everything

凡是跨 component 的資料：

```text
IPC
Package
Vault object
Identity record
Sync message
Protocol message
```

必須具有版本策略。

不得假設：

```text
current struct layout == permanent protocol
```

---

# 30. Fail Closed

安全決策發生錯誤時：

```text
UNKNOWN
ERROR
CORRUPTED
EXPIRED
UNREACHABLE
```

原則上：

```text
DENY
```

不是：

```text
ALLOW
```

除非該功能有經過明確定義的 fail-open policy。

---

# 31. Recovery Must Be Designed From Day One

「安全」但使用者只要：

```text
手機壞掉
```

就永久失去：

```text
Identity
Data
Funds
```

不是完整的安全設計。

我們必須同時設計：

```text
Confidentiality
Integrity
Availability
Recovery
```

但 Recovery 不能變成：

```text
Server has master key
```

---

# 32. Observability Without Surveillance

系統需要：

```text
debugging
audit
performance telemetry
security events
```

但不能因此默認建立中央監控。

Local Audit Log 優先。

Telemetry：

```text
OFF by default
```

若未來提供：

```text
Opt-in
Minimized
Transparent
Inspectable
Revocable
```

---

# 33. Privacy Is Architectural

Privacy 不得只是 Settings 裡的：

```text
Privacy Mode
```

而應由架構導出。

例如：

```text
per-app identities
capability isolation
local-first storage
minimal disclosure
no ambient authority
encrypted sync
```

即使 UI 沒有「Privacy」按鈕，架構本身仍然必須保護使用者。

---

# 34. Security Is Not Compatibility

如果某項 legacy compatibility 必須要求：

```text
global filesystem
unrestricted IPC
root daemon
ambient network access
global user ID
```

則 compatibility layer 必須被隔離。

不得降低整個平台的安全模型來遷就它。

---

# 35. Compatibility Must Be Above the Core

未來若支援：

```text
Linux Apps
Android Apps
Web Apps
WASM Apps
```

應採：

```text
Legacy App
    │
Compatibility Environment
    │
Capability Translation
    │
Native Security Model
```

而不是修改 native security model 迎合 legacy application。

---

# 36. TCB Minimization

Trusted Computing Base 越小越好。

理想方向：

```text
Kernel
Security-critical runtime
Capability manager
Critical key service
Minimal boot trust
```

一般：

```text
GUI
Store
Browser
Media player
Messaging
Cloud
```

不得因方便而變成 TCB。

---

# 37. Crash Is Better Than Privilege Escalation

若我們面臨選擇：

```text
Service crashes
```

或：

```text
Unauthorized resource access
```

安全核心必須選擇前者。

---

# 38. Human Control

系統必須讓使用者能理解：

```text
誰
正在
對什麼
做什麼
為什麼
多久
```

例如不是：

```text
App has storage access
```

而是：

```text
Editor
can READ
Photo AB72
until application exits
granted by User
```

---

# 39. No Dark Architecture

不得故意：

```text
讓取消權限變困難
隱藏資料流向
偷偷恢復設定
偷偷重新取得識別碼
迫使使用者建立雲端帳號
```

這些不只是 UI 問題。

它們違反系統架構本身。

---

# 40. Architecture Before Features

新增任何功能前必須回答：

```text
What resource does this introduce?

Who owns it?

Who can access it?

How is access granted?

How is access revoked?

Can it work offline?

What becomes trusted?

What happens if compromised?

Does it create a permanent identifier?

Does Core now depend on a platform?
```

沒有答案，不進 implementation。

---

# 41. Architecture Decision Records

任何會影響長期架構的決策建立：

```text
docs/adr/
```

格式：

```text
ADR-XXXX

Title
Status
Context
Decision
Alternatives
Security consequences
Performance consequences
Portability consequences
Migration consequences
```

不得只寫：

```text
因為比較方便
```

---

# 42. Prototype Rule

Prototype 可以醜。

可以只有 CLI。

可以沒有 GUI。

但不可用錯誤架構換取 Demo。

允許：

```text
temporary implementation
```

不允許：

```text
temporary security model
```

因為安全模型一旦被大量程式依賴，日後極難修正。

---

# 43. Current Architecture

第一階段：

```text
Applications
     │
     ▼
Portable Interface
     │
     ▼
Independent Runtime
     │
 ┌───┼───────────────┐
 │   │               │
 ▼   ▼               ▼
Identity Capability Vault
 │       │             │
 └───────┼─────────────┘
         ▼
      Crypto
         │
         ▼
 Platform Interface
         │
         ▼
     Linux Adapter
         │
         ▼
       Linux
```

未來：

```text
 Platform Interface
         │
         ▼
     YourOS Adapter
         │
         ▼
       YourOS
```

Core 不改。

---

# 44. First Technical Objective

第一個 prototype 必須能完成：

```text
Create identity
      ↓
Create vault
      ↓
Store object
      ↓
Create application identity
      ↓
Application requests object
      ↓
DENIED
      ↓
Grant capability
      ↓
ALLOWED
      ↓
Revoke capability
      ↓
DENIED
```

若無法完成這個循環，

Phase 0～6 不視為基本架構成立。

---

# 45. Success Criterion

我們追求的不是：

> 做出一個跟 Android 差不多的 OS。

也不是：

> 做出 Apple 的開源版本。

成功標準是：

```text
Less ambient authority
Smaller trust relationships
Clearer ownership
Lower unnecessary coupling
Strong isolation
Explicit resource access
Portable core
Efficient IPC
Minimal copying
Offline independence
User-controlled identity
Replaceable infrastructure
```

最終：

> Application 應該生活在使用者的電腦裡，而不是讓使用者生活在 Application 的生態裡。

---

# Architecture Notes

Phase 0 v0.1 正式採用 capability-oriented architecture，但不綁定 seL4、Fuchsia 或 WASI。這些系統只作為設計參考。

核心設計原則包括：

- Naming ≠ Authority
- No Ambient Authority
- Local Capability 與 Network Capability 分離
- Security Boundary 才值得支付 IPC 成本
- Compatibility 必須位於 Core 之上
- Platform dependency 必須隔離在 Adapter
- Privacy 與 Security 必須由架構提供，而不是依靠 UI 選項

---

# Next Phase

下一階段：

## Phase 0.2 — Threat Model

需要定義：

```text
惡意 App 能做到什麼？
App 被攻破怎麼辦？
Store 被攻破怎麼辦？
同步伺服器被攻破怎麼辦？
裝置遺失怎麼辦？
Root identity 洩漏怎麼辦？
Vault metadata 能否被分析？
IPC endpoint 能否偽造？
Capability 能否重放？
惡意更新怎麼辦？
Kernel 被攻破後還剩下什麼？
未來硬體被實體拿走怎麼辦？
```

Phase 0.2 完成後，才開始定義第一個正式 Rust interface。

---

**End of Phase 0 — System Constitution v0.1**
