# Independent Computing Core
## Phase 0.2 — Threat Model v0.1

**Status:** Security Architecture Baseline  
**Stage:** Phase 0.2  
**Parent:** Phase 0 — System Constitution v0.1  
**Target:** Linux/VM Prototype → Minimal OS → Dedicated Hardware OS  
**Date:** 2026-09-10

---

# 0. Executive Summary

本 Threat Model 的目的不是列出「可能被駭」的清單，而是正式回答：

1. **我們到底要保護什麼？**
2. **我們假設誰可能是惡意的？**
3. **不同元件失陷時，哪些東西仍必須安全？**
4. **目前 Linux/VM Prototype 能提供什麼安全保證？**
5. **哪些安全保證必須等到自己的 Kernel / Secure Boot / Hardware 才能成立？**
6. **後續每個核心模組必須通過哪些攻擊測試才能進入下一階段？**

本專案採用：

- Asset-centric threat modeling
- Trust-boundary analysis
- Capability-oriented security analysis
- Misuse / abuse-case analysis
- Software supply-chain threat modeling
- Compromise-containment analysis

而不是只依賴單一分類法。

最重要的設計原則：

> **我們不假設攻擊永遠能被阻止，而是同時設計「失陷後影響範圍必須被限制」。**

---

# 1. Security Mission

Independent Computing Core 的安全目標不是：

```text
Nobody can ever attack the system.
```

而是：

```text
1. 未授權實體不能取得資源。
2. 已授權實體不能超出被授予的範圍。
3. 一個 App 的失陷不能自然擴散至其他 App。
4. 一個 Repository 的失陷不能直接變成系統控制權。
5. 一個 Relay 的失陷不能取得明文內容。
6. Capability 洩漏時，其權限與生命週期應被限制。
7. 金鑰失陷時應存在撤銷、替換與恢復路徑。
8. 系統失敗時預設 fail closed。
9. Prototype 不宣稱它實際上無法提供的安全保證。
```

---

# 2. Relationship to Phase 0 Constitution

本文件以 Phase 0 的以下憲法規則為最高約束：

```text
C-001 User owns identity and data
C-002 No ambient authority
C-003 Capabilities must be unforgeable / attenuable / revocable
C-004 Local and network capabilities are separate security domains
C-005 Minimal identity disclosure
C-006 Root identity is not a global tracking identifier
C-007 Logical data model != physical storage
C-008 Naming != authority
C-009 Private keys remain inside KeyStore when possible
C-010 Do not invent cryptographic primitives
C-011 Core must not become platform-dependent
C-012 Time / Random / Storage / Network / Process / IPC are dependencies
C-013 Communication itself is a capability
C-014 Security boundaries justify IPC boundaries
C-015 Offline is a normal state
C-016 Stable interfaces, replaceable implementations
```

若後續實作與本 Threat Model 衝突：

> **預設修改實作，不是降低 Threat Model。**

若確實需要修改 Threat Model，必須建立 ADR。

---

# 3. Threat Modeling Method

本專案不把 STRIDE 當唯一方法。

原因：

STRIDE 很適合協助分類：

```text
Spoofing
Tampering
Repudiation
Information Disclosure
Denial of Service
Elevation of Privilege
```

但本系統真正重要的問題還包括：

```text
Capability leakage
Authority amplification
Authority laundering
Revocation failure
Identity correlation
Metadata disclosure
Repository compromise
Signing-key compromise
Rollback
Freeze attack
Recovery abuse
Cross-device replay
Kernel trust failure
Physical device compromise
```

因此我們採混合模型：

```text
Asset
  ↓
Trust Boundary
  ↓
Attacker
  ↓
Attack Path
  ↓
Security Invariant
  ↓
Containment Requirement
  ↓
Mitigation
  ↓
Verification Test
```

---

# 4. System Model

Phase 0.2 假設的邏輯系統：

```text
┌─────────────────────────────────────────────┐
│                  User                       │
└─────────────────────┬───────────────────────┘
                      │ explicit authorization
                      ▼
┌─────────────────────────────────────────────┐
│              Independent Runtime            │
│                                             │
│  ┌────────────┐  ┌──────────────┐           │
│  │ Identity   │  │ Capability   │           │
│  │ Service    │  │ Manager      │           │
│  └─────┬──────┘  └──────┬───────┘           │
│        │                 │                   │
│  ┌─────▼──────┐   ┌──────▼──────┐           │
│  │ KeyStore   │   │ Vault       │           │
│  └─────┬──────┘   └──────┬──────┘           │
│        │                  │                  │
│        └────────┬─────────┘                  │
│                 ▼                            │
│             Crypto Core                     │
└─────────────────┬───────────────────────────┘
                  │ Platform Interface
                  ▼
┌─────────────────────────────────────────────┐
│        Linux Adapter / Future OS Adapter    │
└─────────────────┬───────────────────────────┘
                  ▼
┌─────────────────────────────────────────────┐
│           Linux Kernel / Future Kernel      │
└─────────────────────────────────────────────┘

Applications
    │
    │ opaque handles + IPC
    ▼
Independent Runtime
```

未來網路部分：

```text
Device A
   │
 encrypted authenticated protocol
   ▼
Network / Relay / Repository
   │
 encrypted authenticated protocol
   ▼
Device B
```

---

# 5. Trust Boundaries

正式定義以下 Trust Boundaries。

## TB-01 — User ↔ Application

使用者的操作意圖與 App 的要求不同。

威脅：

```text
deceptive permission request
UI spoofing
consent laundering
permission fatigue
```

---

## TB-02 — Application ↔ Runtime

這是目前最重要的安全邊界之一。

App 一律視為：

```text
UNTRUSTED
```

Runtime 必須驗證：

```text
caller identity
capability handle
rights
scope
lifetime
resource
request format
```

---

## TB-03 — Runtime Service ↔ Runtime Service

即使兩個 Service 都是我們開發，也不能假設永遠安全。

例如：

```text
Vault Service compromised
```

不應自然得到：

```text
Root Identity private key
```

---

## TB-04 — Runtime ↔ Platform Adapter

Core 不可信任 Linux-specific 資料天然正確。

Adapter 必須負責：

```text
error normalization
resource validation
platform-specific isolation
secure OS API usage
```

---

## TB-05 — Platform Adapter ↔ Kernel

Linux Prototype 階段：

```text
Linux Kernel = TRUSTED HOST FOUNDATION
```

未來 OurOS：

```text
Minimal Kernel = TCB
```

---

## TB-06 — Device ↔ Network

所有輸入視為惡意：

```text
packets
DNS
relay responses
repository metadata
time claims
peer identity claims
```

---

## TB-07 — Device ↔ Repository

Repository 是 distribution mechanism，不是 authority。

---

## TB-08 — Device ↔ Peripheral

USB、Bluetooth、外接 storage、未來 sensor / modem 等均可能提供惡意輸入。

---

## TB-09 — Device ↔ Physical World

攻擊者可能：

```text
steal device
clone storage
boot another OS
inspect RAM
replace peripherals
```

Prototype 與 Future Hardware 對此保證不同。

---

# 6. Protected Assets

我們把資產分為四級。

---

## Class A — Crown Jewels

最高優先資產。

### A-01 Root / Recovery Identity Secrets

```text
Master key material
Recovery keys
Root authorization secrets
```

失陷影響：

```text
potential identity takeover
device enrollment abuse
recovery abuse
cross-service impersonation
```

---

### A-02 KeyStore Secrets

```text
private keys
derived secrets
authentication keys
encryption keys
```

---

### A-03 Capability Authority State

```text
capability table
revocation generation
ownership state
delegation relationships
```

若能任意修改：

```text
authorization model collapses
```

---

### A-04 Vault Plaintext

```text
user documents
photos
contacts
messages
application data
future financial data
```

---

### A-05 Update / Package Root Trust State

```text
trusted developer identities
trusted root metadata
key rotation state
version state
revocation state
```

---

### A-06 Boot / Kernel Trust Root

Future OS 才完整存在：

```text
secure boot root
kernel image integrity
boot policy
hardware trust anchors
```

---

## Class B — High Sensitivity

```text
Device identity
App-specific identities
Communication keys
Financial identity state
Vault metadata
Audit logs
Package installation state
Sync state
Recovery metadata
```

---

## Class C — Integrity-Critical

可能不是秘密，但不能被任意修改：

```text
package metadata
version counters
capability policy
object ownership
audit sequence
protocol versions
dependency manifests
build provenance
```

---

## Class D — Availability-Critical

```text
Identity service
Vault access
Capability manager
Update verification
Recovery path
Local IPC
Clock / monotonic time source
Entropy source
```

---

# 7. Security Invariants

後續所有程式碼必須維持以下 invariants。

---

## INV-001 — No Authority by Name

知道：

```text
Object ID
Path
Service name
Handle integer value
```

不能產生權限。

---

## INV-002 — No Authority Amplification

若 App 擁有：

```text
READ
```

任何 delegation / IPC / API 都不能產生：

```text
READ + WRITE
```

---

## INV-003 — Capability Scope Can Only Shrink

```text
Parent rights >= Child rights
Parent scope >= Child scope
Parent lifetime >= Child lifetime
```

---

## INV-004 — Revocation Must Take Effect

Capability 被 revoke 後：

```text
future operations = DENIED
```

不得因 cache、duplicate handle 或 stale session 永久逃避撤銷。

---

## INV-005 — Caller Identity Must Be Bound to Capability

Capability 不能只因 handle number 正確就有效。

Runtime 必須知道：

```text
which execution domain owns this handle
```

---

## INV-006 — Cross-App Isolation

App A compromise 不得直接取得：

```text
App B memory
App B identity
App B storage
App B capabilities
```

---

## INV-007 — Key Non-Export by Default

一般 App API 不得取得：

```text
raw private key
```

---

## INV-008 — Repository Compromise Is Not Device Compromise

單純控制 Repository 不應足以安裝任意可信程式。

---

## INV-009 — Network Is Never an Authority Source by Itself

收到：

```text
"grant me access"
```

不構成授權。

---

## INV-010 — Update Cannot Silently Expand Authority

版本更新若新增 capability：

```text
security-relevant event
```

---

## INV-011 — Rollback Must Not Restore Revoked Trust

不能靠回復舊資料：

```text
restore old package
restore old trust metadata
restore old capability state
```

來復活已撤銷權限。

---

## INV-012 — Security Failure Defaults to Deny

```text
unknown
malformed
expired
corrupt
unverifiable
```

→ `DENY`

---

## INV-013 — Root Identity Is Not Public Identity

一般 App 永遠不能要求：

```text
get_root_identity()
```

---

## INV-014 — Local Security Does Not Depend on Cloud Availability

Cloud offline：

```text
local identity
local vault
local authorization
```

仍應正常運作。

---

## INV-015 — Audit Is Not Authority

Log 說：

```text
operation was allowed
```

不能讓 operation 因此變成 allowed。

Audit 是 observation，不是授權來源。

---

# 8. Attacker Classes

---

## ATK-00 — Accidental Fault

不是惡意攻擊者，但包括：

```text
buggy app
corrupt file
partial write
power loss
invalid state
clock error
crash during update
```

安全系統必須把錯誤視為正常工程問題。

---

## ATK-01 — Malicious Application

能力：

```text
arbitrary code inside its own sandbox
arbitrary API requests
high request rate
malformed IPC
attempt handle guessing
attempt capability reuse
```

目標：

```text
escape sandbox
steal data
gain authority
attack services
fingerprint user
DoS runtime
```

---

## ATK-02 — Compromised Legitimate Application

原本可信任的 App 出現：

```text
RCE
dependency compromise
malicious plugin
memory corruption
```

這是比「明顯惡意 App」更重要的現實威脅。

系統不能把：

```text
developer reputation
```

視為 runtime privilege。

---

## ATK-03 — Malicious Developer

可能發布：

```text
legitimately signed malicious package
privacy-invasive update
capability expansion
tracking logic
```

Signature 只能證明：

```text
who signed
```

不能證明：

```text
software is good
```

---

## ATK-04 — Local Unprivileged Attacker

Linux Prototype 中可能取得一般使用者權限或執行本機程式。

嘗試：

```text
inspect IPC
read files
race runtime
replace sockets
process discovery
resource exhaustion
```

---

## ATK-05 — Remote Network Attacker

能力：

```text
observe traffic
modify traffic
drop traffic
replay traffic
inject packets
impersonate endpoint if authentication fails
```

---

## ATK-06 — Compromised Relay / Sync Server

假設 attacker 完全控制 Relay：

```text
read stored ciphertext
drop messages
reorder messages
replay messages
delay messages
serve different views
collect metadata
```

但不應能：

```text
decrypt payload
forge authenticated peer message
grant local capability
```

---

## ATK-07 — Compromised Repository

假設 attacker 完全控制 package repository infrastructure。

能力：

```text
replace packages
hide updates
serve old versions
target specific users
modify metadata
```

---

## ATK-08 — Signing / Build Infrastructure Compromise

比 Repository compromise 更嚴重。

可能取得：

```text
developer signing key
CI credentials
build worker
release pipeline
```

需要設計：

```text
key rotation
revocation
threshold trust where appropriate
provenance
reproducibility
```

---

## ATK-09 — Physical Device Thief

攻擊者取得關機或鎖定裝置。

可能：

```text
copy storage
remove storage
boot alternate environment
attempt offline key guessing
replace boot components
```

---

## ATK-10 — Malicious Peripheral

例如：

```text
USB
Bluetooth device
storage
future modem
sensor controller
```

可能提供 malformed / hostile input。

---

## ATK-11 — Compromised Platform / Kernel

Linux Prototype：

若 Linux Kernel 或 root 級攻擊者完全失陷，

**不宣稱**能保住：

```text
process memory
software keystore secrets
IPC confidentiality
runtime state
```

這是 Prototype 的明確安全邊界。

---

## ATK-12 — Malicious / Compromised Runtime Service

例如：

```text
Vault Service compromised
Package Service compromised
Sync Service compromised
```

設計要求：

> Service compromise 的 blast radius 應盡可能局限於該 Service 本身。

---

## ATK-13 — Supply-Chain Dependency Attacker

第三方 dependency 可能：

```text
publish malicious version
maintainer account compromise
dependency confusion
build script execution
