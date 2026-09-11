transitive dependency compromise
```

---

## ATK-14 — Privacy Observer

未必能破解內容，但希望建立：

```text
who talks to whom
when
how often
which apps
which devices
stable identifiers
```

---

## ATK-15 — Future Hardware / Firmware Attacker

Future OS 階段才完整處理：

```text
boot firmware
DMA devices
baseband
secure element
hardware debug interface
malicious firmware
```

---

# 9. Explicit Prototype Security Boundary

這一節是硬規則。

第一代 Ubuntu/Linux VM Prototype：

## 我們可以測試與保證的東西

```text
logical capability correctness
authority attenuation
authorization API behavior
revocation semantics
identity separation
protocol parsing
package verification logic
vault encryption design
service API boundaries
malformed-input handling
update state machine
```

## 我們不能誠實宣稱的東西

若 host kernel / root 已失陷：

```text
memory secrecy
key secrecy
IPC secrecy
process isolation
anti-debugging
secure boot
physical tamper resistance
DMA isolation
firmware integrity
```

因此 Prototype 不得宣稱：

> 「即使 Linux root 攻擊也安全。」

---

# 10. Threat Catalogue

以下 Threat IDs 將成為後續 issue、test case 與 security review 的正式編號。

---

## Identity / Key Threats

### T-ID-001 — Root Identity Exposure

**Target:** A-01  
**Attackers:** ATK-01 / 02 / 04 / 11 / 12  
**Impact:** Critical

攻擊：

```text
App obtains root identity secret
debug log leaks key
backup contains plaintext key
memory disclosure
incorrect API export
```

Required controls：

```text
non-export API
KeyStore boundary
secret zeroization where practical
no debug logging
separate root identity from app identities
```

---

### T-ID-002 — Cross-App Identity Correlation

**Target:** Privacy  
**Attackers:** ATK-01 / 02 / 03 / 14  
**Impact:** High

攻擊：

多個 App 發現相同 stable identifier。

控制：

```text
per-app pseudonymous identity
no global advertising-style identifier
minimal disclosure
```

---

### T-ID-003 — Unauthorized Device Enrollment

攻擊者把自己的裝置加入使用者 identity domain。

控制：

```text
explicit authorization
device-specific key
auditable enrollment
revocation
recovery separation
```

---

### T-ID-004 — Recovery Channel Takeover

攻擊者利用 Recovery 取代正常 authentication。

控制：

```text
recovery is not universal bypass
rate limiting
explicit recovery state
old-device notification where possible
key rotation after recovery
```

---

## Capability / Authorization Threats

### T-CAP-001 — Handle Guessing

App 猜測：

```text
0x4217
```

等 opaque handle。

要求：

```text
process-local handle namespace
ownership binding
unpredictability where relevant
invalid handle → deny
```

---

### T-CAP-002 — Handle Reuse / ABA Problem

舊 handle 被關閉後，數字重新使用，App 錯把新資源當舊資源。

控制候選：

```text
generation counters
typed handles
execution-domain binding
stale-handle rejection
```

---

### T-CAP-003 — Authority Amplification

READ capability 經 API bug 變成 WRITE。

必須建立 property tests：

```text
child_rights ⊆ parent_rights
```

---

### T-CAP-004 — Revocation Bypass

攻擊者使用：

```text
duplicate
cached state
in-flight operation
secondary endpoint
```

繼續操作。

需要正式定義：

```text
revocation semantics
in-flight behavior
revocation generation
```

---

### T-CAP-005 — Capability Confusion

將對：

```text
Photo A
```

的 capability 誤用在：

```text
Photo B
```

控制：

```text
capability bound to object identity and type
typed API
server-side validation
```

---

### T-CAP-006 — Delegation Laundering

App A 沒權限取得某資源，但透過 App B 間接取得。

這不一定永遠是漏洞。

我們必須區分：

```text
explicit delegation
implicit laundering
```

只有前者允許。

---

### T-CAP-007 — TOCTOU Authorization Race

```text
check capability
↓
capability revoked
↓
operation executes anyway
```

需要 operation-level atomicity 或明確 semantics。

---

### T-CAP-008 — Excessive Lifetime

Temporary capability 因 bug 永不 expire。

控制：

```text
monotonic clock
expiry enforcement inside authority service
no client-side-only expiry
```

---

## IPC / Runtime Threats

### T-IPC-001 — Caller Spoofing

App 假稱自己是另一個 App。

IPC caller identity 必須由 runtime/kernel binding 提供，不接受 caller 自報。

---

### T-IPC-002 — Message Parser Attack

```text
oversized length
invalid enum
recursive structure
integer overflow
truncated message
unknown protocol version
```

控制：

```text
bounded parsing
versioned schema
length limits
fuzzing
fail closed
```

---

### T-IPC-003 — Unauthorized Endpoint Discovery

知道 service name 不能等於有權 call。

---

### T-IPC-004 — Capability Transfer Bug

IPC 傳遞 capability 時：

```text
wrong rights
wrong recipient
duplicate unexpectedly
retain sender authority unintentionally
```

都屬高風險。

---

### T-IPC-005 — Resource Exhaustion

App 大量：

```text
open handles
IPC messages
objects
sessions
```

造成 runtime crash。

控制：

```text
per-domain quota
backpressure
bounded queues
resource accounting
```

---

## Vault / Storage Threats

### T-VLT-001 — Unauthorized Object Read

沒有 capability 卻取得 object plaintext。

---

### T-VLT-002 — Unauthorized Object Modification

攻擊者不能修改 object 或 metadata 而不被偵測。

---

### T-VLT-003 — Object-ID Enumeration

即使不能讀內容，也可能透過 sequential IDs 推測資料量。

控制：

```text
non-sequential opaque IDs
authorization before metadata disclosure
```

---

### T-VLT-004 — Metadata Leakage

加密內容但暴露：

```text
filename
size
timestamps
contact graph
object type
```

必須把 metadata privacy 當獨立議題。

---

### T-VLT-005 — Snapshot Rollback

攻擊者還原舊 Vault：

```text
revoked state becomes active
deleted secret reappears
old capability policy returns
```

需在未來 storage architecture 中加入 rollback detection strategy。

---

### T-VLT-006 — Partial Write / Crash Corruption

斷電或 crash 時：

```text
ciphertext written
metadata not written
policy mismatch
```

控制：

```text
transactional state transition
integrity validation
crash consistency tests
```

---

## Package / Update Threats

### T-PKG-001 — Repository Package Replacement

Repository 替換 binary。

控制：

```text
signature verification
hash/integrity
developer identity continuity
```

---

### T-PKG-002 — Rollback Attack

Repository 提供舊但有效簽章版本。

控制：

```text
trusted version state
rollback policy
signed metadata versioning
```

---

### T-PKG-003 — Freeze Attack

Repository 永遠不提供安全更新。

需要：

```text
metadata expiry / freshness model
explicit stale state
```

---

### T-PKG-004 — Targeted Malicious Update

只對某個人提供特殊惡意版本。

未來研究：

```text
transparency
reproducible build
witnessing
consistent metadata
```

---

### T-PKG-005 — Signing Key Compromise

不能假設 signing key 永不失陷。

必須支援：

```text
revocation
rotation
compartmentalized roles
offline root trust where appropriate
threshold strategy where justified
```

---

### T-PKG-006 — Legitimately Signed Malicious Update

Developer 自己變惡意或帳號被合法流程控制。

簽章無法解決這個問題。

需要：

```text
capability transparency
update permission diff
source/build provenance
risk signal
user policy
```

---

### T-PKG-007 — Dependency Supply-Chain Compromise

Build 引入惡意 dependency。

需要：

```text
dependency locking
dependency review
minimal dependency policy
provenance
reproducible builds where feasible
```

---

## Network / Sync Threats

### T-NET-001 — Replay

舊 message 被重新送入。

控制：

```text
session identity
sequence / nonce
protocol-specific anti-replay
```

---

### T-NET-002 — Peer Impersonation

必須 cryptographically bind：

```text
peer identity ↔ session
```

---

### T-NET-003 — Message Reordering

Relay 改變順序。

Sync protocol 不能依賴不可信 server 提供真實順序。

---

### T-NET-004 — Message Suppression

Relay 丟棄資料。

Confidentiality 無法解決 availability。

系統需要：

```text
detect stale state where possible
retry
multi-relay / direct mode future option
```

---

### T-NET-005 — Metadata Correlation

即使 E2EE：

```text
IP
timing
packet size
device identifier
```

仍可能暴露關係。

此問題不能因「有加密」而被標記 resolved。

---

### T-NET-006 — Cross-Device Capability Replay

Local capability 不允許直接序列化後送到另一裝置。

Network capability 必須有獨立模型。

---

## Platform / Kernel Threats

### T-PLT-001 — Linux Adapter Privilege Leak

Platform Adapter 不小心：

```text
opens broader filesystem access
inherits ambient descriptors
exposes localhost service
uses insecure temp path
```

---

### T-PLT-002 — Kernel Compromise

Prototype：

```text
outside guaranteed protection
```

Future OS：

必須透過：

```text
small TCB
memory isolation
capability enforcement
secure boot
driver isolation where practical
```

降低風險。

---

### T-PLT-003 — Time Manipulation

Wall clock 可被改變。

Security expiry 不能單純依賴 wall clock。

需要區分：

```text
wall clock
monotonic clock
secure/freshness time
```

---

### T-PLT-004 — Weak Randomness

RandomSource 錯誤會破壞：

```text
keys
nonces
identifiers
```

因此 RandomSource 是 security-critical interface。

---

## Physical Threats

### T-PHY-001 — Stolen Powered-Off Device

Future requirement：

```text
encrypted data at rest
hardware-backed key protection where available
secure boot
credential-derived unlock strategy
```

---

### T-PHY-002 — Evil-Maid / Boot Replacement

Future OS 需研究 verified / measured boot。

Prototype 不宣稱防護。

---

### T-PHY-003 — Malicious Peripheral Input

Driver / parser 不可信輸入。

未來 driver architecture 必須納入 isolation 設計。

---

# 11. Compromise Containment Matrix

這是本 Threat Model 的核心。

| Compromised Component | What attacker may gain | What MUST remain protected |
|---|---|---|
| App A | App A data + App A granted capabilities | App B/C data, root identity, unrelated capabilities |
| App A developer | ability to ship malicious App A update if update trust allows | unrelated apps and system-wide authority |
| Vault Service | Vault-authorized plaintext may be exposed | Root private keys, package signing authority, unrelated kernel authority |
| Sync Relay | ciphertext + transport metadata + availability control | plaintext, local capability grants, private keys |
| Package Repository | distribution control | ability to forge trusted developer signature |
| Online signing key | packages within that key's delegated authority | offline/root trust outside delegation |
| Package Service | package-management state | raw root identity and unrelated Vault plaintext |
| Linux user-level process | resources granted by Linux permissions | runtime resources protected by process/permission model |
| Linux root / kernel | effectively whole software prototype | **No software-only secrecy guarantee claimed** |
| Future user app | its own domain | kernel, other domains, global key authority |
| Device thief | physical storage/device possession | plaintext without unlock/key material, subject to future hardware guarantees |

---

# 12. Risk Rating Model

我們不用模糊的：

```text
LOW / MEDIUM / HIGH
```

直接靠直覺。

每個 threat 計算：

```text
Risk Score = Impact × Feasibility
```

兩者均為 1–5。

## Impact

```text
1 = negligible
2 = limited single-object/app impact
3 = significant app/user data impact
4 = cross-component / major identity impact
5 = root compromise / broad confidential data / arbitrary authority
```

## Feasibility

```text
1 = highly constrained / exceptional capability required
2 = difficult
3 = realistic with meaningful prerequisites
4 = practical for capable attacker
5 = trivial / remotely repeatable / no special prerequisite
```

Risk：

```text
1–4   LOW
5–9   MODERATE
10–15 HIGH
16–25 CRITICAL
```

但：

> **任何破壞 Security Invariant 的漏洞，即使計分較低，也不能被視為「可以接受」。**

Risk score 用於排修復優先級，不用於取消憲法規則。

---

# 13. Mandatory Abuse Tests

每個核心 prototype 至少必須測試：

---

## Capability Tests

```text
random invalid handle
stale handle
closed handle
cross-process handle reuse
wrong resource type
rights escalation
scope escalation
expiry
revocation
delegation
revocation during operation
```

---

## IPC Tests

```text
empty message
truncated message
oversized message
unknown version
invalid enum
duplicate field
malformed capability transfer
high message rate
queue exhaustion
service restart
```

---

## Vault Tests

```text
unauthorized read
unauthorized write
metadata enumeration
corrupt ciphertext
corrupt metadata
partial write
crash during commit
rollback snapshot
wrong identity
wrong capability
```

---

## Identity / KeyStore Tests

```text
request raw private key
cross-app identity query
invalid key reference
deleted key use
revoked device
wrong recovery path
debug/log leakage checks
```

---

## Package Tests

```text
modified binary
modified manifest
wrong signer
old signed package
expired metadata
missing metadata
capability increase
dependency mismatch
revoked signer
repository serves inconsistent view
```

---

## Network Tests

```text
replay
drop
delay
duplicate
reorder
tamper
wrong peer
wrong protocol version
oversized packet
malformed packet
```

---

# 14. Fuzzing Requirements

以下元件一旦存在 parser，就必須進 fuzz target：

```text
IPC decoder
Package manifest parser
Vault object parser
Sync protocol decoder
Identity import/export parser
Recovery data parser
Network protocol parser
```

Fuzzing success condition 不是只有：

```text
no crash
```

還包括：

```text
no unauthorized state transition
no authority creation
no secret disclosure
bounded resource behavior
```

---

# 15. Resource Exhaustion Is a Security Problem

我們正式把 DoS 納入安全模型。

所有 execution domain 未來都需要 resource accounting：

```text
memory
handles
IPC queue
CPU time
storage
open objects
network bandwidth
background wakeups
```

Prototype 不一定立即完成完整 scheduler accounting，

但 API 不得假設：

```text
resources are infinite
```

---

# 16. Logging Threat Model

不得記錄：

```text
private keys
recovery secrets
full capability secrets
plaintext sensitive object
authentication tokens
```

Audit Log 若包含 stable IDs，也可能成為 tracking database。

因此：

```text
logging data minimization
```

必須與功能 logging 分開考慮。

---

# 17. Crash and Restart Semantics

Security-critical service crash 後不得：

```text
reset permissions to allow
forget revocation
recreate broad default capability
accept stale session automatically
```

重啟原則：

```text
unknown security state → deny
```

除非資料可經 authenticated persistent state 完整恢復。

---

# 18. Rollback as a Cross-System Threat

Rollback 不只存在 Package Update。

以下全部可能被 rollback：

```text
Vault
Capability state
Revocation list
Identity state
Device enrollment
Package metadata
Recovery state
Sync database
```

因此：

> **Rollback protection 是未來整個 platform 的橫向 security primitive，不只是 updater feature。**

這一點暫列為未來 Architecture Topic：

```text
ADR candidate: Monotonic Security State
```

---

# 19. Security State vs User Data

