我們將 storage 分成兩個概念：

```text
User Data State
```

與：

```text
Security State
```

例如：

```text
photo.jpg
```

與：

```text
developer key revoked at generation 18
```

不能用完全相同的同步/回復策略。

原因：

User 可能合理地想恢復舊照片，

但不能因此把已撤銷的惡意 signing key 恢復成可信。

---

# 20. Recovery Threat Model

Recovery 必須同時防：

```text
permanent lockout
unauthorized recovery
social engineering
server takeover
recovery-material theft
old-device abuse
```

基本不變量：

```text
Recovery must not silently bypass trust.
```

Recovery 後可能需要：

```text
rotate secrets
invalidate old sessions
re-authorize devices
mark security event
```

正式 Recovery Protocol 留到 Identity / KeyStore Phase 詳細設計。

---

# 21. Update Threat Model Principles

未來 update subsystem 必須假設：

```text
repository may be compromised
online keys may be compromised
network may be malicious
old valid versions may be served
updates may be withheld
different users may receive different metadata
```

因此 updater 不能只做：

```text
TLS + one signing key
```

我們會研究：

```text
role separation
key rotation
revocation
metadata expiration
rollback protection
threshold trust where justified
reproducible builds
transparency / witnessing
```

但不在 Phase 0.2 決定完整 Update Protocol。

---

# 22. Privacy Threat Model

Privacy failure 不只等於 plaintext leak。

我們分成：

```text
Content Privacy
Identity Privacy
Metadata Privacy
Relationship Privacy
Behavior Privacy
Location Privacy
Cross-App Correlation
Cross-Device Correlation
```

例如：

```text
E2EE message content safe
```

並不代表：

```text
communication graph safe
```

因此之後任何模組宣稱：

```text
private
```

都必須明確寫是哪一種 privacy。

---

# 23. Side Channels

第一代 Prototype 不宣稱消除：

```text
CPU cache side channels
speculative execution side channels
fine-grained timing attacks
power analysis
EM analysis
memory-bus observation
```

但架構必須避免主動製造簡單 side channel，例如：

```text
different error message reveals object existence
timing reveals capability validity unnecessarily
object IDs reveal creation order
```

高階 side-channel protection 留待：

```text
Future Kernel / Hardware Security Model
```

---

# 24. Future Kernel Threat Model Requirements

未來 Minimal OS 開始後，本 Threat Model 必須擴充至少：

```text
kernel object authority
address-space isolation
scheduler isolation
IPC primitive security
memory mapping rights
DMA
driver isolation
interrupt authority
boot trust
debug interface
device firmware
secure time
entropy
persistent monotonic security state
```

目標不是：

```text
Kernel is trusted, therefore stop analysis.
```

而是：

```text
Minimize what kernel must be trusted to do.
```

---

# 25. Security Gates

每個 Phase 都不能只用「功能完成」作為完成標準。

---

## Gate S0 — Threat Defined

必須回答：

```text
assets
attackers
trust boundaries
failure behavior
```

---

## Gate S1 — Authority Defined

每個 API 必須回答：

```text
Who can call?
With what authority?
On which resource?
For how long?
How revoked?
```

---

## Gate S2 — Negative Tests Exist

至少必須有：

```text
unauthorized path
malformed input path
expired/revoked path
```

---

## Gate S3 — Isolation Tested

若元件有 security boundary：

必須證明另一 domain 無法正常 API bypass。

---

## Gate S4 — Crash / Restart Tested

Security state 不能因 restart 變寬鬆。

---

## Gate S5 — Fuzzable Parsers Fuzzed

Parser 存在即建立 fuzz target。

---

## Gate S6 — Security Review

Milestone freeze 前重新檢查：

```text
new authority
new identifier
new trust
new persistent state
new network surface
```

---

# 26. Phase 0–6 First Security Acceptance Test

第一個正式 prototype 的 security acceptance flow：

```text
1. Create User Identity
2. Create Vault
3. Store Object X
4. Create App A
5. Create App B
6. App A reads X without capability
   → DENIED
7. App A guesses Object ID
   → DENIED
8. App A guesses random capability handle
   → DENIED
9. User grants READ(X) to App A
   → ALLOWED
10. App A attempts WRITE(X)
    → DENIED
11. App A delegates reduced temporary READ(X) to App B
    → allowed only if delegation policy permits
12. App B attempts to expand READ to WRITE
    → DENIED
13. Revoke parent capability
14. App A reads X
    → DENIED
15. App B uses derived capability
    → behavior must match defined revocation semantics
16. Restart Runtime
17. Previously revoked capability
    → remains DENIED
```

只有這條流程穩定成立，

我們才視為 capability + vault 基礎架構開始可信。

---

# 27. Security Claims We Will NOT Make

除非有實際證據，禁止宣稱：

```text
unhackable
military-grade
zero trust therefore secure
formally verified
anonymous
metadata-private
quantum-safe
tamper-proof
root-proof
kernel-compromise-proof
```

Security claim 必須具體：

例如：

```text
"App A cannot read Vault object X through the supported runtime API
without a valid READ capability."
```

比：

```text
"Vault is completely secure."
```

更合理。

---

# 28. Open Architecture Questions

Phase 0.2 暫不強迫決定以下問題：

### Q-001

Capability revocation 採：

```text
indirection table
generation counters
revocation tree
epoch
hybrid
```

哪一種？

→ Phase 6 Capability Design 決定。

---

### Q-002

Capability handle 是否需要 random/unpredictable？

Process-local table 正確實作後，

安全性不應只依賴難猜。

→ Phase 6 決定 representation。

---

### Q-003

Security State 如何防 snapshot rollback？

→ Storage / Future OS Architecture 研究。

---

### Q-004

Recovery 是否使用：

```text
recovery key
multi-device quorum
social recovery
hardware backup
hybrid
```

→ Identity / KeyStore Phase。

---

### Q-005

Update Trust 是否使用 TUF-inspired role model？

→ Package / Update Phase 進行 ADR，比較 TUF、Sigstore、SLSA 等模型後決定。

---

### Q-006

App Runtime 最終採：

```text
native process
WASM/WASI
hybrid
other capability runtime
```

→ App Runtime Phase，不在現在鎖定。

---

# 29. Architecture Decisions Produced by Phase 0.2

Phase 0.2 v0.1 現在正式確立：

## D-TM-001

**Malicious App 是正常系統狀態，不是例外。**

---

## D-TM-002

**Compromised legitimate App 與 malicious App 使用相同 runtime security model。**

---

## D-TM-003

**Repository 預設不可信。**

---

## D-TM-004

**Signing key compromise 必須被視為必須能恢復的事件。**

---

## D-TM-005

**Linux root / kernel compromise 超出第一代 software prototype 的安全保證。**

---

## D-TM-006

**Rollback 是平台級威脅，不只是 update 威脅。**

---

## D-TM-007

**Metadata privacy 與 content encryption 分開建模。**

---

## D-TM-008

**Capability authorization 必須由 authority-side 驗證，不相信 client 自報。**

---

## D-TM-009

**任何 parser 都是 attack surface。**

---

## D-TM-010

**DoS / resource exhaustion 是 security architecture 的一部分。**

---

## D-TM-011

**Recovery 是 security protocol，不是忘記密碼功能。**

---

## D-TM-012

**Security State 與 User Data State 必須允許不同的 rollback / recovery policy。**

---

# 30. Reference Systems and Standards

這些來源是研究參考，不代表本專案照抄其架構。

## NIST SP 800-154 — Guide to Data-Centric System Threat Modeling

NIST 將 threat modeling 視為一種風險評估方式，可針對資料、應用、主機、系統或環境分析攻擊與防禦面。

目前文件仍是 Initial Public Draft；NIST 在 2025 年的 planning note 表示計畫完成最終版。

Reference:

https://csrc.nist.gov/pubs/sp/800/154/ipd

---

## seL4 Capability Model

seL4 將 capability 定義為不可偽造、代表對系統物件/資源存取權的 token。

Reference:

https://docs.sel4.systems/Tutorials/capabilities.html

---

## Fuchsia / Zircon Handles and Rights

Zircon handle 是 process-local 的 kernel object reference；rights 附著於 handle，可在 duplicate / replace 時縮減，並可透過 channel IPC 轉移。

References:

https://fuchsia.dev/fuchsia-src/concepts/kernel/handles

https://fuchsia.dev/fuchsia-src/concepts/kernel/rights

https://fuchsia.dev/fuchsia-src/get-started/learn/intro/sandboxing

---

## WASI Capability-Based Sandbox

WASI application/component 以 capability-based sandbox 運作；初始沒有 ambient authority，只有 host 明確授予的能力。

截至 2026-09-10，WASI 0.3 是現行 stable milestone release。

Reference:

https://wasi.dev/

---

## SLSA Supply-Chain Threats

SLSA 將軟體供應鏈各階段的威脅分組，並強調 producer / consumer 面臨聚合性的 dependency 與 build pipeline 風險。

Reference:

https://slsa.dev/spec/v1.1/threats

---

## The Update Framework (TUF)

TUF 的設計明確考慮 Repository 與 Signing Key 失陷，並採用 trust expiration、角色分離、key rotation / revocation、threshold 等 compromise-resilience 原則。

References:

https://theupdateframework.io/

https://theupdateframework.io/docs/security/

---

# 31. Next Step

Phase 0.2 完成後，下一個 Phase 0 文件應為：

# Phase 0.3 — Architecture Boundaries & Dependency Rules

它要正式回答：

```text
哪些 crate 屬於 Pure Core？
哪些 crate 可以使用 std？
哪些模組可以碰 filesystem？
哪些模組可以碰 clock？
哪些模組可以碰 random？
哪些模組可以碰 network？
哪些模組可以做 IPC？
哪些 dependency 可以被 Core 引入？
哪些 API 會成為長期 ABI / protocol？
Platform Adapter 的責任到哪裡？
Service boundary 在哪裡？
```

Phase 0.3 完成後，

我們才開始建立真正的 Rust workspace skeleton。

---

**End of Phase 0.2 — Threat Model v0.1**
