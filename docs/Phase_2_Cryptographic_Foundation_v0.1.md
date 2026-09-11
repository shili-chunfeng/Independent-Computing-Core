# Independent Computing Core
## Phase 2 — Cryptographic Foundation v0.1

**Status:** Cryptographic Architecture Baseline / Initial Implementation  
**Stage:** Phase 2  
**Parent Documents:** Phase 0, Phase 0.2, Phase 0.3, Phase 1  
**Project Version:** 0.2.0  
**Target:** Linux/VM Prototype → Minimal OS → Dedicated Hardware OS  
**Date:** 2026-09-11

---

# 0. Purpose

Phase 2 建立整個 Independent Computing Core 之後所有安全功能共用的 cryptographic foundation。

本階段不發明密碼學 primitive，也不開始設計 cryptocurrency。

目標是建立：

```text
Crypto Profile
Crypto Provider Boundary
Typed Key Material
Hash
KDF
Digital Signature
Key Agreement
AEAD
Nonce Rules
Domain-Separation Rules
Key Lifecycle Rules
Test-Vector Policy
Crypto-Agility / PQ Migration Boundary
```

---

# 1. Non-Negotiable Rule

延續 Phase 0 C-010：

> **Invent systems, not cryptographic primitives.**

禁止自行實作新的：

```text
block cipher
stream cipher
hash function
MAC
signature algorithm
elliptic curve
KDF
CSPRNG
```

ICC 只負責：

```text
選擇經公開分析的 primitive
建立 typed API
建立 domain separation
管理 key lifecycle
建立 protocol composition
限制錯誤使用方式
```

---

# 2. Classical Crypto Profile v1

第一代固定 profile：

| Purpose | Algorithm |
|---|---|
| Hash | SHA-256 |
| Extract/Expand KDF | HKDF-SHA-256 |
| Digital Signature | Ed25519 |
| Diffie-Hellman | X25519 |
| AEAD | ChaCha20-Poly1305 |
| Password / Low-Entropy KDF | Argon2id v1.3 |

Profile ID：

```text
ICC_CLASSICAL_V1 = 0x0001
```

這是固定演算法集合，不是由 network peer 任意 negotiation 出來。

---

# 3. Why Fixed Profiles

錯誤設計：

```text
Client: I support strong + weak algorithms
Attacker modifies negotiation
Server: OK, use weak algorithm
```

因此：

> Crypto agility ≠ unrestricted algorithm negotiation.

我們採：

```text
Protocol Version
      ↓
Crypto Profile ID
      ↓
Fixed reviewed algorithm suite
```

未來新演算法建立新 Profile。

舊 Profile 是否接受，由 policy 決定。

---

# 4. SHA-256

SHA-256 作為 Classical v1 的主要 256-bit digest。

用途：

```text
integrity digest
content digest
HKDF underlying hash
protocol transcript components where specified
build/package hashing where protocol selects it
```

禁止把 plain hash 當：

```text
password hash
MAC
signature
secret authentication token
```

標準：NIST FIPS 180-4。

---

# 5. Hash Domain Separation

禁止無上下文地建立 security-sensitive identity：

```text
SHA256(data)
```

若 digest 具有 protocol/security meaning，應使用 canonical framing：

```text
DOMAIN || VERSION || LENGTH || DATA
```

例如：

```text
ICC/package-manifest/v1
ICC/device-binding/v1
ICC/vault-object/v1
```

實際 byte framing 由對應 protocol 定義。

Crypto Provider 不自行猜 protocol context。

---

# 6. HKDF-SHA-256

HKDF 用於：

```text
shared secret → protocol keys
master key material → purpose-specific subkeys
session secret → send/receive keys
```

不直接用於人類密碼。

基本規則：

```text
IKM
 ↓ Extract(salt)
PRK
 ↓ Expand(info)
Purpose-specific OKM
```

`info` 必須具有 domain separation。

例如：

```text
ICC/sync/send-key/v1
ICC/sync/receive-key/v1
ICC/vault/object-key/v1
```

標準：RFC 5869。

---

# 7. Password / Low-Entropy KDF

HKDF 不是 password-hardening function。

未來使用 PIN / passphrase 解鎖 software key material 時，Classical v1 指定：

```text
Argon2id version 1.3
```

但其：

```text
memory cost
time cost
parallelism
salt format
hardware calibration
```

不能現在硬編死。

因為合理成本取決於實際硬體。

Phase KeyStore / Device Unlock 會建立版本化 `PasswordKdfParameters`。

RFC 9106 要求 Argon2id 為其實作必須支援的主要 variant，並提供 password/key derivation 用途與參數建議。

---

# 8. Ed25519

Classical v1 signature：

```text
Ed25519
```

用途：

```text
identity assertions
package/developer signatures
signed metadata
future device authorization
```

Ed25519 約為 128-bit classical security level，public key 32 bytes、signature 64 bytes。

標準：RFC 8032。

---

# 9. Signature Domain Separation

Crypto Provider 的 Ed25519 API：

```text
sign(exact_bytes)
```

Provider 不建立 protocol framing。

因此任何正式 protocol 在簽章前 MUST 定義：

```text
protocol domain
version
message type
canonical encoding
payload
```

禁止：

```text
同一份 bytes 在不同 protocol 中具有不同 semantic
但共用完全相同 signed representation
```

否則可能發生 cross-protocol signature reuse。

---

# 10. Private Signing Key Rule

目前 Phase 2 為測試 provider，存在：

```text
Ed25519SigningSeed
```

這是 **A1 internal workspace type**。

它不得：

```text
跨 IPC
寫入 log
derive Debug
derive Clone
Serialize
成為 App API
```

Phase KeyStore 完成後，一般 service 應改為：

```text
KeyHandle
   ↓
SIGN operation
```

而不是傳遞 seed bytes。

---

# 11. X25519

Classical v1 key agreement：

```text
X25519
```

標準：RFC 7748。

Curve25519/X25519 目標約為 128-bit security level，使用 32-byte input/output。

Phase 2 Provider 對 shared secret 執行 contributory check。

若結果為 non-contributory / all-zero class：

```text
DENY
```

而不是繼續 KDF。

---

# 12. Raw DH Output Must Not Be Used Directly

禁止：

```text
X25519 shared secret
       ↓
直接拿去當 AEAD key
```

必須：

```text
X25519 shared secret
       ↓
HKDF-SHA-256
       ↓
protocol-specific key
```

HKDF info 必須包含 protocol/purpose context。

---

# 13. Static vs Ephemeral X25519

Phase 2 provider 暫時提供 typed `X25519Secret` primitive 以驗證算法邊界。

真正 protocol 必須明確決定：

```text
ephemeral
static
pre-key
one-time key
```

不能因為 API 能重複使用 secret，就默認 key reuse 是正確的。

Messaging / Sync phase 會另建 key-agreement protocol。

---

# 14. ChaCha20-Poly1305

Classical v1 AEAD：

```text
ChaCha20-Poly1305
```

RFC 8439 定義：

```text
256-bit key
96-bit nonce
128-bit authentication tag
AAD
```

它在無 AES 專用硬體時具有良好的純軟體特性，並是成熟、廣泛部署的 AEAD。

---

# 15. AEAD Means Encryption + Authentication

禁止：

```text
ChaCha20 only
AES-CTR only
home-made encrypt-then-hash
```

一般 confidential data 必須使用 AEAD。

Decryption authentication failure：

```text
AuthenticationFailed
```

不得輸出 unauthenticated plaintext。

---

# 16. Nonce Rule

RFC 8439 對 ChaCha20-Poly1305 要求：

> 同一 key 下，每次 invocation 必須使用不同 96-bit nonce。

因此 Crypto Provider **不自動產生 nonce**。

Nonce ownership 屬於使用它的 protocol/storage state machine。

原因：

```text
Crypto library 可以產生 random nonce
但它不知道 multi-process / rollback / snapshot / multi-device 狀態
```

真正 uniqueness 必須在更高層設計。

---

# 17. Nonce Strategies

未來 protocol 可選：

```text
counter-derived nonce
session-prefix + counter
random nonce with formal collision budget
per-key object counter
```

但必須 ADR / protocol specification。

禁止：

```text
current Unix time as nonce
random u32
object ID truncated without proof
constant nonce
```

---

# 18. AAD Rule

對 storage/protocol，AAD 應綁定重要但不需保密的 context，例如：

```text
protocol version
object type
object ID
owner ID
sequence number
key version
```

這能防止 ciphertext 被合法地搬到錯誤 semantic context。

實際 AAD schema 由各 protocol 定義。

---

# 19. Crypto Provider Boundary

架構：

```text
Identity / Vault / Package / Sync Domain
              │
              ▼
       icc-crypto-api
              ▲
              │ implements
       icc-crypto-rust
              │
              ▼
 RustCrypto / dalek implementations
```

Domain Core 不直接依賴：

```text
sha2
hkdf
ed25519-dalek
x25519-dalek
chacha20poly1305
```

---

# 20. Why Provider Boundary Exists

不是為了讓 runtime 任意選算法。

用途是：

```text
implementation replacement
hardware crypto/HSM backend
future OurOS backend
security audit isolation
unit-test substitution
post-quantum migration
```

例如未來：

```text
icc-crypto-rust
        ↓ replace
icc-crypto-hardware
```

Domain protocol 不必綁定 crate type。

---

# 21. No Algorithm Strings

禁止安全 API：

```text
algorithm = "whatever-user-supplied-string"
```

採 typed/stable IDs：

```text
CryptoProfileId
HashAlgorithmId
KdfAlgorithmId
SignatureAlgorithmId
KeyAgreementAlgorithmId
AeadAlgorithmId
```

未知 ID：

```text
UnsupportedAlgorithm
```

不得 fallback。

---

# 22. No Silent Downgrade

例如未來收到：

```text
Profile 0x9999 unknown
```

不能：

```text
"那改 ClassicalV1 好了"
```

除非 protocol 明確、authenticated negotiation 且 policy 允許。

預設：

```text
FAIL CLOSED
```

---

# 23. Secret Types

Phase 2 建立 typed secret wrappers：

```text
Ed25519SigningSeed
X25519Secret
SharedSecret32
AeadKey32
DerivedKey32
```

目的：

```text
減少 algorithm/key-purpose confusion
禁止 accidental Debug
禁止 accidental Clone
集中 zeroization
```

這些仍不是最終 KeyStore API。

---

# 24. Secret Zeroization

Phase 2 使用 `zeroize` crate 清除 secret wrapper 的記憶體。

但必須明確：

> Zeroization 不是「資料曾經從未被複製」的證明。

Compiler、register、OS paging、crash dump、kernel compromise 都可能超出單純 Drop-zeroize 能保證的範圍。

因此我們只做精確 claim：

```text
owned secret wrapper storage is zeroized on Drop
```

不宣稱：

```text
secret has vanished from the whole machine
```

---

# 25. No Clone / No Debug Secret Policy

Secret wrapper 預設：

```text
Clone = NO
Copy = NO
Debug = NO
Serialize = NO
```

如果某個 protocol 未來真的需要複製 secret：

必須顯式 API + review。

---

# 26. Randomness

Key / nonce generation 的 entropy 來源仍經：

```text
SecureRandom Port
```

Linux Adapter Phase 2 從直接打開 `/dev/urandom` 改為：

```text
getrandom 0.4.3
```

其 Linux backend 優先使用 Linux `getrandom` system call，並有適當 fallback/error semantics。

Crypto Provider 本身不偷偷呼叫 OS RNG。

---

# 27. Deterministic Tests vs Production Entropy

Test：

```text
DeterministicRandom
```

允許。

Production key generation：

```text
DeterministicRandom
```

禁止。

測試用 deterministic key material 必須清楚標示 test-only。

---

# 28. Crypto Error Semantics

我們不把 underlying crate error string 變成 protocol。

使用：

```text
InvalidKey
InvalidPublicKey
InvalidSignature
AuthenticationFailed
NonContributoryKeyAgreement
InvalidOutputLength
InvalidInput
UnsupportedAlgorithm
Internal
```

避免把 low-level implementation detail 洩漏到 Domain。

---

# 29. Authentication Failure Must Be Indistinguishable Where Appropriate

對 AEAD：

```text
wrong key
wrong nonce
wrong AAD
tampered ciphertext
tampered tag
```

對上層都可以收斂為：

```text
AuthenticationFailed
```

避免建立不必要 oracle。

---

# 30. Test Vector Policy

每個 algorithm provider 必須至少有：

```text
official known-answer test
positive round-trip test
negative/tamper test
boundary test
```

Phase 2 第一版已加入：

```text
SHA-256("abc") known vector
Ed25519 sign/verify + tamper
X25519 two-party agreement
ChaCha20-Poly1305 round trip + tamper
```

後續 compiler environment 中再擴充 RFC/NIST 完整 test vectors。

---

# 31. Cross-Implementation Verification

在 protocol 進入 A3 stability 前，重要 crypto format 必須至少與另一個獨立 implementation 做 compatibility test。

例如：

```text
ICC Rust provider
      ↕
independent reference/vector
```

不能只做：

```text
our encrypt → our decrypt
```

因為兩邊同時寫錯也可能互相通過。

---

# 32. Crypto Dependency Baseline

Phase 2 第一版 pin：

```text
sha2              = 0.11.0
hkdf              = 0.13.0
ed25519-dalek     = 3.0.0
x25519-dalek      = 3.0.0
chacha20poly1305  = 0.11.0
zeroize           = 1.9.0
getrandom         = 0.4.3
```

全部使用 exact direct-version pin。

但：

> direct exact pins 不能替代 Cargo.lock。

目前執行環境沒有 Cargo，因此真正 dependency resolution 後仍必須生成並提交 `Cargo.lock`，再進行 advisory/license/source review。

---

# 33. Dependency Features

我們刻意關閉不需要的 default features。

例如：

```text
ed25519-dalek:
  default-features = false
  zeroize only

x25519-dalek:
  default-features = false
  static_secrets + zeroize

chacha20poly1305:
  alloc + zeroize
```

不啟用：

```text
legacy_compatibility
hazmat
serde for secret keys
automatic getrandom inside crypto provider
```

---

# 34. Ed25519 Hazardous Features

`ed25519-dalek` 3.0.0 明確把 `legacy_compatibility` 標為 unsafe compatibility mode，`hazmat` 則暴露容易誤用的 raw signing API。

ICC Classical v1：

```text
legacy_compatibility = FORBIDDEN
hazmat = FORBIDDEN
```

除非未來 ADR 重新證明必要性。

---

# 35. Post-Quantum Position

截至 2026，NIST 已正式標準化：

```text
FIPS 203 — ML-KEM
FIPS 204 — ML-DSA
FIPS 205 — SLH-DSA
```

NIST 也正明確推動 cryptographic inventory 與 PQ migration。

因此我們現在就確立：

> ICC protocol 不得假設 Ed25519/X25519 永遠是唯一 public-key crypto。

但 Phase 2 **不直接把 ML-KEM/ML-DSA 加入 ClassicalV1**。

理由：

```text
目前沒有需要 long-lived network protocol 的 Phase 2 use-case
hybrid composition 必須由 protocol 層設計
key/signature sizes 影響 wire/storage formats
implementation/provider audit 要獨立評估
```

---

# 36. PQ Migration Rule

未來不做：

```text
X25519 OR ML-KEM chosen by unauthenticated negotiation
```

而可能建立：

```text
ICC_HYBRID_PQ_V1
```

例如：

```text
classical contribution
+
post-quantum contribution
↓
versioned KDF composition
```

真正設計必須另立 ADR。

---

# 37. Cryptographic Inventory

從 Phase 2 開始，任何使用 crypto 的 protocol / persistent format 必須記錄：

```text
algorithm/profile
purpose
key lifetime
where key is stored
what data is protected
migration path
```

這是未來 PQ migration、revocation 與 crypto deprecation 的基礎。

---

# 38. Crypto Agility Is Migration Ability

我們對 crypto agility 的定義：

```text
Ability to migrate safely from reviewed profile A to reviewed profile B
```

不是：

```text
Ability to accept arbitrary algorithms at runtime
```

---

# 39. Persistent Ciphertext Format

Phase 2 provider 回傳：

```text
ciphertext || Poly1305 tag
```

但這 **不是 Vault 永久格式**。

Vault phase 必須另外定義：

```text
format version
profile ID
key generation/version
nonce
AAD schema
ciphertext
```

Domain struct / provider output 不直接等於 persistent format。

---

# 40. Key IDs vs Keys

外部 API 應逐步只知道：

```text
KeyHandle / KeyId
```

而不是 secret bytes。

Phase 2 secret byte wrapper 只存在於 future Crypto Service / KeyStore 的內部 trust domain。

---

# 41. Key Lifecycle

每個長期 key 未來至少必須有：

```text
generate
activate
use
rotate
revoke
destroy
recover/rebind where applicable
```

不能只設計：

```text
create key forever
```

---

# 42. Key Purpose Separation

禁止同一把 key 同時用於：

```text
signing
AEAD
DH
```

也不應默認同一 symmetric key 用於多個不同 protocol purpose。

HKDF 建立 purpose-separated child keys。

---

# 43. Key Versioning

未來 persisted encrypted object 必須能知道：

```text
which key generation/version
```

但不必暴露 secret。

需要支援：

```text
old data decrypt
new data encrypt with current key
background migration
revocation semantics
```

詳細留到 KeyStore/Vault phase。

---

# 44. Decryption Before Authentication

上層 API 不得看到未驗證 plaintext。

即使底層 primitive 在內部計算出 plaintext：

```text
Tag invalid
   ↓
Discard
   ↓
AuthenticationFailed
```

---

# 45. Constant-Time Scope

我們使用目標為 constant-time 的 vetted implementations。

但不能對整個 OS 宣稱：

```text
constant-time system
```

因為：

```text
allocator
scheduler
cache
OS
hardware
protocol branches
```

都可能造成 timing variation。

Crypto primitive constant-time 與 protocol side-channel 是兩個層次。

---

# 46. Linux Prototype Limitation

延續 Phase 0.2：

若 Linux root/kernel 完全失陷，Phase 2 不宣稱可保住：

```text
in-memory Ed25519 seed
X25519 secret
AEAD key
HKDF output
```

未來 Hardware-backed KeyStore / OurOS 才能縮小該信任範圍。

---

# 47. New Workspace Structure

Phase 2 新增：

```text
crates/
└── crypto/
    ├── icc-crypto-api/
    └── icc-crypto-rust/
```

依賴：

```text
Domain Core
    ↓
icc-crypto-api
    ↑
icc-crypto-rust
```

禁止 Domain Core 直接依賴 provider implementation crate。

---

# 48. Architecture CI Update

Phase 2 architecture checker 新增：

```text
crypto API cannot import provider crates
Domain Core cannot import RustCrypto/dalek directly
crypto crates must remain no_std
crypto provider cannot depend on Linux/platform adapter
```

CI 新增：

```text
cargo check -p icc-crypto-api --no-default-features
cargo check -p icc-crypto-rust --no-default-features
cargo build --workspace --release
```

---

# 49. SecureRandom Linux Improvement

Phase 1 Linux implementation：

```text
open /dev/urandom
read_exact
```

Phase 2 改為：

```text
getrandom::fill
```

原因不是 `/dev/urandom` 本身不安全，
而是 `getrandom` 專門封裝各平台 OS entropy API、failure handling 與 Linux syscall/fallback 行為，更符合 Platform Adapter 邊界。

---

# 50. Security Tests Added

Phase 2 source tree加入：

```text
SHA-256 known answer
Ed25519 valid signature
Ed25519 tampered message rejection
X25519 agreement equality
X25519 contributory rejection path in provider
ChaCha20-Poly1305 round trip
ChaCha20-Poly1305 ciphertext tamper rejection
```

後續還要加入官方 RFC vectors。

---

# 51. Phase 2 Acceptance Criteria

Phase 2 要達到：

```text
[✓] fixed ClassicalV1 crypto profile
[✓] typed stable algorithm IDs
[✓] no generic string-selected algorithms
[✓] SHA-256 provider
[✓] HKDF-SHA-256 provider
[✓] Ed25519 provider
[✓] X25519 provider
[✓] ChaCha20-Poly1305 provider
[✓] secret wrapper zeroization
[✓] no Clone/Debug for secret wrappers
[✓] provider/domain dependency separation
[✓] nonce ownership outside provider
[✓] all-zero/non-contributory DH rejection
[✓] Linux entropy adapter improvement
[✓] architecture static checks
[ ] actual Cargo dependency resolution
[ ] Cargo.lock generation
[ ] cargo fmt
[ ] cargo clippy
[ ] cargo test
[ ] cargo check no_std
[ ] official RFC vector expansion
```

未勾選項目的原因：目前執行容器沒有 Rust/Cargo toolchain。

不能把 static validation 說成 compiler validation。

---

# 52. Static Validation Performed

本交付在目前環境可執行的驗證：

```text
Cargo TOML parsing
workspace member path validation
path dependency resolution
architecture checker
forbidden dependency scan
no_std declaration scan
secret Debug/Clone derivation scan
```

真正編譯驗證交由已有 CI workflow 執行。

---

# 53. ADRs Produced

Phase 2 正式決策：

```text
ADR-0003 Classical Crypto Profile v1
ADR-0004 Crypto Provider Boundary
ADR-0005 Secret Material and Zeroization Policy
ADR-0006 Crypto Agility and PQ Migration Policy
```

---

# 54. Next Phase

下一階段：

# Phase 3 — Identity Core

它會第一次真正把 Phase 2 crypto foundation 用在 system identity。

要設計：

```text
Root / Recovery Identity
Device Identity
App-specific pseudonymous identity
Identity derivation / unlinkability
Key handles
identity document / record
rotation
revocation
device enrollment
minimal disclosure boundary
```

但 Phase 3 不能把 Root Identity 直接變成全系統 public user ID。


# 55. References

## Standards / RFCs

- NIST FIPS 180-4 — Secure Hash Standard (SHA-256): https://csrc.nist.gov/pubs/fips/180-4/upd1/final
- RFC 5869 — HKDF: https://www.rfc-editor.org/rfc/rfc5869.html
- RFC 8032 — Ed25519 / EdDSA: https://www.rfc-editor.org/rfc/rfc8032.html
- RFC 7748 — X25519: https://www.rfc-editor.org/rfc/rfc7748.html
- RFC 8439 — ChaCha20-Poly1305: https://www.rfc-editor.org/rfc/rfc8439.html
- RFC 9106 — Argon2 / Argon2id: https://www.rfc-editor.org/rfc/rfc9106.html
- NIST SP 800-56C Rev. 2 — Key derivation methods: https://csrc.nist.gov/pubs/sp/800/56/c/r2/final
- NIST FIPS 203 — ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 — ML-DSA: https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205 — SLH-DSA: https://csrc.nist.gov/pubs/fips/205/final
- NIST PQC migration project: https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/

## Rust implementation references checked for Phase 2

- sha2 0.11.0: https://docs.rs/sha2/0.11.0/sha2/
- hkdf 0.13.0: https://docs.rs/hkdf/0.13.0/hkdf/
- ed25519-dalek 3.0.0: https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/
- x25519-dalek 3.0.0: https://docs.rs/x25519-dalek/3.0.0/x25519_dalek/
- chacha20poly1305 0.11.0: https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/
- zeroize 1.9.0: https://docs.rs/zeroize/1.9.0/zeroize/
- getrandom 0.4.3: https://docs.rs/getrandom/0.4.3/getrandom/

---

**End of Phase 2 — Cryptographic Foundation v0.1**
