Zircon 的 handle / rights / process-local authority 與 capability transfer 設計，是未來 IPC / kernel handle model 的重要比較案例，但本專案不直接複製其 ABI。

Reference:

https://fuchsia.dev/fuchsia-src/concepts/kernel/handles

https://fuchsia.dev/fuchsia-src/concepts/kernel/rights

---

# 112. Phase 0.3 Completion Criteria

Phase 0.3 視為完成，因為目前已明確定義：

```text
Layer model
Dependency direction
no_std policy
std boundary
Platform Adapter boundary
External effect model
Time boundary
Random boundary
Storage boundary
Secret boundary
Network boundary
IPC boundary
Process boundary
Async/runtime boundary
Filesystem boundary
Configuration boundary
Logging boundary
Error boundary
Wire/persistence boundary
Unsafe boundary
FFI boundary
Third-party dependency policy
Service boundary
Testing boundary
CI architecture enforcement
Initial workspace design
Initial Port set
Initial coding order
```

---

# 113. Next Phase

下一步正式進入：

# Phase 1 — Project Skeleton & Engineering Baseline

Phase 1 將不再只是架構文件。

我們會真正建立：

```text
Rust workspace
Cargo structure
rust-toolchain
CI rules
crate boundaries
no_std checks
lint policy
dependency policy
test support
Linux adapter skeleton
```

並產生第一份可以：

```bash
cargo check
cargo test
```

成功的程式碼。

Phase 1 的第一個目標不是功能。

而是證明：

> **我們設計的 Architecture Boundary 能在真正的 Rust 專案中成立。**

---

**End of Phase 0.3 — Architecture Boundaries & Dependency Rules v0.1**
