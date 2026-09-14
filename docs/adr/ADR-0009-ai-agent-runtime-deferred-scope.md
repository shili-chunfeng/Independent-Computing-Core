# ADR-0009 — AI Agent Runtime: Deferred Scope and Sandboxed Placement

## Status

Proposed for Phase 9 owner review. This ADR does not authorize any
implementation work now and does not change the execution order defined by
the Project Execution Contract.

## Context

The owner intends ICC to eventually host an AI agent that can plan and carry
out tasks on the user's behalf, acting under the user's direction rather than
as an independent account holder. Two existing documents already bound this
intent before this ADR:

1. Project Execution Contract §4 ("What ICC Is Not") explicitly lists
   `AI assistant` among the product-layer items that must not be prioritized
   ahead of the unfinished Identity, KeyStore, Vault, Capability Authority,
   Service Runtime, and Package Trust foundations. This ADR does not relax
   that deferral.
2. Project Execution Contract §19 (Phase 9 — Application Model, Runtime &
   Sandbox) is the first point in the roadmap where a native application
   execution model, per-app identity, storage namespace, initial capability
   set, and crash isolation exist. Any future agent capable of taking actions
   on the user's behalf requires exactly this machinery to exist first.

This ADR exists to record, ahead of time, *where* a future AI agent belongs in
the architecture and *what it is not allowed to be*, so that when Phase 9 work
actually starts — by this owner, a future contributor, or an autonomous AI
agent operating under this same Execution Contract — the placement decision
is not made improvised, under schedule pressure, or by the agent's own
implementer.

Relevant existing constraints this ADR must not contradict:

- Constitution §3 Default Trust Model: `Our own application = UNTRUSTED`.
- Constitution §4 / C-002 No Ambient Authority: no resource access without a
  traceable, explicit grant.
- Constitution §26 No Special Privilege for Store Apps: first-party origin is
  not a trust upgrade.
- Constitution §38 Human Control: the user must be able to answer who is
  acting, on what, with which rights, why, for how long, granted by whom.
- Constitution §32 Observability Without Surveillance and §33 Privacy Is
  Architectural.
- README: "Local authorization remains authority-side; UI/CLI is not a
  security authority."
- Threat Model ATK-12 (Malicious/Compromised Runtime Service) and INV-002 (No
  Authority Amplification) apply to any long-running service, including an
  agent runtime.

## Decision

### 1. This ADR defers implementation

No crate, module, dependency, model runtime, or CI job is introduced by this
ADR. The AI Agent Runtime remains out of scope until Phase 9's own Build list
and Exit Gate are met and the preceding phases (3–8) are merged to `main`.
This ADR is a placement decision only.

### 2. The agent is an ordinary sandboxed Phase 9 App, not a platform component

An AI Agent Runtime is a Service/App under Phase 9, with the same required
properties as any other application:

```text
AppId
execution domain
App-specific identity
storage namespace
initial capability set
CPU/memory/handle/IPC/storage quota
crash isolation
```

It does not run inside the Domain Core, the Capability Authority, the
KeyStore, or any other component classified as part of the Trusted Computing
Base under Constitution §36. It has zero ambient authority at startup, the
same as every other App under Constitution §4.

### 3. Every agent action must resolve to an explicit capability

The agent proposing an action is not authorization to perform it. Consistent
with the existing "UI/CLI is not a security authority" rule, "agent output is
not a security authority" either. All resource access — filesystem, network,
identity, key operations, other apps' data, device peripherals — must go
through the same capability-grant path any other App would use.

### 4. A fixed class of actions always requires interactive confirmation

Independent of how broad a capability the agent already holds, the following
action classes require a fresh, explicit user confirmation at the time of the
action, not merely at capability-grant time:

```text
Any network egress not already scoped to a single prior user-approved destination
Any KeyStore / secret-operation invocation
Any identity or device state transition (enrollment, rotation, revocation, recovery)
Any capability delegation to another App or service
Any deletion or irreversible mutation of a Vault object
Any cross-App data access
```

This list is a floor, not a ceiling; Phase 9 design work may extend it. It may
only be narrowed by a future ADR that explicitly supersedes this one — never
by an implementation detail or a broader capability grant elsewhere.

### 5. No bypass of the crypto/KeyStore boundary

The agent never receives raw private key material. Any signing or secret
operation the agent needs is requested through the KeyStore's non-exporting
operations (ADR-0005, ADR-0008), identically to any other caller.

### 6. Autonomy is an explicit state machine, not self-assessment

Agent execution exposes explicit states — proposing, executing,
blocked-pending-confirmation, and handed-off-to-user — rather than relying on
the agent's own judgment of whether a situation is sensitive enough to ask.
Low-confidence or failed execution transitions to handed-off-to-user; it does
not silently retry with escalated privileges.

### 7. Model locality is a capability question, not exempted from one

Whether inference happens on-device or over the network is itself subject to
Constitution §22 (Local First) and §23 (Cloud Is Replaceable). If any model
component requires network access, that access is requested and displayed as
an ordinary network capability grant like item 4 above, not bundled invisibly
into the agent's installation.

### 8. Runtime technology is not selected here

This ADR does not choose native / WASM / WASI / hybrid execution, a specific
model runtime, or a specific model. That remains the Phase 9 "Runtime choice
gate" decision under Project Execution Contract §19, to be made by its own
ADR when that phase starts.

## Alternatives Considered

### Implement the agent runtime now, ahead of Phase 9

Rejected. Contradicts Project Execution Contract §4's explicit deferral of
"AI assistant" and would build application-layer functionality before
Identity, KeyStore, Vault, and Capability Authority exist to constrain it.

### Grant the agent an implicit or broader default capability set for convenience

Rejected. Violates Constitution C-002 (No Ambient Authority) and INV-002 (No
Authority Amplification). Convenience is not a listed exception anywhere in
the Constitution or Threat Model.

### Let the agent decide for itself when a situation is sensitive enough to ask the user

Rejected. This would make the agent's own output a security authority, which
directly contradicts the existing "UI/CLI is not a security authority"
principle and Constitution §38 Human Control.

### Treat the agent as a trusted first-party/platform component

Rejected. Constitution §3 states our own application is untrusted by default,
and §26 forbids special privilege for first-party or store-distributed
software. An agent shipped by the platform itself gets no exemption.

### Leave the placement undecided until Phase 9 begins

Rejected as the sole approach. Leaving it undecided risks the placement being
made ad hoc, under time pressure, or by whichever contributor (human or AI)
happens to reach Phase 9 first — which is precisely the scenario this ADR is
meant to prevent, given the Contract's rule that AI should proceed
autonomously through implementation.

## Security Consequences

Positive:

- no new code, dependency, or attack surface is introduced by this ADR;
- explicitly forecloses ambient/ elevated authority for a future agent before
  any implementation exists to argue otherwise under deadline pressure;
- fixes a floor of always-confirm action classes before any agent code exists,
  rather than retrofitting confirmation after a capability model is already
  built around convenience;
- reaffirms that neither UI nor agent output can self-certify as authority.

Limitations / remaining risks:

- this ADR does not yet define the concrete capability schema, IPC shape, or
  quota values the agent will use — that is real Phase 9 design work;
- prompt-injection- and tool-misuse-style threats specific to an AI agent are
  not yet entered into the Phase 0.2 Threat Model catalogue; a future Threat
  Model update should add an attacker class and threat entries for a
  compromised or manipulated agent before Phase 9 implementation begins;
- no runtime or model is selected, so no claim is made about any specific
  model's behavior;
- this ADR cannot prevent a future contributor from proposing to supersede it;
  it only requires that any such change go through the same ADR review this
  document did.

## Performance Consequences

None. No implementation is introduced.

## Portability Consequences

None. No implementation is introduced. The decision is written to be
consistent with existing Platform Independence requirements (Constitution
§13–14) so it does not need revision when a future OurOS adapter replaces the
Linux adapter.

## Migration Consequences

When Phase 9 work begins, the decisions in this ADR become mandatory inputs
to that phase's Build list and Exit Gate in the Project Execution Contract,
specifically the always-confirm action list (Decision 4) and the sandboxing
requirements (Decision 2). Any change to this ADR's decisions requires a
superseding ADR, not a silent edit to this file or to the Contract.
