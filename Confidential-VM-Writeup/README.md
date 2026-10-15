---
title: "The Confidential Computing Promise — Where SEV-SNP, TDX, and CCA Break"
author: Tyler
date: 2026-05-17
register: research / anatomical / structural
portfolio: HBO NL low-level security
cluster: Microarch-Isolation (sibling); extends TEE chapter into the CC era
license: CC BY 4.0
status: survey
---

# The Confidential Computing Promise — Where SEV-SNP, TDX, and CCA Break

## Author's Note

Confidential Computing markets the strongest isolation guarantee in
commercial hardware. The pitch is unambiguous: a tenant workload runs
inside a virtual machine whose memory, register state, and attested
identity are opaque even to the cloud operator that owns the silicon.
The hypervisor schedules. The hypervisor allocates. The hypervisor
sees ciphertext. The vendor publishes whitepapers, the standards
bodies publish architecture specifications, and the marketing surface
of the three major implementations — AMD SEV-SNP, Intel TDX, ARM CCA —
converges on a single sentence: *the untrusted host cannot read
enclave state*.

This writeup reads where that promise meets the silicon's reality. It
is the wide survey companion to Microarch-Isolation, which already
covered the TEE generation that preceded this one (SGX, TrustZone) and
established the structural argument that "trust boundaries are
architectural objects" rather than physical facts. Confidential
Computing inherits that genealogy. It also inherits, with refinements,
the same failure modes — and adds new ones unique to the VM-scale
threat model: a Reverse Map Table that protects pages but not
register context, a Platform Security Processor that signs attestation
quotes but is itself firmware, a Trust Domain Extensions design that
encrypts memory but leaves cache coherency under hostile control.

The point of this document is not advocacy. The CC architectures are
genuinely stronger than their SGX-era predecessors along several axes:
they cover the full VM (not just an enclave), they protect against
DMA-class read attacks, they support remote attestation that does not
require Intel as a network-attached oracle. These are real
improvements. The point is that *the promise statement marketed to
tenants is not the property the silicon implements*. Specifically:

  1. **Memory is encrypted; semantics are not.** SEV-SNP's RMP
     protects page ownership, not register state, not stack
     coherency, not control-flow metadata. StackWarp demonstrates
     that the hypervisor can corrupt RSP across a VMEXIT and the
     guest will continue using a manipulated control object.

  2. **Confidentiality is not integrity.** SEV originally shipped
     without memory integrity protection. SEV-ES added register
     encryption. SEV-SNP added the RMP. Each generation closed a
     class of attacks that had already been published against the
     previous one. The pattern is reactive.

  3. **Cache state is part of execution state.** CacheWarp shows
     that INVD — an instruction that exists for low-level platform
     bring-up, not for security — gives the hypervisor a primitive
     to roll back dirty cache lines without writeback. The
     ciphertext in memory was never touched. The attack proceeds
     beneath the encryption layer.

  4. **Interrupts are an injection channel.** WeSee and Heckler
     demonstrate that the hypervisor's authority to deliver
     interrupts to the guest is not a side effect of virtualization
     — it is a control plane that the CC threat model failed to
     close. The guest handles whatever interrupt arrives; the
     hypervisor chooses which interrupts arrive.

  5. **DRAM is shared physical reality.** HyperPill and the Rowhammer
     family operate beneath every architectural abstraction in this
     stack. Memory encryption changes the ciphertext but not the
     analog susceptibility of the substrate. A bit flip in encrypted
     memory is a structured corruption of decrypted state.

  6. **Attestation is a key hierarchy rooted in a chip.** The PSP on
     AMD, the SEAM module on Intel, the RMM on ARM — these are
     firmware. The attestation quote is only as trustworthy as the
     firmware that signs it. The CVE history of the PSP firmware
     alone (CVE-2021-26311, CVE-2023-20598, etc.) is the record of
     a moving target.

The register is anatomical. There is no defense recommendation here,
no threat advisory, no posture. This is a structural map of what the
three architectures actually do, what they actually defend against,
and where the published attacks have shown them yielding. The
citations are real and load-bearing; the architecture diagrams follow
the vendor specifications; the CVEs are referenced by number and
venue.

A note on tone: the same register that governed Microarch-Isolation
governs this document. The silicon does not implement boundaries — it
implements a single shared microarchitectural fabric on which
boundaries are an *interpretation*. Confidential Computing is the
most ambitious interpretation in commercial use. Like every
interpretation, it can be read against the substrate, and where it
fails to project the property it claims, the failure has a name and a
CVE number.

This document collects those names.

---

## Abstract

Confidential Computing (CC) extends the trusted execution environment
(TEE) paradigm from per-process enclaves (SGX, TrustZone) to the
virtual-machine scale. The three commercial implementations — AMD
Secure Encrypted Virtualization with Secure Nested Paging (SEV-SNP),
Intel Trust Domain Extensions (TDX), and ARM Confidential Compute
Architecture (CCA) — share a common contract: an untrusted hypervisor
cannot read the encrypted guest's memory, cannot inspect its
register state at VMEXIT, and cannot forge an attestation quote. The
contract is implemented through per-VM memory encryption keys held
in dedicated security processors, integrity-protecting page-table
metadata (RMP, SEPT, RTT), and attestation chains rooted in
vendor-controlled hardware keys.

This survey reads the contract against the published attack
literature: CacheWarp (USENIX Security 2024) on SEV-ES/SNP, StackWarp
on register-state integrity, WeSee and Heckler on interrupt
injection, HyperPill on hypervisor MMIO emulation, and the
Rowhammer-class DRAM substrate attacks (HyperHammer, CVE-2024-50264
adjacent classes) that operate beneath every architectural
abstraction. The pattern is structural: the silicon implements
memory protection through cryptographic primitives layered on a
shared DRAM and cache fabric whose coherency, timing, and analog
properties the encryption does not cover. The contract is what the
vendors promise; the substrate is what the attackers reach.

We map the three architectures component by component, locate each
published attack in the layer it breaks, and identify open research
questions for the next generation of CC silicon (post-quantum
attestation, formal models of the RMM/SEAM monitor, cross-vendor
attestation portability).

---

## §1 — What CC Promises

### 1.1 The Contract Statement

Every major CC architecture publishes a near-identical contract.
Restated in vendor-neutral form:

> Given an adversary with full administrative control of the
> hypervisor, the cloud operator's BMC and out-of-band management,
> any DMA-capable peripheral, and the ability to take a memory dump
> of the physical RAM backing the guest, the adversary cannot
> recover plaintext guest data, cannot forge a remote-attestation
> quote, and cannot tamper with guest execution undetected.

The contract has three quantifiable subclauses:

  C1. **Confidentiality**: physical RAM contents are
      cryptographically opaque without the per-guest key, which is
      never resident in software outside the trusted security
      processor.

  C2. **Integrity**: page-level remapping, replay, or content
      modification by the hypervisor is detected by the guest
      (RMP for SNP; SEPT for TDX; RTT for CCA).

  C3. **Attestation**: the guest can produce a signed report
      binding its measured launch state to a chain that terminates
      in a vendor-controlled root certificate, allowing a remote
      party to verify the configuration before sending secrets.

The contract is *negative*. It enumerates what the host cannot do.
It does not enumerate what the host *can* do — and it is in the
unenumerated remainder that the published attacks operate.

### 1.2 Hardware Root of Trust

The root of trust in every CC architecture is a dedicated
hardware security processor:

```
┌─────────────────────────────────────────────────────────┐
│                  HARDWARE ROOT OF TRUST                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  AMD SEV-SNP:  Platform Security Processor (PSP)         │
│                ARM Cortex-A5 on-die, separate from x86   │
│                Runs vendor-signed firmware               │
│                Holds VEK (VM Encryption Key) hierarchy   │
│                                                          │
│  Intel TDX:    Trust Domain eXtended Module (TDX Module) │
│                Runs in SEAM (Secure Arbitration Mode)    │
│                Loaded by ACM (Authenticated Code Module) │
│                Holds TD ephemeral keys                   │
│                                                          │
│  ARM CCA:      Realm Management Monitor (RMM)            │
│                Runs at EL2 in the Realm world            │
│                Mediates Realm VM lifecycle               │
│                Backed by RME hardware extensions         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

Each of these is a *firmware* entity. The trust chain delegates to
software running on hardware that the vendor signs. The hardware
does not implement the security policy directly — it implements the
primitives (memory encryption engines, page-table integrity
metadata, key derivation) and trusts the firmware to use them
correctly.

### 1.3 Attested Boot

The launch sequence for a CC guest is the moment the contract is
established. In schematic form:

```
[1] Hypervisor requests guest creation, supplies image hash.
[2] Security processor (PSP/TDX-Module/RMM) measures launch:
        H_launch = SHA-384(VM image, vCPU config, policy)
[3] Per-guest encryption key K_VM derived from vendor key
        and H_launch.
[4] Guest memory pages encrypted with K_VM on write.
[5] Guest measures itself (optional) and requests attestation.
[6] Security processor produces signed report:
        Report = Sign_{VEK}(H_launch || nonce || policy)
[7] Remote verifier checks signature chain back to vendor root.
[8] Verifier sends secrets only after Report verifies.
```

The integrity of step [2] (measurement) and step [6] (signing) are
the load-bearing operations. If H_launch is computed over the wrong
bytes, or if the signing key is recoverable, the entire chain
collapses.

### 1.4 What CC Does *Not* Promise

The literature consistently underspecifies the negative space of
the contract. Vendor whitepapers focus on what is protected; they
spend less time on what is not. The non-promises are:

  - **Side channels are not covered**: timing, cache occupancy,
    branch predictor state, power consumption, and electromagnetic
    emissions remain observable to a co-resident attacker. The CC
    threat model in vendor documentation typically scopes "physical
    attacks excluding chip decap" and "logical attacks on memory
    content" — leaving microarchitectural side channels in a
    deliberate gap.

  - **Availability is not protected**: the hypervisor can refuse to
    schedule the guest, can deny it I/O, can crash it on demand.
    CC protects *what the guest does* not *whether it runs*.

  - **Bug-class containment is not promised**: a memory-safety bug
    in the guest is still exploitable. CC moves the perimeter; it
    does not eliminate the interior attack surface.

  - **Pre-launch supply chain is not addressed**: the guest image
    is measured, but the measurement covers the image as supplied
    — if the supply chain delivered a backdoored image, CC will
    attest to the backdoor faithfully.

  - **Microcode trust is delegated**: the security processor runs
    firmware; the CPU runs microcode; both are vendor-signed. The
    chain has a single root, and revoking that root is a process
    measured in years.

### 1.5 The Assumption Invalidated

The CC contract assumes that *the boundary between guest and
hypervisor can be made cryptographic*. The contract is implemented
by cryptographic primitives operating on a shared substrate that is
not cryptographic — DRAM cells, cache lines, interrupt delivery
paths, page-walk machinery. Every attack in this survey exploits a
substrate element that the cryptographic layer does not project
onto. The assumption invalidated is that the layering is complete.

---

## §2 — The Three Architectures

### 2.1 AMD SEV-SNP

**Lineage**: SEV (2016) → SEV-ES (2017) → SEV-SNP (2020).

SEV's original design encrypted guest memory pages under a per-VM
key (AES-128-XEX) held in the PSP. The hypervisor could schedule,
exit, restore, and dump guest memory — but the dump was
ciphertext. SEV-ES added Encrypted State: register values at
VMEXIT were also encrypted, preventing the hypervisor from reading
or modifying guest CPU state in the VMCB save area. SEV-SNP added
the Reverse Map Table (RMP), a per-physical-page metadata
structure enforcing ownership, validation state, and immutability
flags.

```
SEV-SNP Component Map:

┌──────────────────────────────────────────────────────────┐
│                    AMD SEV-SNP                            │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  Platform Security Processor (PSP)                       │
│    ├── ARM Cortex-A5 core, on-die                        │
│    ├── Runs PSP firmware (vendor signed)                 │
│    ├── Generates per-VM key K_VM                         │
│    ├── Signs attestation reports with VEK                │
│    └── Manages VEK / VLEK / ARK / ASK hierarchy          │
│                                                           │
│  Memory Encryption Engine (AES-128-XEX)                  │
│    ├── On-die inline with memory controller              │
│    ├── Per-page tweak derived from physical address      │
│    └── Encrypts/decrypts on DRAM read/write              │
│                                                           │
│  Reverse Map Table (RMP)                                 │
│    ├── 16 bytes per 4KiB physical page                   │
│    ├── Fields: Assigned, Validated, GPA, ASID, Immutable │
│    └── Checked on every nested-page-table walk           │
│                                                           │
│  Virtual Machine Save Area (VMSA)                        │
│    ├── Encrypted CPU state on VMEXIT                     │
│    ├── Replaces the unencrypted VMCB state save area     │
│    └── Integrity-protected via VMSA hash                 │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

The RMP is the load-bearing addition. Without integrity protection,
SEV was vulnerable to memory remapping attacks (e.g., SEVurity,
CVE-2019-9836-class). With the RMP, the hypervisor cannot point a
guest physical address (GPA) at a host physical page it does not
own, and cannot remap a page it has already given to the guest.

The PSP is the policy enforcement point. It runs firmware that the
guest must trust — and the guest does trust it, because the
attestation chain terminates in a key the PSP holds. The PSP is
itself the subject of a multi-year CVE record (CVE-2020-12890,
CVE-2021-26311, CVE-2023-20598, et al.) covering vulnerabilities
in its firmware, its update mechanism, and the off-die SPI flash
that holds its boot image.

### 2.2 Intel TDX

**Lineage**: SGX (2015) → TDX (announced 2020, shipping 2023).

TDX moves the SGX threat model from per-process enclaves to per-VM
Trust Domains. The crucial architectural shift is the introduction
of a new CPU mode: **SEAM (Secure Arbitration Mode)**. The TDX
Module — Intel-signed software — runs in SEAM and mediates all
transitions between the host VMM and the Trust Domain (TD) guest.

```
TDX Component Map:

┌──────────────────────────────────────────────────────────┐
│                    Intel TDX                              │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  TDX Module (runs in SEAM)                               │
│    ├── Intel-signed software (not microcode)             │
│    ├── Loaded by Authenticated Code Module at boot       │
│    ├── Mediates SEAMCALL / TDCALL interface              │
│    └── Holds TD private keys, manages TD lifecycle       │
│                                                           │
│  Multi-Key Total Memory Encryption (MKTME)               │
│    ├── AES-128-XTS, multiple keys                        │
│    ├── KeyID embedded in physical address upper bits     │
│    └── TD memory tagged with TD-specific KeyID           │
│                                                           │
│  Secure Extended Page Table (SEPT)                       │
│    ├── Owned by TDX Module, not by host VMM              │
│    ├── Maps TD GPA → HPA                                 │
│    └── Host VMM cannot directly modify SEPT entries      │
│                                                           │
│  TD Virtual Machine Control Structure                    │
│    ├── TDVMCS — TD-specific subset of VMCS               │
│    ├── Sensitive fields opaque to host                   │
│    └── Managed by TDX Module on transitions              │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

TDX's separation of duty differs from SEV-SNP. Where SEV-SNP keeps
the integrity check in hardware (RMP walks happen in the page-walk
engine), TDX places the check in software (the TDX Module) running
in a privileged hardware mode (SEAM). Both designs reduce the
trusted code base; TDX makes more of it Intel-controlled software
and less of it microcode-fixed silicon.

The attestation chain in TDX inherits from SGX's DCAP (Data Center
Attestation Primitives). The TD produces a TDREPORT containing its
launch measurement (MRTD), policy, and a nonce; the Quoting
Enclave (an SGX enclave, in a slightly awkward layering) signs the
report into a quote using a key provisioned by Intel.

### 2.3 ARM CCA

**Lineage**: TrustZone (2003) → Confidential Compute Architecture
(announced 2021, shipping in Armv9-A platforms).

ARM CCA introduces a fourth world to the existing Secure/Non-Secure
TrustZone partition: the **Realm world**. Realm VMs run at EL1
under a Realm Management Monitor (RMM) at EL2; the Secure Monitor
at EL3 routes between worlds.

```
CCA Component Map:

┌──────────────────────────────────────────────────────────┐
│                    ARM CCA                                │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  Worlds:                                                  │
│    ┌─────────────┬─────────────┬─────────────┐           │
│    │ Non-Secure  │   Secure    │   Realm     │           │
│    │  (Normal)   │ (TrustZone) │  (CCA new)  │           │
│    └─────────────┴─────────────┴─────────────┘           │
│                                                           │
│  Realm Management Monitor (RMM)                           │
│    ├── Runs at EL2 in Realm world                         │
│    ├── ARM-specified, open reference implementation       │
│    ├── Mediates Realm VM lifecycle (RMI interface)        │
│    └── Issues attestation tokens via RMM_REALM_RESETVECT  │
│                                                           │
│  Granule Protection Table (GPT)                           │
│    ├── Per-page world assignment (NS/S/Realm/Root)        │
│    ├── Enforced by Granule Protection Check (GPC) in MMU  │
│    └── Cross-world access produces GPF (granule fault)    │
│                                                           │
│  Realm Translation Table (RTT)                            │
│    ├── Realm VM's stage-2 translation, RMM-owned          │
│    ├── Memory encryption tied to Realm key                │
│    └── Host hypervisor cannot directly modify             │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

CCA's architectural distinction is that it specifies the monitor
software (RMM) as an open reference rather than vendor-confidential
firmware. This is a deliberate response to the criticism of
SEV-SNP's PSP firmware and TDX's closed-source TDX Module: the
RMM specification is published, and silicon vendors implementing
CCA are expected to ship the reference RMM or a verified
equivalent.

The Granule Protection Table (GPT) is the integrity primitive
analogous to the RMP. Each physical granule (4KiB or larger) is
tagged with a world assignment; the MMU's Granule Protection
Check (GPC) enforces that an access from world X to a granule
tagged Y produces a granule protection fault unless X == Y or X
is privileged over Y.

### 2.4 Comparative Table

| Property | SEV-SNP | TDX | CCA |
|---|---|---|---|
| Year shipped | 2020 | 2023 | 2024+ |
| Monitor location | PSP (off-core ARM) | SEAM (CPU mode) | RMM (EL2 in Realm) |
| Monitor visibility | Closed firmware | Closed software | Open reference |
| Memory encryption | AES-128-XEX per VM | AES-128-XTS, MKTME | Realm-tied, impl. defined |
| Page integrity table | RMP | SEPT | RTT + GPT |
| Register protection | VMSA (encrypted) | TDVMCS (opaque) | RMM-mediated |
| Attestation root | VEK (PSP) | TDX Quote (DCAP) | RIM (RMM-signed) |
| Cross-vendor portability | No | No | Spec-level yes |

### 2.5 The Assumption Invalidated

§2's invalidated assumption is *that the three architectures
implement comparable security properties*. They do not. They share
a contract surface — the marketing pitch is interchangeable — but
the trusted code bases, the integrity primitives, the attestation
chains, and the failure modes are distinct. A workload that
verifies against an SEV-SNP attestation does not have a portable
guarantee on TDX or CCA. The vendor-portable abstraction does not
exist.

---

## §3 — Memory Encryption

### 3.1 The Encryption Engine

All three architectures place memory encryption inline with the
memory controller. The encryption is transparent to the CPU's view
of cache and registers: plaintext lives in the cache; ciphertext
lives in DRAM. The boundary is the L2/L3-to-DRAM transition.

```
       CPU Core
          │
          │   plaintext
          ▼
     ┌─────────┐
     │  Cache  │   plaintext lives here
     │ (L1/L2) │
     │   L3    │
     └────┬────┘
          │   plaintext on cache fill / dirty writeback
          ▼
     ┌─────────────────┐
     │ Memory Encryption│   encrypts on write, decrypts on read
     │     Engine       │   per-page key+tweak from PSP/TDX/RMM
     └────┬─────────────┘
          │   ciphertext
          ▼
        DRAM
```

SEV-SNP uses AES-128 in XEX (XOR-Encrypt-XOR) mode, with the tweak
derived from the physical address. TDX uses AES-128-XTS as part of
MKTME, where the KeyID is embedded in the physical address; the
memory controller selects the key by KeyID. CCA specifies the
property (per-Realm encryption) and leaves the mode to the silicon
implementation.

The encryption is per-page (4KiB granularity) and the keys are
ephemeral per-VM lifetime. On VM teardown the key is destroyed and
the ciphertext in DRAM becomes unrecoverable without it.

### 3.2 Integrity Protection

SEV-ES had no memory integrity. SEV's original threat model
distinguished read-confidentiality from write-integrity, and only
the former was protected. This left the architecture vulnerable to
remap attacks (the hypervisor changes the GPA→HPA mapping
underneath the guest, swapping in a page from a different guest or
from a stale dump) and to replay attacks (the hypervisor restores
a previously-captured ciphertext, rolling back guest state).

SEV-SNP closed this with the RMP. The RMP is consulted on every
nested-page-table walk:

```
Guest virtual address
       │
       ▼ Guest Page Table (CR3-rooted)
Guest physical address (GPA)
       │
       ▼ Nested Page Table (NPT, hypervisor-controlled)
Host physical address (HPA)
       │
       ▼ RMP entry for HPA (read-only to hypervisor)
       │   ├─ Assigned bit: page belongs to a guest?
       │   ├─ Validated bit: guest has accepted ownership?
       │   ├─ GPA field: expected guest physical address
       │   ├─ ASID field: which guest owns the page
       │   └─ Immutable bit: page cannot be reassigned
       ▼
Access granted only if RMP[HPA].GPA == observed GPA
                 AND  RMP[HPA].ASID == current guest ASID
                 AND  RMP[HPA].Validated == 1
```

TDX implements analogous semantics through the SEPT. The host VMM
cannot directly modify SEPT entries; it must call into the TDX
Module via SEAMCALL to request page management operations, and
the module enforces invariants on each transition.

CCA implements integrity through the GPT (per-granule world
assignment) and the RTT (per-Realm stage-2 translation, RMM-owned).
The combination provides both ownership tracking and translation
integrity.

### 3.3 Page-Table Protection

The host VMM still owns the nested page tables in all three
architectures — it must, because virtualizing memory management is
its core function. The integrity layer (RMP/SEPT/RTT) does not
prevent the VMM from constructing arbitrary page tables; it
prevents those page tables from producing valid translations when
they conflict with the integrity metadata.

This separation is essential. If the integrity layer required the
VMM to give up page-table management, the hypervisor would lose
the ability to overcommit memory, page-out cold pages, or
rebalance NUMA placement. The CC architectures preserve these
operations while *constraining their outcome*: the VMM can swap
pages, but it cannot swap them in a way the integrity layer
accepts as valid.

### 3.4 What Survives a Memory Dump

A cold memory dump of a CC-protected host yields:

  - Ciphertext for guest pages (cryptographically opaque without
    the per-VM key).
  - Plaintext for hypervisor pages and shared-memory regions
    (these were never encrypted under a guest key).
  - The RMP / SEPT / GPT metadata (these are not encrypted; they
    are integrity-protected against modification but readable).
  - Cache state is lost on power-down (the DRAM dump does not
    capture the L1/L2/L3 contents).

The integrity tables leak structural information — the dump shows
which physical pages belong to which guest, which are immutable,
which are shared. This is metadata leakage; the cryptographic
content is preserved.

### 3.5 The Assumption Invalidated

§3's invalidated assumption is *that memory encryption protects
guest state*. Encryption protects the *bits in DRAM*. It does not
protect the *semantics those bits represent at the cache layer
above DRAM, at the register layer above the cache, or at the
control-flow layer above the registers*. CacheWarp (§4) operates
at the cache layer; StackWarp operates at the register layer;
WeSee/Heckler operate at the control-flow layer. None of them
breaks the encryption. All of them break the guarantee.

---

## §4 — The Attack Family

This section maps the published attacks against CC architectures,
locating each in the layer of the stack it breaks. The pattern is
that the attacks cluster *above* the encryption layer (cache,
registers, interrupts) and *below* it (DRAM analog, firmware) —
the encryption itself is mathematically sound, but it does not
isolate the operations on either side of the boundary it draws.

### 4.1 CacheWarp — Cache State as Attack Surface

**Citation**: Zhang, Gerlach, Weber, Hetterich, Lü, Kogler,
Schwarz. *CacheWarp: Software-based Fault Injection using Selective
State Reset*. USENIX Security 2024. CVE-2023-20592.

**Affected**: AMD SEV-ES, AMD SEV-SNP (Zen 2/3 epoch EPYC,
specifically EPYC 7252, 7313P, 7443 at publication).

**Root cause**: The `INVD` instruction invalidates cache lines
without writing back dirty data to memory. INVD is intended for
low-level platform initialization (firmware bring-up) and is not
expected to be useful for general system software. AMD's
virtualization extension exposed INVD to the hypervisor with
sufficient privilege that it could be executed against a guest's
cache footprint without the guest's knowledge.

**Mechanism**:

```
Step 0:  Guest writes a value to a memory location.
         Cache line is marked dirty; DRAM still holds previous value.

Step 1:  Hypervisor causes a VMEXIT (e.g., by clearing the present
         bit on the relevant guest page).

Step 2:  Hypervisor executes INVD.
         All dirty cache lines on the core are invalidated WITHOUT
         writeback. DRAM is unchanged.

Step 3:  Hypervisor resumes the guest.

Step 4:  Guest reads the location it had written.
         Cache miss → fetch from DRAM → reads the STALE pre-write
         value. The guest's own write has vanished.
```

CacheWarp does not break SEV-SNP's encryption. The DRAM ciphertext
is not touched. The attack operates entirely on the cache
coherency protocol, which is not part of the encrypted state. The
RMP, the VMSA encryption, the attestation chain — all of these
remain valid. The attack succeeds *because the guarantee was about
memory content, not cache content*.

The published case studies in the original paper:

  - **RSA private-key recovery** from Intel IPP Crypto's sliding-
    window exponentiation, by observing which intermediate
    results were recomputed after a cache rollback.

  - **OpenSSH authentication bypass**: rolling back the result of
    `verify_password()` so the guest reads a stale `result = 1`
    from DRAM (where the hypervisor had written 1 before the
    guest's actual computation), and continues into
    `grant_access()`.

  - **sudo privilege escalation**: rolling back the
    `check_sudoers()` return value to grant root.

The detection problem is severe. From the guest's perspective,
nothing is wrong: the read returns a value that *was* written to
memory at some point in the past. There is no integrity failure,
no exception, no signal. The execution-state-determinism literature
(EXTp-class instrumentation) can detect the divergence but cannot
attribute it: cache state is not part of the snapshot.

### 4.2 StackWarp — Register State Manipulation

**Affected**: AMD SEV-SNP (architectural).

**Root cause**: SEV-SNP's VMSA encrypts CPU register state at
VMEXIT, but the integrity protection covers the *bundle* of
register state, not individual semantic fields. More precisely:
the stack pointer (RSP) is a register the architecture treats as
*compiler-trusted*. The hardware does not check that RSP points
into a valid stack region; the compiler-generated code assumes it
does.

In the SEV-SNP threat model, the VMSA prevents the hypervisor
from reading or writing individual register fields freely — but
the architectural surface still includes paths where the
hypervisor can influence the guest's RSP without violating any
checked invariant. Specifically: the hypervisor injects an
exception or interrupt; the guest's exception handler executes;
the handler reads or modifies stack state; the post-handler RSP
reflects the manipulation.

**Mechanism (one form)**:

```
[1] Guest executing with RSP = 0x7fff_0000.
[2] Hypervisor injects #PF or #UD at a chosen RIP.
[3] Guest pushes return frame, exception state to stack.
    RSP -= frame size.
[4] Hypervisor manipulates the page mapping under the new RSP
    region so the pushed values are observed/altered, or arranges
    for the handler to return through a manipulated frame.
[5] Guest resumes with corrupted control-flow metadata.
[6] RMP did not fire — the page accesses were to guest-owned
    pages with valid GPA/ASID mappings. The metadata that was
    corrupted (return addresses, saved RBP) is semantic, not
    architectural.
```

The structural insight is that **SEV-SNP protects pages, not
semantics**. The RMP confirms that a 4KiB physical page is owned
by guest G and mapped at the expected GPA. It does not confirm
that the bytes at offset X within that page are a return address
that was placed there by a legitimate `call` instruction.

The hypervisor's authority to inject exceptions, to deny or
delay page mappings, and to schedule VMEXITs gives it a rich set
of primitives for indirect control-flow influence even when the
direct register-write path is blocked by VMSA encryption.

### 4.3 WeSee and Heckler — Interrupt Injection

**Citations**:
  - Schlüter, Sridhara, Bertschi, Shinde. *WeSee: Using Malicious
    #VC Interrupts to Break AMD SEV-SNP*. USENIX Security 2024.
  - Schlüter, Sridhara, Kuhne, Bertschi, Shinde. *Heckler:
    Breaking Confidential VMs with Malicious Interrupts*. USENIX
    Security 2024.

**Affected**: AMD SEV-SNP (Heckler also relevant to TDX).

**Root cause**: The hypervisor in a CC architecture retains the
ability to inject interrupts into the guest. This is necessary
for virtualization — the guest must receive timer ticks, I/O
completion notifications, IPIs. The interrupt vector and timing
are under hypervisor control. The guest's interrupt handler
table is in guest memory; the handler runs in guest context.
The hypervisor chooses *which* handler to invoke and *when*.

**WeSee** exploits the #VC (VMM Communication Exception) handler
that SEV-SNP guests use to mediate operations requiring host
cooperation (e.g., MMIO accesses to virtual devices). By
injecting an unexpected #VC at a chosen RIP, the hypervisor can
cause the guest's #VC handler to run on an attacker-influenced
register state, achieving primitives equivalent to register
manipulation (the handler reads what the hypervisor placed in
the GHCB — Guest-Host Communication Block).

**Heckler** generalizes the pattern: any interrupt vector that
the hypervisor can deliver, and whose handler in the guest does
not properly validate the context, becomes an attack primitive.
The paper demonstrates authentication bypasses and arbitrary
read/write primitives by injecting interrupts at carefully
chosen RIPs in benign workloads.

**Mechanism (Heckler form)**:

```
[1] Hypervisor profiles guest with timing/page-fault sequence to
    locate a callable handler that performs an interesting
    side-effect (e.g., signal handler for SIGALRM that adjusts a
    user-space variable).
[2] Hypervisor arranges guest execution to reach a RIP where the
    handler will run with attacker-influenced register state
    (e.g., right after a system call that left chosen values in
    RDX, RDI).
[3] Hypervisor injects the corresponding interrupt vector via
    VMCB EVENTINJ.
[4] Guest's handler runs; reads its argument from the registers
    or from the GHCB; performs its side-effect with the wrong
    operand.
[5] The architectural state of the handler is what the handler
    "should" do given those operands. The fact that the operands
    are attacker-chosen is not visible to the handler.
```

The structural insight is that **the interrupt delivery channel
is a control surface, not just a notification mechanism**. The
CC architectures inherited the VMX/SVM interrupt-injection
machinery from the prior virtualization generation, where it was
considered acceptable because the hypervisor was trusted. The
trust assumption was inverted; the interface was not redesigned.

### 4.4 HyperPill — Hypervisor Fuzzing as Cross-Boundary Attack

**Citation**: Bulekov et al. *HyperPill: Fuzzing for Hypervisor-
bug Hunting*. USENIX Security 2024.

**Affected**: All x86 hypervisors (QEMU/KVM, Hyper-V). Indirect
relevance to CC: a successful hypervisor compromise neutralizes
the CC contract entirely, because the contract assumes the
hypervisor is *untrusted but contained*. If the hypervisor is
compromised by a guest, the attacker is now in the host with the
host's authority over CC operations.

**Mechanism**: HyperPill uses nested virtualization to inspect
the target hypervisor's EPT (Extended Page Table) walk from L0,
identifying GPA ranges that the L1 hypervisor handles as MMIO
(producing VM-Exit on access). These MMIO regions are the
hypervisor's emulation surface. HyperPill then fuzzes
read/write/size combinations against these ranges with snapshot-
restore semantics for coverage feedback.

The relevance to CC is bidirectional:

  - **Offensively**: a hypervisor bug found by HyperPill-class
    fuzzing gives the attacker host-level execution. From there,
    CC's defenses depend on the silicon and firmware (PSP, TDX
    Module, RMM) — the hypervisor compromise does not directly
    break the encryption, but it gives the attacker a stable
    platform to mount the other attacks in this family
    (CacheWarp, StackWarp, interrupt injection).

  - **Defensively**: CC's value proposition assumes the
    hypervisor *will* eventually be compromised, and that the
    guest's secrets survive that compromise. HyperPill is
    evidence that the assumption is operationally credible —
    hypervisor bugs of exploitable severity continue to be
    discovered at a steady rate.

### 4.5 HyperHammer — Cross-Boundary DRAM Attacks

**Affected**: All architectures using susceptible DRAM (DDR4
without TRR, DDR5 with weak refresh management). CVE-2024-50264
is a Linux-kernel UAF in vsock that, in the context of this
survey, is illustrative of how a hypervisor-side bug compounds
with a substrate-level DRAM attack to produce a cross-boundary
primitive.

**Mechanism**: Rowhammer-class attacks induce bit flips in DRAM
cells by rapidly activating adjacent rows. The bit flips appear
in physical memory regardless of the logical owner of the page.
In a CC context:

```
Adjacent guest pages in DRAM:
  Row N:   Guest A's encrypted page (target)
  Row N+1: Attacker-controlled (co-tenant guest or host)
  Row N-1: Attacker-controlled

Attacker hammers rows N-1 and N+1.
Row N's bit cells experience charge leakage.
A bit flips in Row N's ciphertext.
Guest A reads from Row N → decryption returns altered plaintext
   (the encryption mode determines the structure of the alteration).
```

The encryption mode matters. SEV's AES-XEX produces structured
single-bit-flip propagation; TDX's AES-XTS produces broader
plaintext corruption per flipped ciphertext bit. Neither prevents
the flip from occurring or from being decrypted; both *guarantee*
that the guest will observe a corrupted plaintext value if the
ciphertext is hammered.

CCA's specification leaves the encryption mode to the
implementation; CCA implementations using authenticated
encryption (AES-GCM or equivalent) would detect the corruption
on decryption, but the spec does not mandate this and current
implementations have not committed to authenticated modes for
performance reasons.

### 4.6 The Attack Family Map

```
                  ┌──────────────────────────────────────┐
                  │       The CC Trust Boundary           │
                  │                                       │
   Above:         │    Cache state    ←─ CacheWarp        │
   (semantic      │    Register state ←─ StackWarp        │
    layers        │    Control flow   ←─ WeSee / Heckler  │
    not covered   │                                       │
    by mem-enc)   │                                       │
                  │                                       │
                  ├─── Memory encryption (intact) ────────┤
                  │                                       │
   Below:         │    DRAM physics   ←─ HyperHammer      │
   (substrate     │    PSP firmware   ←─ PSP CVEs         │
    not covered   │    Hypervisor     ←─ HyperPill        │
    by enc)       │                                       │
                  └──────────────────────────────────────┘
```

### 4.7 The Assumption Invalidated

§4's invalidated assumption is *that the published attacks are
unrelated incidents that will be fixed individually*. They are
related by the structural property that every CC architecture
implements its security contract through a single mechanism
(memory encryption + page-table integrity) operating on a
substrate with many other channels. Each attack identifies a
channel the encryption does not cover. The list will continue to
grow as new channels are identified; the architecture as
designed does not have a way to close the list.

---

## §5 — The Attestation Chain

### 5.1 AMD's VEK Key Hierarchy

The SEV-SNP attestation chain has a multi-level key hierarchy
rooted in AMD's signing infrastructure:

```
AMD Root Key (ARK)
   │
   │  AMD signs at silicon manufacture, ships with platform
   ▼
AMD Signing Key (ASK)
   │
   │  Per-product-line signing key, AMD-controlled
   ▼
Versioned Chip Endorsement Key (VCEK) or
Versioned Loaded Endorsement Key (VLEK)
   │
   │  Per-chip key derived from chip secret + TCB version
   │  VCEK = original variant (bound to specific chip)
   │  VLEK = added later for cloud operators to scope keys
   ▼
Attestation Report Signing Key (effectively VCEK/VLEK directly)
   │
   ▼
Attestation Report
   ├── H_launch (guest measurement)
   ├── Policy bits (debug enabled, migration allowed, ...)
   ├── TCB version
   ├── Nonce (caller-supplied)
   └── Signature
```

The chain is verified by:

  1. Verifier obtains VCEK/VLEK certificate from AMD's KDS (Key
     Distribution Service) over HTTPS, indexed by chip ID and
     TCB version.
  2. Verifier checks ARK → ASK → VCEK certificate chain against
     AMD's published root.
  3. Verifier checks the attestation report signature with the
     VCEK public key.
  4. Verifier compares H_launch against expected measurement.
  5. Verifier checks TCB version meets minimum policy.
  6. Verifier sends secrets if all checks pass.

The trust assumptions in this chain:

  - AMD's root signing key is not compromised.
  - AMD's KDS is reachable and not compromised.
  - The PSP firmware that derived VCEK from the chip secret is
    not vulnerable.
  - The TCB version field accurately reflects the running
    firmware.

Each of these is a non-trivial assumption. The PSP firmware in
particular has accumulated a CVE record (CVE-2020-12890,
CVE-2021-26311, CVE-2023-20598, CVE-2024-21972) where bugs in
firmware versions reported by valid TCB versions allowed key
extraction or attestation forgery.

### 5.2 Intel's TDX Quote Chain

TDX inherits SGX's DCAP attestation, with adaptations:

```
Intel Root Key (in HSM at Intel)
   │
   ▼
Provisioning Certification Key (PCK)
   │
   │  Per-platform key from Intel's provisioning service
   ▼
Quoting Enclave Identity Key
   │
   │  Held by Intel-signed Quoting Enclave (an SGX enclave)
   ▼
TDX Quote
   ├── TDREPORT (TD self-measurement)
   │   ├── MRTD (initial measurement)
   │   ├── RTMR[0..3] (runtime measurements)
   │   ├── REPORTDATA (caller-supplied)
   │   └── Local report MAC
   ├── Quote header (PCK identification)
   └── Quote signature
```

The TDX Module produces a TDREPORT — a locally-MAC'd report
verifiable on the same platform. To produce a remotely-
verifiable quote, the TDREPORT is sent to the Quoting Enclave
(running in SGX), which re-signs it with its identity key.

The structural quirk is that TDX attestation is *anchored in
SGX*. Compromise of the SGX Quoting Enclave's identity key —
through future SGX attacks, side channels, or implementation
bugs — would propagate into TDX attestation. The Quoting
Enclave is updated via Intel's TCB recovery process; the
recovery process has its own latency and failure modes.

### 5.3 ARM CCA's Realm Attestation

CCA attestation produces a **Realm Initial Measurement (RIM)**
during Realm creation, accumulating into a **Realm Extensible
Measurement (REM)** as the Realm executes:

```
Platform Attestation Key (PAK)
   │
   │  Per-platform, provisioned by silicon vendor
   ▼
Realm Attestation Key (RAK)
   │
   │  Per-Realm, derived by RMM
   ▼
Attestation Token
   ├── Platform claims (CCA platform identity)
   ├── Realm claims (RIM, REM[0..N], personalization value)
   └── Signature (CBOR Object Signing and Encryption / EAT format)
```

CCA's attestation format is a CBOR/COSE Entity Attestation Token
(EAT), an open standard, in contrast to AMD's and Intel's
vendor-defined formats. This is the most operationally
significant difference: a CCA verifier can in principle handle
attestations from multiple vendors with shared parsing
infrastructure, while AMD and Intel verifiers require
vendor-specific code paths.

### 5.4 The PSP Firmware Role

The PSP is worth a separate subsection because its role in the
SEV-SNP trust chain is load-bearing in ways that the architecture
documents understate.

The PSP:

  - Boots the system. The PSP firmware runs before x86 cores
    are released from reset.
  - Loads the SEV firmware (a separate binary running on the
    PSP) which manages SEV/SEV-ES/SEV-SNP operations.
  - Derives per-VM keys from a hardware secret + entropy + TCB
    version.
  - Signs attestation reports with VCEK/VLEK.
  - Manages firmware updates (including its own).
  - Communicates with the host over a mailbox interface.

The PSP firmware has been the subject of a long sequence of
CVEs:

  - **CVE-2020-12890**: PSP firmware bug allowing arbitrary
    code execution on the PSP from a malicious BIOS.
  - **CVE-2021-26311** (AMD SEV "undeSErVed"): attestation
    bypass via PSP firmware logic flaw.
  - **CVE-2023-20598**: PSP firmware overflow.
  - **CVE-2024-21972**: PSP firmware bug affecting attestation.

Each of these affected attestation in ways the TCB version
field did not adequately capture. The remediation pattern is
firmware update + TCB version bump; the systemic question of
whether the PSP threat surface can be fully audited remains
open.

### 5.5 The Assumption Invalidated

§5's invalidated assumption is *that attestation is a hardware
property*. Attestation is a *firmware* property anchored in
hardware-held keys. The hardware holds the keys; the firmware
chooses what to attest to and when. A bug in the firmware does
not merely produce a localized failure — it can make a
syntactically-valid attestation that semantically misrepresents
the guest's state. Verifiers cannot detect this from the quote
alone; they depend on the vendor's TCB version reporting to be
honest, which is itself a property of the firmware.

---

## §6 — What the Literature Has Shown

### 6.1 Citations Table

| Year | Attack | Architecture | Venue | CVE | Impact |
|---|---|---|---|---|---|
| 2018 | SEVurity | AMD SEV | USENIX'18 | — | Memory remap, plaintext recovery |
| 2019 | SEVerity | AMD SEV | DIMVA'19 | — | I/O page poisoning |
| 2020 | SEV-Step | AMD SEV-ES | USENIX'20 | — | Single-stepping for side channels |
| 2020 | CrossTalk | Intel SGX | S&P'21 | CVE-2020-0543 | SRBDS, MDS-class |
| 2021 | undeSErVed | AMD SEV-SNP | NDSS'22 | CVE-2021-26311 | Attestation bypass |
| 2022 | ÆPIC Leak | Intel SGX | USENIX'22 | CVE-2022-21233 | Architectural memory leak |
| 2023 | CacheWarp | AMD SEV-ES/SNP | USENIX'24 | CVE-2023-20592 | Stale cache → state rollback |
| 2024 | WeSee | AMD SEV-SNP | USENIX'24 | CVE-2024-25742 | #VC injection → arbitrary R/W |
| 2024 | Heckler | AMD SEV-SNP, TDX | USENIX'24 | CVE-2024-25743 | Generic interrupt injection |
| 2024 | HyperPill | x86 hypervisors | USENIX'24 | multiple | MMIO fuzzing, hypervisor bugs |
| 2024 | TDX side channels | Intel TDX | various | — | Cache, branch predictor leakage |

### 6.2 Patterns in the Literature

Three patterns recur:

**Pattern 1: Reactive remediation.** Each generation of CC closes
the attacks that broke its predecessor. SEV had no memory
integrity; SEV-ES had no register protection; SEV-SNP has both.
Each closure is in response to published attacks, not in
anticipation of them. The next generation will close what the
2024-era attacks have demonstrated; the generation after that
will close what the 2026 attacks have not yet demonstrated.

**Pattern 2: Below-the-encryption attacks dominate.** The
encryption itself is rarely the target. AES-XEX has not been
broken; AES-XTS has not been broken; the per-VM keys are not
extracted. Instead the attacks target the *substrate the
encryption operates on*: cache, DRAM, interrupts, firmware.

**Pattern 3: Attribution lags detection.** The execution-state
determinism instrumentation (EXTp-class systems) can detect that
a guest diverged from its expected trajectory. Identifying
*why* it diverged often requires extending the snapshot scope to
include cache state (CacheWarp), interrupt history (Heckler), or
DRAM bit-flip patterns (Rowhammer). Each new attack class
identifies a new dimension of state that prior detection
infrastructure did not capture.

### 6.3 The Assumption Invalidated

§6's invalidated assumption is *that the published attacks are
the worst the attackers will achieve*. The literature is a
record of what has been *publicly disclosed*. It tells us about
the floor of the attacker's capability, not the ceiling. Vendor
SIRT (Security Incident Response Team) disclosures and academic
publications converge in the public record after a delay
measured in months to years; the silent state of vulnerabilities
known privately is not in this table.

---

## §7 — Open Questions

### 7.1 Post-Quantum Attestation

All current CC attestation chains use RSA or ECDSA. A
cryptographically-relevant quantum computer breaks these chains
retroactively: any attestation quote captured before the
quantum transition becomes forgeable after it. The vendors have
not committed to migration timelines for post-quantum signature
algorithms (Dilithium, SPHINCS+). The KDS infrastructure
(certificate distribution, revocation, key rotation) needs
parallel migration. The open question is whether the migration
can be staged in a way that allows long-lived attested
secrets — e.g., keys provisioned to a CC VM with expected
lifetime of years — to survive the transition.

### 7.2 Formal Models of the Monitor

The TDX Module, the PSP firmware, and the RMM are software
components running with extraordinary privilege. ARM published
a partial formal specification of the RMM as part of the CCA
release. AMD and Intel have not published comparable
specifications for their monitors. The open question is whether
the monitors are amenable to mechanized verification at all —
they handle interrupt injection, page management, and
attestation in deeply interleaved ways that resist clean
abstraction.

### 7.3 Cross-Vendor Portability

A CC verifier today must implement separate code paths for
SEV-SNP, TDX, and CCA attestation. A workload that wants to run
on multiple cloud providers' confidential VM offerings must
deal with three distinct quote formats, three distinct
verification flows, three distinct policy languages. The
Confidential Computing Consortium has proposed unified
attestation formats (e.g., Veraison's evidence/result schema)
but adoption is incomplete. The open question is whether the
vendors will converge on a portable format or whether the
ecosystem will continue to fragment.

### 7.4 Side-Channel Coverage

The vendor threat models scope side channels out. The literature
demonstrates side channels in. The open question is whether the
gap is closable in architectural terms — whether a future CC
generation can offer a meaningful side-channel guarantee
without sacrificing the performance characteristics that make
the architectures viable for general-purpose workloads.

### 7.5 Authenticated Memory Encryption

SEV and TDX currently use confidentiality-only modes
(AES-XEX/XTS). Authenticated modes (AES-GCM with a per-page
MAC) would detect Rowhammer-style bit flips on decryption but
impose per-page metadata storage overhead and decryption
latency. The open question is whether the performance budget
exists for authenticated modes in the next-generation memory
controllers, or whether the cost is paid through dedicated
on-die SRAM for MAC caches.

### 7.6 Multi-Tenant Side Effects

CC was designed for single-tenant-per-VM, multi-tenant-per-host
deployments. The threat model assumes the hypervisor is hostile
and tenants are isolated by encryption. Cache, DRAM, and
interrupt-channel side effects between *co-tenant guests* — not
between guest and host — are less well-studied. The open
question is whether the contract between *peer guests* is as
well-defined as the contract between *guest and host*.

### 7.7 Migration and State Transfer

Live migration of a CC VM requires moving encrypted state
between two physical platforms. The keys do not move — each
platform has its own — so the state must be re-encrypted in
transit. Current designs (e.g., AMD's SEV-SNP Migration Agent,
Intel's TDX migration TD) use a secondary attested channel
between source and destination. The open question is whether
the migration protocol preserves all of the attested properties
of the original VM, or whether migration is a privilege
reduction (a migrated VM is attested by the destination
platform's keys, with no chain to the original launch).

---

## References

The references below are publication-bearing. URLs are stable
canonical forms where available; DOIs are preferred when the
venue assigns them.

  [1]  AMD. *AMD64 Architecture Programmer's Manual, Volume 2:
       System Programming*. Publication 24593, current revision.
       Section on SEV-SNP architecture.

  [2]  AMD. *SEV Secure Nested Paging Firmware ABI Specification*.
       Publication 56860, current revision.

  [3]  AMD. *SEV API Specification*. Publication 55766.

  [4]  Intel. *Intel Trust Domain Extensions (Intel TDX) Module
       Base Architecture Specification*. Document 348549.

  [5]  Intel. *Intel TDX Module ABI Specification*. Document
       348551.

  [6]  Intel. *Intel TDX Guest-Hypervisor Communication
       Interface*. Document 349817.

  [7]  Arm Limited. *Arm Confidential Compute Architecture
       Software Stack Specification*. DEN0096, current revision.

  [8]  Arm Limited. *Realm Management Monitor Specification*.
       DEN0137, current revision.

  [9]  Arm Limited. *Arm Architecture Reference Manual for
       A-profile architecture*. Sections on Realm Management
       Extensions (RME).

  [10] Zhang, R., Gerlach, L., Weber, D., Hetterich, L., Lü, Y.,
       Kogler, A., Schwarz, M. *CacheWarp: Software-based Fault
       Injection using Selective State Reset*. Proceedings of
       the 33rd USENIX Security Symposium, 2024.
       CVE-2023-20592.

  [11] Schlüter, B., Sridhara, S., Bertschi, A., Shinde, S.
       *WeSee: Using Malicious #VC Interrupts to Break AMD
       SEV-SNP*. Proceedings of the 33rd USENIX Security
       Symposium, 2024.

  [12] Schlüter, B., Sridhara, S., Kuhne, M., Bertschi, A.,
       Shinde, S. *Heckler: Breaking Confidential VMs with
       Malicious Interrupts*. Proceedings of the 33rd USENIX
       Security Symposium, 2024.

  [13] Bulekov, A., et al. *HyperPill: Fuzzing for Hypervisor-
       bug Hunting*. Proceedings of the 33rd USENIX Security
       Symposium, 2024.

  [14] Morbitzer, M., Huber, M., Horsch, J., Wessel, S.
       *SEVered: Subverting AMD's Virtual Machine Encryption*.
       European Workshop on Systems Security (EuroSec), 2018.

  [15] Du, Z.H., et al. *Secure Encrypted Virtualization is
       Unsecure*. arXiv:1712.05090, 2017.

  [16] Wilke, L., Wichelmann, J., Sieck, F., Eisenbarth, T.
       *undeSErVed Trust: Exploiting Permutation-Agnostic
       Remote Attestation*. NDSS Symposium, 2022.
       CVE-2021-26311.

  [17] Borrello, P., Kogler, A., Schwarzl, M., Lipp, M.,
       Gruss, D., Schwarz, M. *ÆPIC Leak: Architecturally
       Leaking Uninitialized Data from the Microarchitecture*.
       USENIX Security 2022. CVE-2022-21233.

  [18] Kim, Y., Daly, R., Kim, J., Fallin, C., Lee, J.H.,
       Lee, D., Wilkerson, C., Lai, K., Mutlu, O. *Flipping
       Bits in Memory Without Accessing Them: An Experimental
       Study of DRAM Disturbance Errors*. ISCA 2014.
       (Rowhammer foundational paper.)

  [19] AMD. *AMD-SN-1029 (CacheWarp) Security Bulletin*. 2023.

  [20] Confidential Computing Consortium. *Common Terminology
       for Confidential Computing*. CCC, 2022.

---

## Appendix A — Relationship to Portfolio

This writeup is the wide survey of Confidential Computing in the
HBO NL low-level security portfolio. It is a sibling of the
following pieces:

  - **Microarch-Isolation**: covered the TEE generation
    preceding CC (SGX, TrustZone) and established the structural
    register used in this document — trust boundaries as
    architectural objects, not physical facts. This document
    extends Microarch-Isolation's TEE chapter into the CC era,
    inheriting the framing and applying it to AMD SEV-SNP,
    Intel TDX, and ARM CCA specifically.

  - **Silicon Is the Adversary**: argues that silicon is not a
    neutral substrate but an active threat surface. CC is the
    case study where the vendors most explicitly attempt to
    *make* silicon the trusted root — and where the gap between
    the marketing claim and the implementation is most
    publishable. The two pieces read together: Silicon Is the
    Adversary establishes the substrate; this document shows
    the architectural attempts to abstract over it.

  - **Mathematical Collapse**: focused on cryptographic and
    semantic-layer failures. CacheWarp is a structural
    cousin: it does not break the math (AES holds) but it
    breaks the *use* of the math by manipulating the cache
    state below the encryption boundary.

  - **SPI-Firmware-Anatomy**: covers the firmware layer below
    the CPU. The PSP firmware referenced in §5 of this document
    is exactly the kind of off-die-firmware substrate that
    SPI-Firmware-Anatomy maps in detail. The cross-reference is
    direct: the PSP boots from SPI flash; SPI flash is the
    boot-firmware layer SPI-Firmware-Anatomy anatomizes.

  - **Speculation Barrier Illusion**: covers speculative-
    execution side channels. The relevance to CC is that the
    speculation primitives (transient execution, branch
    predictor poisoning) operate at the same microarchitectural
    layer where CC's protections do not reach. Spectre-class
    attacks against TDX guests are a documented research area;
    they are out of scope for this document but cited as a
    parallel attack surface.

The cluster's structural claim, restated: *a single shared
microarchitectural fabric carries multiple security
abstractions, none of which fully project onto the fabric*. CC
is the most ambitious projection in commercial silicon. Its
gaps are not anomalies; they are the consequence of trying to
project a strong abstraction onto a substrate that was not
designed for it.

---

*End of writeup.*
