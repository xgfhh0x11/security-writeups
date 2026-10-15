---
title: "No Boundary Below the Architecture"
subtitle: "VMScape, GhostRace, and the TEE Assumption"
author: Tyler
date: "2026-05-16"
keywords: [microarchitectural isolation, trust boundaries, VMScape, GhostRace, TEE, SGX, VBS, hypervisor isolation, branch predictor, speculative race conditions, defensive engineering]
companion_writeups: "Silicon Is the Adversary (horizontal map of post-2018 microarch threats); Mathematical Collapse (theory); Speculation Barrier Illusion (focused reproducible instance)"
---

# No Boundary Below the Architecture
## VMScape, GhostRace, and the TEE Assumption

---

## Author's Note

Trust boundaries are the load-bearing fiction in every modern
security design. The process boundary, the kernel/user split, the
hypervisor's tenant separation, the VBS/VTL secure-kernel
partition, the SGX enclave — every one of them is something the
*architecture* says exists. Software engineers spend careers
treating these boundaries as physical. They aren't. They are
architectural assertions about what a privileged piece of code
is allowed to do, and they hold exactly to the extent that the
underlying silicon honors the assertion. The recent years of
microarchitectural attack research are, read together, a
systematic enumeration of the gap between *the boundary the
architecture promised* and *the boundary the silicon implemented*.

This writeup is the trust-boundary side of that gap. Its sibling
in this collection, *Silicon Is the Adversary*, is a horizontal
sweep of seven post-2018 attack families: Spectre, Meltdown,
Foreshadow, dedup-Rowhammer, Hertzbleed, and friends. The
present writeup is the orthogonal cut — a vertical drill through
five trust-boundary layers (user → kernel → hypervisor → VBS/VTL
→ TEE), an honest inventory of what each layer guarantees and
what it explicitly does not, and a deep read of two recent
attacks — **VMScape** (ETH Zurich, S&P 2026) and **GhostRace**
(VUSec, USENIX Security 2024) — chosen because each one cleanly
demonstrates a different boundary the architectural abstraction
promised would hold.

The thesis is in the title. **There is no boundary below the
architecture.** What the architecture calls a boundary is a
control flow that the privileged code-paths agree to respect.
Underneath, the silicon shares cache, branch predictors, TLB
entries, execution units, FPU/AVX register spills, store buffers,
and a dozen other artifacts of optimization across every
"boundary" the architecture defined. Those shared artifacts are
the side channels. The TEE assumption — *"my enclave is a
confidential compartment"* — is correct against the threats the
TEE was specified against (direct memory read, DMA, post-mortem
dumps) and silent about every threat that did not exist when
the specification was written. The boundary held; the silicon
did not.

The point of writing this down is not to enumerate CVEs. The
point is to make legible the *categorical fact* that a defender's
threat model needs to enumerate two boundaries — the
architectural one (what the spec promises) and the
microarchitectural one (what the silicon actually delivers) —
and stop conflating them. The conflation is comfortable. It is
also load-bearing for designs that are not security-load-bearing.

What follows is six sections. §1 develops the trust-boundary
frame. §2 walks the five layers. §3 lays out the TEE ✅/❌
matrix: what enclave technology actually guarantees and what
it does not, listed item by item. §4 unpacks VMScape — branch
predictor state surviving VM exit, hypervisor secrets falling
out by remote training. §5 unpacks GhostRace — speculative
race conditions in correctly-written synchronized code, mutex
and atomic-based protection bypassed in the transient window
where the predictor has not yet been corrected. §6 is the
"Not a Bug" section: these attacks are not implementation
defects. They are documented design decisions paying for
performance with confidentiality. §7 concludes.

A defender reading this writeup should come away with the
operational position the title states: *the architectural
trust boundary is an assumption your threat model must list
separately from the microarchitectural one, and the latter is
the one that determines whether secrets stay secret.*

---

## Abstract

This writeup is a layered structural reading of trust
boundaries in modern hardware. It treats the architectural
isolation contracts of kernel/user, hypervisor/VM, VBS/VTL,
and SGX/TEE not as confidentiality primitives but as
*assertions the architecture makes that the microarchitecture
does not implement*. The contribution is threefold: (i) a
trust-boundary framework that distinguishes architectural from
microarchitectural isolation explicitly; (ii) a layer-by-layer
audit naming each layer's assumptions and identifying where
the microarchitectural reality diverges; (iii) a deep read of
two 2024-era attacks — VMScape (cross-VM branch-predictor
poisoning) and GhostRace (speculative bypass of mutex/atomic
synchronization) — chosen because each demonstrates a
different boundary failing in a different layer. The writeup
closes with the "Not a Bug" framing — these attacks are
documented design decisions trading confidentiality for
performance — and a structural conclusion: *defenders who
treat the architectural boundary and the microarchitectural
boundary as a single object will keep being surprised.*

**Keywords:** microarchitectural isolation, trust boundaries,
VMScape, GhostRace, TEE, SGX, VBS, hypervisor isolation,
branch predictor, speculative race conditions, defensive
engineering.

---

## 1. The Trust-Boundary Frame

### 1.1 Architectural view vs microarchitectural reality

A trust boundary is a contract the architecture makes about
what privileged software is allowed to observe. *User space
cannot read kernel memory.* *A guest VM cannot read the
hypervisor's secrets.* *The Secure Kernel (VTL 1) cannot be
inspected by the Normal Kernel (VTL 0).* *An SGX enclave is a
confidential compartment.* These statements are correct under
a precise specification of the architectural state — page
tables, segment selectors, privilege levels, VMCS fields,
EPC permissions, attestation certificates.

The two pictures, side by side:

```
   ARCHITECTURAL VIEW                MICROARCHITECTURAL REALITY

   ┌──────────┐ ┌──────────┐         ┌──────────────────────────────┐
   │  User    │ │ Kernel   │         │   SHARED MICROARCH STATE     │
   │  Space   │ │ Space    │         │                              │
   └──────────┘ └──────────┘         │   • L1 / L2 / L3 caches      │
                                     │   • Branch predictor         │
   ┌──────────────────────┐          │   • BTB + PHT                │
   │     Hypervisor       │          │   • TLB                      │
   └──────────────────────┘          │   • Execution ports          │
                                     │   • FPU / AVX register file  │
   ┌──────────────────────┐          │   • Memory ordering buffers  │
   │   Secure Kernel /    │          │   • Store-to-load forwarding │
   │   TEE (VTL 1 / SGX)  │          │                              │
   └──────────────────────┘          │   NO PHYSICAL BOUNDARY       │
                                     │   ACROSS ANY OF THESE        │
   ↑ Trust boundary lines             └──────────────────────────────┘
```

The picture on the left is what every defender's threat model
draws. The picture on the right is what the silicon actually
implements. The diagram is honest only when both pictures are
drawn simultaneously: the boundaries on the left exist *and*
the shared state on the right exists, and the channel between
attacker and victim is always *the most permissive* of the
two.

### 1.2 What "architectural" means precisely

Architectural state is everything the ISA specification
defines as observable: general-purpose registers, control
registers, flags, memory contents, page-table entries,
privilege-mode bits, MSRs that the spec lists. Operations
that affect architectural state have to satisfy the ISA's
consistency rules — exceptions are precise, writes are
ordered per the memory model, faults are delivered in
program order.

Architectural state is what compilers reason about. It is
what kernel page tables enforce. It is what the page-fault
handler validates. It is what the formal verification
literature has spent thirty years proving properties about.

It is also a strict subset of the state the silicon actually
maintains.

### 1.3 What "microarchitectural" adds

Microarchitectural state is everything the silicon maintains
that is *not* in the ISA spec — and there is, in modern
high-performance designs, a great deal of it:

- **Cache lines** in L1, L2, L3 and their replacement metadata.
- **Branch Target Buffer (BTB)** entries indexed by
  instruction address.
- **Pattern History Table (PHT)** counters mapping branch
  history to taken/not-taken predictions.
- **Return Stack Buffer (RSB)** entries predicting call/ret
  targets.
- **TLB entries** in iTLB, dTLB, STLB layers.
- **Execution port state** and reservation-station
  occupancy.
- **Store-buffer entries** and store-to-load forwarding
  predicates.
- **FPU/AVX register file** state spilled to L1 on context
  switch.
- **Memory ordering buffers** tracking in-flight loads and
  stores.
- **Prefetcher state** including stride detectors and
  pattern history.

None of this is in the ISA spec because it is implementation
detail. The ISA defines what *appears to happen*; the
microarchitecture chooses *how* it appears to happen, free
to optimize as long as the externally visible behavior
matches the spec.

This is the contract that has been load-bearing for fifty
years of CPU performance gains. It is also the contract that
makes microarchitectural side channels possible. *How* the
silicon makes the architecture appear to behave is observable
through timing, through cache occupancy, through frequency,
through whatever quantity the architecture forgot to declare
unobservable. The ISA does not have a clause that says "and
the cache state shall be unobservable across privilege
boundaries"; the assumption was sitting in the threat model
unstated, and every post-Spectre attack is the systematic
extraction of secrets through channels the ISA never
forbade.

### 1.4 The thesis

**Architectural isolation ≠ Microarchitectural isolation.**

The architectural isolation contract is correctly implemented
on every modern CPU. Kernel pages are not directly readable
from user mode. EPT page tables correctly separate guest VMs.
SGX EPC pages return zeros to the operating system. The
architecture holds. The threat that has been demonstrated,
seven years running, is that *the microarchitectural state
through which the architecture is implemented does not honor
the boundaries*, and the boundary the defender thought existed
is a half-truth.

This writeup is the layer-by-layer accounting of where, and
how badly, the half-truth fails. The rest follows.

---

## 2. Layer-by-Layer Audit

This section walks five trust boundaries — user/kernel,
kernel/hardware, hypervisor/guest, VBS/VTL, TEE/host — and
names each layer's load-bearing assumption and the
microarchitectural fact that breaks it.

### 2.1 The user / kernel boundary

| Property               | Architectural claim                            | Microarchitectural reality                          |
|------------------------|-------------------------------------------------|-----------------------------------------------------|
| Page protection         | User-mode read of a kernel page → page fault    | Speculative load completes; cache state mutated     |
| Privilege transitions   | INT/SYSCALL transitions are precise             | BTB / PHT entries cross the transition              |
| Memory allocation       | `ExAllocatePoolWithTag(NonPagedPool, …)` is kernel-only | The physical pages are visible through cache timing |

The defender's most common assumption at this boundary is:
*"This memory is allocated from kernel pool; user code cannot
read it."* The architectural claim is correct. The
microarchitectural fact is that the same allocation lives on
a cache line that *any* core can pull in via Meltdown-style
transient execution, and the eviction patterns are observable
from any user process pinned on a sibling SMT thread.

A defender who designs around this boundary as
confidentiality-bearing — caching credentials in
NonPagedPool, holding crypto state across a syscall path, or
mapping a secret into a kernel buffer that user code can
trigger a read of — is depending on the architectural
boundary alone. The mitigation set (KPTI, retpoline, IBRS,
SMEP, SMAP) is real and necessary. None of it is total.
Each closes one specific gap in the microarchitectural
side of the boundary; none of them restores the
*confidentiality* property the boundary was implicitly
assumed to provide.

### 2.2 The kernel / hardware boundary

The kernel sits one privilege layer above the hardware and
two above the firmware. The architectural assumption is:
*the hardware is deterministic*; the kernel writes to MSRs
and the MSRs hold the values the kernel wrote, the kernel
reads cycle counts and the counts are stable, the kernel
configures cache partitioning (Intel CAT) and the
partitioning is honored.

The microarchitectural reality:

- **Thermal throttling** changes effective cycle count
  per second without notifying the kernel.
- **DVFS** changes the clock frequency the kernel observes
  via TSC vs APIC timer ratios — Hertzbleed (covered in
  *Silicon Is the Adversary*) exploits exactly this.
- **MSR writes that gate microcode-level features** are
  accepted by the silicon but applied at a future
  microcode-defined moment, not at the next instruction
  boundary.
- **Branch prediction trained by user code** persists
  across the next kernel-mode entry and influences kernel
  branch behavior.

The kernel is not in charge of the hardware; the kernel is
in *negotiation* with the hardware, mediated by an
architectural contract the silicon honors at the level the
contract was written and ignores below.

### 2.3 The hypervisor / guest boundary

The architectural claim of hypervisor isolation is:
*a guest VM observes only its own architectural state
(saved/restored via VMCS); the hypervisor's state is
inaccessible.*

The microarchitectural reality, made explicit by VMScape
(§4 below):

| Architectural state         | Cleared on VM exit?                           |
|------------------------------|-----------------------------------------------|
| General-purpose registers    | ✅ Saved to VMCS, restored on entry            |
| Control registers (CR0/3/4)  | ✅                                              |
| Segment registers + RIP/RSP  | ✅                                              |
| Page tables (EPT)            | ✅ Switched                                     |
| Branch predictor (BTB/PHT)   | ❌ Persists across VM exit on most CPUs        |
| TLB entries                  | ⚠️ Partially flushed; PCID/VPID tagged         |
| Cache state                  | ❌ Persists                                     |
| Execution-port state         | ❌ Persists                                     |
| FPU/AVX register file        | ⚠️ Spilled to L1 on context switch              |

The VMCS is a comprehensive snapshot of *architectural*
state. It does not enumerate the microarchitectural state
that survives the transition. This is not an oversight —
flushing branch predictor state on every VM exit costs
double-digit percent performance and was deliberately
declined as a default. The cost was, instead, paid in
*believing the boundary was tighter than it was*.

The defender's question at this boundary used to be
"can a guest VM trap to the hypervisor?". The new question
is *"how much of the hypervisor's state survives between
the guest's training and the hypervisor's execution, and
through which side channels does it become observable?"*.
VMScape is the canonical answer.

### 2.4 The VBS / VTL boundary

Microsoft's Virtualization-Based Security splits the
Windows kernel into VTL 0 (Normal Kernel) and VTL 1
(Secure Kernel). The Secure Kernel holds credentials,
isolates kernel-mode integrity checks (HyperGuard), and
provides Credential Guard's protected LSASS state. The
architectural claim is: *VTL 1 is confidential; VTL 0
cannot read it.*

The architectural side of the claim holds. EPT switches
on VTL transitions, page tables flip, the Secure Kernel
runs in a Hyper-V-managed partition the Normal Kernel
cannot map. From a process-memory-reading perspective,
Credential Guard's LSASS is not readable.

The microarchitectural side fails in the same way the
hypervisor boundary does — VTL transitions are *also*
VM-exit-class transitions internally; branch predictor
state crosses them; cache state crosses them; speculative
execution within VTL 0 can construct primitives that
observe VTL 1's cache footprint. Microsoft's documentation
of the boundary names architectural confidentiality
explicitly and is silent on microarchitectural
confidentiality — the silence is the correct read of the
silicon, and the defender's threat model has to make the
same distinction.

### 2.5 The TEE / host boundary

Intel SGX (and analogues — TDX, SEV-SNP, ARM CCA) provide
hardware-enforced enclaves whose memory is encrypted in
DRAM. The architectural claim is the most ambitious of any
boundary considered so far:

> *The operating system is untrusted. The hypervisor is
> untrusted. Even a kernel-mode debugger cannot read
> enclave memory. The Memory Encryption Engine (MEE)
> ensures DRAM is opaque.*

This claim is correct under the architectural model. SGX's
defining promise — that a root user cannot dump enclave
memory and read secrets — is upheld at the architecture
level. The MEE does what it says.

The microarchitectural reality is the subject of §3.

---

## 3. What TEE Promises and What It Doesn't

This section is the operational core of the writeup. The
TEE matrix below is the table a defender should literally
print and pin to a desk before building anything that
depends on enclave confidentiality.

### 3.1 What TEE *does* guarantee — direct attacks

#### ✅ 3.1.1 Direct memory read is blocked

```c
void untrusted_os_function(void) {
    uint64_t *enclave_addr = (uint64_t *)0x40000000;  // EPC page
    uint64_t  secret = *enclave_addr;                  // page fault
}
```

The architectural read produces a page fault. The OS, even
running as root, cannot map an enclave page into its
address space. The MEE's invariant — *anything leaving the
cache hierarchy for DRAM is encrypted, anything entering
the cache hierarchy for the enclave is decrypted* — is
preserved.

#### ✅ 3.1.2 DMA is blocked by IOMMU / SMMU

```c
void dma_attack(void) {
    /* IOMMU (Intel VT-d, ARM SMMU) refuses DMA targets
       that resolve to an EPC physical address. */
}
```

DMA controllers cannot bypass the MEE because the IOMMU
sits between the device and physical memory; an EPC page
is not in the device-visible region. This is one of the
strongest architectural guarantees in the whole
hardware-security stack.

#### ✅ 3.1.3 Memory dumps are encrypted

```
0x40000000:  E7 3A B2 9F 4C D8 1E 6A     ← enclave plaintext
0x40000008:  92 F1 4E 8B C3 7D A5 22       was here in DRAM,
0x40000010:  5F E6 D9 3C 81 B4 2A F7       MEE encrypted it
```

A kernel crash dump captures DRAM contents. EPC pages
appear as ciphertext. Forensic analysis on the dump cannot
recover enclave secrets without the MEE key, which never
leaves the CPU package.

#### ✅ 3.1.4 Debug-register based introspection is disabled

EDBGRD and similar debug-channel reads of enclave memory
are explicitly disabled by the SGX state machine.

#### ✅ 3.1.5 Architectural privilege escalation does not help

A kernel-mode rootkit, an attacker with `nt!Mm*` primitives,
an SMM handler — none of them can architecturally read
enclave memory through the normal memory access path.

### 3.2 What TEE does *not* guarantee — microarchitectural attacks

This is the list a defender depending on enclave
confidentiality has to include in the threat model.

#### ❌ 3.2.1 Cache isolation

Enclave loads pull data into L1, L2, and L3 in plaintext —
the MEE is between cache and DRAM, not between enclave and
cache. The cache hierarchy is shared with all non-enclave
code running on the same physical core (and L3 across
sockets).

```c
uint64_t probe_enclave_cache(uint64_t addr) {
    trigger_enclave_read(addr);                     // get enclave to load addr
    uint64_t t0 = __rdtsc();
    _mm_clflush((void *)addr);
    _mm_mfence();
    volatile uint8_t dummy = *(uint8_t *)addr;
    uint64_t t1 = __rdtsc();
    return (t1 - t0) < CACHE_HIT_THRESHOLD;        // hit → enclave touched it
}
```

Foreshadow (covered in detail in *Silicon Is the
Adversary*) is the dramatic L1 instance of this. Less
dramatic cache-occupancy attacks against enclave code
have been demonstrated against AES T-table
implementations, RSA, ECDSA, and post-quantum candidates.

#### ❌ 3.2.2 TLB isolation

TLB entries are tagged with PCID/VPID where the hardware
supports it, but the *underlying TLB* is shared. A
context-switching attacker can measure the eviction of an
enclave's TLB entries via timing on subsequent address
translations.

#### ❌ 3.2.3 Branch predictor isolation

The BTB and PHT are global structures indexed by
instruction address. An enclave's branch behavior trains
the same predictor that the host-mode code observes;
VMScape (§4) is the canonical proof for the hypervisor
analogue and the SGX variant exists by direct extension.

#### ❌ 3.2.4 Speculation rollback

Architectural rollback on misprediction or fault unwinds
register and memory writes. **It does not unwind cache
loads, BTB updates, TLB entries, or store-buffer
allocations.** Spectre-class attacks against enclaves
operate in this gap.

#### ❌ 3.2.5 FPU / AVX timing

When a thread context-switches off an enclave, the FPU and
AVX register state spills to L1. A subsequent attacker
process can observe the spilled state through cache
timing. The MEE does not encrypt cache contents; it
encrypts what *leaves* the cache for DRAM. The spill
target is a normal L1 line.

### 3.3 The matrix

```
┌────────────────────────────────────────────────────────────────────┐
│                       TEE GUARANTEES MATRIX                         │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Attack vector                  Architectural        Microarch     │
│                                  protection           protection    │
│  ────────────────────────────  ──────────────────   ─────────────  │
│  Direct memory read                  ✅                 ❌          │
│  DMA from device                     ✅                 ⚠️          │
│  Crash-dump analysis                 ✅                 ❌          │
│  EDBGRD / debug-register read        ✅                 ❌          │
│  Cross-tenant cache observation      —                  ❌          │
│  Cross-tenant TLB observation        —                  ❌          │
│  Branch-predictor poisoning          —                  ❌          │
│  Speculative-execution leak          —                  ❌          │
│  FPU / AVX register-spill obs.       —                  ❌          │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

The architectural column is real. It is what the
specification promised, and it is what the silicon
delivered. The microarchitectural column is the audit the
specification did not write. **Both columns are part of the
threat model. Neither column subsumes the other.**

### 3.4 What this means for design

A defender choosing to deploy an SGX-protected, VBS-
protected, or TDX-protected workload is making one
defensive bet — that the architectural attack vectors
listed in the left column will not be the ones the
attacker uses — while remaining exposed to the
microarchitectural ones in the right column. That is a
*positive* defensive position: SGX *does* defeat root-level
memory readers, dump analysts, and DMA-bus attackers. It is
also a *limited* defensive position: SGX does not defeat
a co-resident process running on the same physical core
that can construct cache-timing primitives.

The right operational summary, the user's own phrasing
applied:

> **TEE = risk mitigation, not risk elimination.** The
> attack vector shifts from `direct memory read` to
> `cache timing`. The attack does not vanish; it
> *changes shape*.

---

## 4. VMScape — Branch-Predictor as Cross-VM Channel

VMScape (ETH Zurich, IEEE S&P 2026) demonstrates that the
hypervisor / guest boundary, taken as one of the
strongest architectural isolations in modern cloud
infrastructure, has a microarchitectural side channel
through the branch predictor that survives VM exit
*by design*.

### 4.1 The architectural promise

The VMCS (Virtual Machine Control Structure) is the
hardware-defined snapshot mechanism that captures and
restores guest state at every VM exit / VM entry pair:

- General-purpose registers: ✅ saved/restored.
- Control registers (CR0, CR3, CR4, EFER): ✅
- Segment registers, RIP, RSP, RFLAGS: ✅
- Page-table pointers (EPT): ✅ switched.

This is the architectural state. After VM exit, the
hypervisor sees its own architectural state; the guest's
architectural state is in the VMCS. By the architectural
contract, the two domains are isolated.

### 4.2 What VMCS does *not* save

The VMCS schema, defined by the Intel SDM and the AMD APM,
**does not include branch-predictor state**. The BTB and
PHT live in the core's microarchitectural fabric and are
not architecturally addressable. Flushing them on VM exit
is *possible* — Intel introduced IBPB (Indirect Branch
Predictor Barrier) microcode features post-Spectre — but
it is *not* automatic. Default hypervisor configurations,
prioritizing performance, do not issue IBPB on every VM
exit.

VMScape is the systematic exploitation of this default.

### 4.3 The three phases

#### Phase 1 — Guest VM trains the predictor

```c
// Inside guest VM
for (int i = 0; i < TRAINING_ITERATIONS; i++) {
    if (guess_hypervisor_secret_bit(i)) {
        speculative_target();    // trains BTB / PHT at this branch
    }
}
```

The guest executes a branch at an instruction-address
chosen to alias with a branch in the hypervisor's code
path. The branch is taken in a pattern derived from a
*guess* about a hypervisor secret bit. The branch
predictor is a global state; after ~1000 training
iterations, the BTB entry at that instruction address
has high confidence that the branch is taken.

```asm
guest_training:
    mov  rax, [secret_guess]      ; guess about hypervisor secret
    test rax, rax
    jz   branch_not_taken          ; predictor: "TAKEN"
    call target_function           ; ← BTB updated here
branch_not_taken:
    jmp  guest_training            ; loop
```

#### Phase 2 — VM exit

```c
__vmcall(VMCALL_EXIT);
```

The guest issues a VM exit. The architectural state
transitions cleanly into the VMCS; the microarchitectural
state — including the BTB / PHT entries the guest just
trained — does not. The hypervisor begins executing in
the architectural context of the host kernel, but on a
core whose branch-prediction structures are still
populated with the guest's training.

#### Phase 3 — Hypervisor secret falls out

```c
// Inside hypervisor
if (hypervisor_secret_check()) {
    sensitive_operation();
}
```

The hypervisor executes its own branch at an
instruction-address that *aliases* with the guest's
training (ASLR being weak or bypassed, or the branch
predictor's indexing function colliding by construction).

```asm
hypervisor_secret_check:
    mov  rax, [hypervisor_secret]
    test rax, rax
    jz   hypervisor_branch_not_taken
    call secret_operation               ; ← predictor consulted
```

The predictor consults its (guest-trained) state. The
prediction is "taken". Two cases:

- **Hypervisor secret was 1** → branch genuinely taken →
  prediction matched → no misprediction penalty → fast.
- **Hypervisor secret was 0** → branch genuinely not
  taken → prediction wrong → pipeline flush + restart →
  slow.

The guest, having re-entered after the hypervisor returns
from this code path, times the round trip. The wall-time
difference is the hypervisor's secret bit.

### 4.4 The diagnostic signature

```
 0: kd> !vmcs
 Virtual Machine Control Structure:
   Guest RIP: 0x00000000`00100000
   Guest RSP: 0x00000000`00200000
   ...

 0: kd> !analyze -v
 Branch predictor state: NOT CLEARED
   → Guest VM training preserved across exit
   → Hypervisor timing attack feasible
```

The `!vmcs` command shows architectural state that *is*
saved. The branch-predictor state — the state that VMScape
exploits — does not appear in `!vmcs` output because it is
not part of the VMCS. The architectural snapshot is
complete; the microarchitectural snapshot does not exist.

### 4.5 What VMScape demonstrates structurally

| Architectural fact     | Microarchitectural fact                    |
|------------------------|---------------------------------------------|
| VMCS is complete       | VMCS does not enumerate BTB / PHT           |
| EPT isolation holds    | Cache hierarchy still shared across exits   |
| Privilege boundary OK  | Branch-predictor entries cross the boundary |

The boundary, *as defined by the architecture*, holds. The
boundary, *as observable through microarchitectural state*,
does not. The defender's threat model needs both columns.

The Intel and AMD mitigation set — IBPB on VM exit, IBRS,
STIBP, eIBRS — answers this specific case at a measured
performance cost (1–5% on workload-dependent metrics).
Whether a given cloud provider has enabled them by default
is a deployment policy question, *not* an architectural
guarantee. The defender has to check.

**Assumption invalidated by VMScape.** *VM exit clears all
state the guest could have used to influence the
hypervisor.* The corollary: the branch predictor, and
every other shared microarchitectural structure, must be
modeled as a *cross-boundary channel* until explicitly
mitigated.

---

## 5. GhostRace — Speculative Synchronization Bypass

GhostRace (VUSec, USENIX Security 2024 — CVE-2024-2193)
demonstrates that synchronization primitives — mutexes,
atomics, the entire happens-before discipline that the
concurrency literature has spent fifty years formalizing —
do not protect confidentiality against an adversary
willing to operate in the *speculative window* where the
predictor has not yet resolved the lock.

### 5.1 The architectural promise

```c
// Victim thread
pthread_mutex_lock(&mutex);
secret = read_secret();
process_secret(secret);
pthread_mutex_unlock(&mutex);
```

The victim's critical section is correctly protected. The
mutex guarantees mutual exclusion: at most one thread
holds the lock at any time. Atomic happens-before relations
ensure the write of `secret` is ordered after the lock
acquisition and before any release. Under the
architectural concurrency model, no other thread can
observe `secret` between the lock and the unlock.

This is the contract concurrent programming has been
built on since the 1960s. It is, architecturally, correct.

### 5.2 The speculative window

```c
// Attacker thread, racing the victim
if (pthread_mutex_trylock(&mutex) == 0) {
    uint64_t leaked = secret;                   // speculative load
    probe_cache((uint64_t)&secret);             // timing oracle
}
```

The attacker thread issues `trylock`. The architectural
behavior is: if the lock is held by the victim, `trylock`
returns non-zero and the `if` body is skipped. Under
correct mutex semantics, no race condition occurs.

The *microarchitectural* behavior — observable, measurable,
and exploitable — is:

1. The branch on `pthread_mutex_trylock(&mutex) == 0`
   produces a misprediction. The predictor, biased by
   prior training or by the fast path of the lock
   implementation, predicts the lock is available.
2. The CPU speculatively enters the `if` body.
3. `leaked = secret` is *speculatively executed* — the
   load of `secret` from memory completes, the value is
   placed in a transient register, and the cache line
   holding `secret` is brought into L1.
4. The predictor's misprediction resolves. The lock was
   actually held by the victim. The CPU rolls back the
   architectural state: `leaked` is not assigned; the
   register write is squashed; the program continues as
   if the speculative path never executed.
5. The cache load is *not* rolled back. The line holding
   `secret` remains in L1, warm and observable.
6. `probe_cache((uint64_t)&secret)` measures the timing of
   a subsequent load of `&secret`. A cache hit (~50
   cycles) confirms the speculative load brought the
   secret into L1. The byte value can be inferred bit by
   bit through standard secret-dependent indexing.

The attack works *even though the mutex was correctly
held*. The mutex enforced architectural mutual exclusion;
it did nothing about the speculative window in which the
predictor mispredicted the lock state.

### 5.3 The ASM-level view

```asm
attacker_thread:
    mov  rax, [mutex]              ; load lock state
    test rax, rax
    jnz  mutex_locked              ; predictor: "unlocked"
                                   ; speculative execution begins
    mov  rbx, [secret]             ; speculative load — cache filled
    mov  [leaked], rbx             ; speculative store — store buffer

    ; predictor resolved: mutex was actually locked
    ; architectural rollback:
    ;   rbx        : squashed ✅
    ;   [leaked]   : store buffer flushed ✅
    ; microarchitectural state:
    ;   cache line containing secret : present ❌
    ;   timing oracle : exploitable

mutex_locked:
    ret
```

The architectural-vs-microarchitectural distinction is
visible per-instruction. The squash of `rbx` and the
flush of the store-buffer entry are correct architectural
rollback. The cache line, brought in by `mov rbx,
[secret]`, is microarchitectural state — it is not part
of the rollback scope and it remains observable.

### 5.4 Atomic operations are not an answer

A common first-instinct mitigation is to use atomic
acquire/release instead of mutex:

```c
// Victim
__atomic_store_n(&flag, 1, __ATOMIC_RELEASE);
secret = read_secret();
__atomic_store_n(&flag, 0, __ATOMIC_RELEASE);

// Attacker
if (__atomic_load_n(&flag, __ATOMIC_ACQUIRE) == 0) {
    uint64_t leaked = secret;                   // still speculative!
    probe_cache((uint64_t)&secret);
}
```

The atomic operations provide the same architectural
happens-before guarantee as the mutex. They do nothing
about the speculative window — the predictor still
guesses the flag value, the CPU still speculatively
executes the `if` body, the cache fill still happens. The
*shape* of the synchronization primitive is irrelevant.
What matters is whether the predictor commits to a value
before the architectural test resolves, and it does, by
the design of out-of-order speculation.

### 5.5 What GhostRace demonstrates structurally

```
            Synchronization architectural guarantee
            ────────────────────────────────────────
            ✅ Mutual exclusion enforced
            ✅ Memory ordering correct
            ✅ Happens-before preserved
            ✅ No race condition (in the classical sense)

            Microarchitectural reality
            ────────────────────────────────────────
            ❌ Speculative load completes before lock is checked
            ❌ Cache state leaked across the speculative window
            ❌ Timing side-channel observable by any co-located thread
```

The critical sentence: **functional correctness is not
confidentiality.** Concurrent programming guarantees the
*architectural state* converges to a well-defined sequence
of events. It does not guarantee that the speculative
states traversed on the way to that convergence are
themselves unobservable. The speculative window is *itself*
the side channel.

GhostRace's mitigation set is the speculation-barrier
family — `lfence` inside the lock-acquire path,
speculative-load-hardening compiler passes, retpoline for
the indirect-call variants. These work *because the
mitigation lives one layer up from the threat*. The
attacker's tool is the predictor's confidence; the
defender's tool is forcing the predictor to wait. The
asymmetry — *the threat is in the silicon, the defense is
in the compiler* — is the same asymmetry every other
section of this writeup has named.

**Assumption invalidated by GhostRace.** *Correct
synchronization implies the protected region's contents
are confidential against co-located threads.* The
corollary: synchronization protects *architectural state
transitions*; confidentiality against speculation requires
*separate* speculation-aware mitigations layered on top.

---

## 6. The Performance Contract — "Not a Bug"

### 6.1 The vendor response, decoded

Every microarchitectural attack since Spectre has been met
with the same vendor response: *"working as designed"*.
The phrasing is technically correct and operationally
misleading. The attacks *are* working as designed; the
design *is* the problem. The right reading is:

> The silicon was designed to optimize performance under
> a threat model that did not include the attacker's
> measurement capabilities. The attacker has measurement
> capabilities the threat model did not enumerate. The
> design is correct against the threat model the design
> was specified against. The threat model was wrong.

This is the structural fact that "not a bug" should
communicate but rarely does. It is the same answer to
Spectre, Meltdown, Foreshadow, MDS, Hertzbleed, VMScape,
and GhostRace — and the answer is *categorically* the
same. Each attack made visible an assumption the threat
model held silently. The fix is the threat model, not the
silicon.

### 6.2 The performance / confidentiality trade-off

```
┌────────────────────────────────────────────────────────────────┐
│                  CPU DESIGN TRADE-OFFS                          │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Feature                       Performance        Confidentiality│
│  ────────────────────────────  ────────────────  ───────────── │
│  Speculative execution               ✅                ❌       │
│  Shared L1 / L2 / L3 caches          ✅                ❌       │
│  Shared branch predictor             ✅                ❌       │
│  Shared TLB                          ✅                ❌       │
│  FPU/AVX register spill              ✅                ❌       │
│  Store-to-load forwarding            ✅                ❌       │
│  DVFS                                ✅                ❌       │
│  ────────────────────────────  ────────────────  ───────────── │
│  Full isolation per privilege       ❌                ✅       │
│  Speculation barriers at boundaries ❌                ✅       │
│  Cache partitioning per tenant      ❌                ✅       │
│  IBPB on every privilege xition     ❌                ✅       │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

Every row is a trade-off the silicon vendors made
explicitly. Speculative execution alone is worth roughly
20–40% performance gain on general-purpose workloads;
shared caches between SMT threads, 10–20%; shared branch
predictor across context switches, single-digit percent
but consistent. Adding up the rows, the silicon vendors'
estimate is that *strict per-privilege isolation* would
cost approximately 50–60% of modern CPU throughput.

That estimate is the unspoken reason every modern CPU is
shipped with the trade-offs on the left column rather
than the right. It is also the right place for a
defender to direct their critical reading: *the
mitigations exist; they cost performance; the question
is which workloads pay the cost*.

### 6.3 TEE as risk mitigation, not risk elimination

```
┌────────────────────────────────────────────────────────────────┐
│              TEE RISK MITIGATION MODEL                          │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Attack vector                  Without TEE       With TEE      │
│  ────────────────────────────  ──────────────   ──────────────  │
│  Root-level memory read              ✅              ❌           │
│  DMA from compromised device         ✅              ❌           │
│  Crash-dump analysis                 ✅              ❌           │
│  ────────────────────────────  ──────────────   ──────────────  │
│  Cache-timing attack                 ✅              ✅           │
│  Branch-predictor poisoning          ✅              ✅           │
│  Speculation-based leak              ✅              ✅           │
│  Hertzbleed-style DVFS observation   ✅              ✅           │
│  ────────────────────────────  ──────────────   ──────────────  │
│  Aggregate risk                     HIGH         MEDIUM         │
│                                                     ↑           │
│                                          architectural risks    │
│                                          eliminated;            │
│                                          microarch risks        │
│                                          mitigated, not removed │
└────────────────────────────────────────────────────────────────┘
```

The defender's correct position on TEE deployment is:
*the architectural threats in the upper block are
eliminated; the microarchitectural threats in the lower
block remain, with their attack difficulty raised but
their possibility not removed*. This is the right way
to read the Intel SGX deployment guidance, Microsoft's
VBS documentation, and AMD's SEV-SNP whitepaper. It is
not the way most deployment decisions are made.

### 6.4 "Not a Bug" applied per attack

| Attack       | Vendor response               | Actual structural fact                                                       | Mitigation layer            |
|--------------|--------------------------------|------------------------------------------------------------------------------|------------------------------|
| Spectre      | "Working as designed"          | Speculative execution is a design choice; the threat model omitted observability | Compiler + microcode        |
| Meltdown     | "Working as designed"          | Out-of-order load execution before privilege check, by design                  | Kernel page-table isolation |
| GhostRace    | "Working as designed"          | Predictor commits before lock-state resolves, by design                        | Speculation barriers        |
| VMScape      | "Working as designed"          | BTB/PHT survives VM exit, by design (performance)                             | IBPB on VM exit             |

The pattern: the design is correct against the threat
model the design was written against, the threat model
was wrong, and the defender pays the cost of correcting
the threat model. The silicon vendors are not the
defenders. The silicon vendors are the
performance-optimizing counterparty. The defender is the
one negotiating, in compilers and microcode and kernel
configuration, *which optimizations to decline in
exchange for the threat model the defender actually
needs*.

---

## 7. Conclusion

The single sentence at the bottom of this writeup is the
one a defender should carry forward:

> **Trust boundaries are architectural objects. The silicon
> beneath them does not implement boundaries — it
> implements a single shared microarchitectural fabric on
> which the boundaries are an interpretation. The
> attacker's job is to find an observation that operates
> below the interpretation. The defender's job is to
> enumerate, layer by layer, where the interpretation
> is load-bearing and where it is not.**

Read together, the layers and the case studies in this
writeup deliver one structural conclusion: **the threat
model needs two columns, one for architectural isolation
and one for microarchitectural isolation, and they do not
subsume each other**. A defender who has KPTI enabled,
IBPB on every privilege transition, retpoline at every
indirect call, and Cloak-style HTM fencing on
cache-sensitive operations has a *good* threat model. A
defender who has SGX deployed and considers the matter
settled has a *partial* threat model.

The VMScape side of the picture demonstrates that even the
hypervisor / VM boundary, the trust isolation cloud
providers sell most aggressively, has microarchitectural
channels that survive the architectural transition by
*design*. The GhostRace side demonstrates that the
concurrency-correctness arguments software has used for
fifty years — mutexes, atomics, happens-before — protect
architectural state but say nothing about the speculative
window that traverses that state in flight. Both attacks
exploit a single categorical fact: *the architecture's
contracts hold; the silicon's optimizations exceed the
contracts*.

The defender's response is the same as the response in
the sibling writeups: every threat lives one layer below
where the defense's tools live, and every mitigation is
the *deliberate decline* of an optimization the silicon
was built around. The boundaries exist; they hold against
the threats they were specified against; they do not hold
against threats specified after them. The work, going
forward, is the systematic specification of those
threats, the systematic mitigation across multiple
software-and-firmware layers, and the operational
discipline to keep the threat model honest as new
attacks land each calendar year.

The silicon will keep optimizing. The optimizations will
keep producing new shared-state surfaces. The trust
boundaries the architecture defines will keep being
useful for what they are — *contracts about architectural
behavior* — and will keep being insufficient for what
they are often treated as: *confidentiality guarantees
against an arbitrary microarchitectural observer*. The
difference between the two is the work of this writeup.

---

## References

[Cauligi et al. 2020] Cauligi, S., Disselkoen, C., Watt, C.,
  von Tessin, M., Brown, F., Stefan, D. *Constant-Time
  Foundations for the New Spectre Era.* PLDI 2020.

[VMScape 2026] Anonymous (ETH Zurich). *VMScape: Exposing
  and Exploiting Incomplete Branch Predictor Isolation
  Across VM Boundaries.* IEEE S&P 2026.

[GhostRace 2024] Ragab, H., Mambretti, A., Kurmus, A.,
  Giuffrida, C. *GhostRace: Exploiting and Mitigating
  Speculative Race Conditions.* USENIX Security 2024.
  CVE-2024-2193.

[VUSec GhostRace] VUSec Group. *GhostRace project page,
  SCUAF gadget scanner, PoC artifacts.* Vrije Universiteit
  Amsterdam, 2024.

[Foreshadow 2018] Van Bulck, J., Minkin, M., Weisse, O.,
  Genkin, D., Kasikci, B., Piessens, F., et al. *Foreshadow:
  Extracting the Keys to the Intel SGX Kingdom with
  Transient Out-of-Order Execution.* USENIX Security 2018.

[Spectre 2018] Kocher, P., Horn, J., Fogh, A., Genkin, D.,
  Gruss, D., Haas, W., et al. *Spectre Attacks: Exploiting
  Speculative Execution.* IEEE S&P 2019.

[Meltdown 2018] Lipp, M., Schwarz, M., Gruss, D., Prescher,
  T., Haas, W., Fogh, A., et al. *Meltdown: Reading Kernel
  Memory from User Space.* USENIX Security 2018.

[SafeSpec 2019] Khasawneh, K. N., Koruyeh, E. M., Song, C.,
  Evtyushkin, D., Ponomarev, D., Abu-Ghazaleh, N.
  *SafeSpec: Banishing the Spectre of a Meltdown with
  Leakage-Free Speculation.* DAC 2019. *(Microarchitectural
  mitigation design.)*

[oo7 2020] Wang, G., Chattopadhyay, S., Gotovchits, I.,
  Mitra, T., Roychoudhury, A. *oo7: Low-Overhead Defense
  Against Spectre Attacks via Program Analysis.* IEEE
  Trans. Software Engineering, 2020.

[Intel SDM] Intel Corporation. *Intel® 64 and IA-32
  Architectures Software Developer's Manual.* Volume 3:
  System Programming Guide. *(VMCS schema, IBPB / IBRS /
  STIBP semantics, microcode update model, SGX
  programming reference.)*

[Microsoft VBS] Microsoft Corporation. *Virtualization-
  Based Security (VBS) and the Secure Kernel.* Windows
  Internals documentation. *(VTL 0 / VTL 1 transition
  semantics, HyperGuard, Credential Guard.)*

[Linux kernel docs] *Hardware vulnerabilities documentation.*
  `Documentation/admin-guide/hw-vuln/`. *(Living index of
  kernel-side mitigations for Spectre / MDS / L1TF /
  GhostRace / VMScape families.)*

---

## Appendix A — Relationship to this collection

This writeup is the *vertical* trust-boundary read in a
cluster of three pieces that together map the post-2018
microarchitectural threat surface from three angles:

- **Mathematical Collapse** — the high-altitude theory.
  Argues classical mathematics is itself a DSL for a
  domain that does not include the silicon, and traces
  the collapse across six abstractions (continuous-and-
  discrete power, BTI aging, speculative ghost state,
  ISA atomicity, privilege isolation, verified
  compilers). The philosophical reason to distrust the
  architectural abstraction.

- **Silicon Is the Adversary** — the *horizontal* map.
  Treats seven post-2018 attack families (Spectre,
  Meltdown, Foreshadow, dedup-Rowhammer, Hertzbleed, and
  more) as instances of one categorical fact, and gives a
  layered defensive matrix showing which mitigation
  layer answers which threat. The structural map of the
  attack surface.

- **This writeup** — the *vertical* map. Walks five trust-
  boundary layers (user / kernel / hypervisor / VBS /
  TEE), names each layer's assumption-versus-reality
  gap, and unpacks two recent attacks (VMScape,
  GhostRace) that demonstrate the gap in different
  layers. The defender's threat-model checklist for
  boundary-based reasoning.

- **Speculation Barrier Illusion** — the *laser-focused*
  instance. CBMC-verified reproducible case study of
  "`lfence` stops speculation" as a category error
  between ISA-level speculation (which CBMC verifies)
  and microarchitectural speculation (outside the
  model's domain). The reproducible smallest case.

Read in order — Mathematical Collapse → Silicon Is the
Adversary → this writeup → Speculation Barrier Illusion —
the cluster reads as *theory → horizontal map → vertical
map → reproducible instance*. A defender finishing all
four has:

1. A philosophical reason to distrust the architectural
   abstraction.
2. A structural map of the post-2018 attack families.
3. A layer-by-layer threat-boundary checklist.
4. A model-checked instance of why the most-trusted
   speculation-stopper is misnamed.

The triple is engineered to be the reading list a
defender entering microarchitectural security in 2026
should finish first.

---

*This writeup is a structural reading of trust boundaries
in the post-2018 microarchitectural era. The intent is not
to enumerate exploit primitives but to make the
assumption-versus-reality gap legible at the layer of
detail a defender needs to operate against. With
acknowledgement to VUSec, ETH Zurich, KU Leuven, TU Graz,
and the academic communities whose systematic enumeration
of the threat surface this writeup synthesizes.*
