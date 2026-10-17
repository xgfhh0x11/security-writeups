---
title: "Silicon Is the Adversary"
subtitle: "Microarchitectural Threats from Spectre to Hertzbleed"
author: Utku Erol
date: "2026-05-16"
keywords: [microarchitectural security, Spectre, Meltdown, Foreshadow, Hertzbleed, speculative constant-time, memory deduplication, Rowhammer, side-channel, defensive engineering]
companion_writeup: "Speculation Barrier Illusion (focused single-instance case study of the same boundary)"
---

# Silicon Is the Adversary
## Microarchitectural Threats from Spectre to Hertzbleed

---

## Author's Note

The first time I read the original Spectre paper, I read it as a
bug — a specific defect in branch-predictor logic that some clever
engineers would patch in microcode and we would move on. That
reading is wrong, and the years since 2018 have made the wrongness
into a category. Spectre, Meltdown, Foreshadow, Rowhammer's
dedup-assisted variants, Hertzbleed, Augury — none of these are
bugs. They are the silicon doing what the silicon does, observed
through a channel the software-side threat model never knew to
include. The "bug" framing puts the failure inside the chip; the
correct framing puts it inside the model. There is no patch
forthcoming for a model error.

This writeup is the long form of that observation. The title is
deliberately blunt: **silicon is the adversary**. Not the vendor,
not a particular product line, not bad faith. The substrate itself.
Modern CPUs were optimized for performance over decades by engineers
who had every reason to expose state to whoever could pay attention,
and now we are the attention. The defender, in this picture, never
gets to operate at the silicon layer. Every mitigation lives one
abstraction up — a compiler pass, a kernel page-table layout, a
microcode patch landing in firmware updates, an algorithm
rewritten to keep its data path the same regardless of secret.
The asymmetry between threat layer and defense layer is the central
structural fact, and it is the fact this writeup is about.

What follows is six sections. The first re-reads Spectre and
Meltdown as a categorical shift rather than two attacks. The
second develops the strongest formal answer the academic community
has produced — Speculative Constant-Time and the Pitchfork
analyzer that decides it — and shows what it accepts and what it
gives up. The third walks the cross-domain primitive set that has
accreted since 2018: memory deduplication as an oracle, Rowhammer
as a write primitive, Foreshadow as an L1-cache decloak. The
fourth does Hertzbleed: not a cache attack, not a timing attack —
a power side-channel that the CPU itself converts into timing via
DVFS, the most uncomfortable demonstration to date that
"constant-time" was always a property of an abstraction and never
of the silicon. The fifth sketches what defenders actually have —
HTM-as-Cloak, partitioning, retpoline, KPTI — and is honest about
which of these answer the threats and which only push the boundary
one level deeper. The sixth concludes.

The unifying argument across all six sections: **the threat is
where the defense isn't, and that geometry is the problem to
think about, not any single CVE within it.**

---

## Abstract

This writeup is a structural reading of post-2018 microarchitectural
security. It treats Spectre, Meltdown, Foreshadow, the
deduplication-assisted Rowhammer family, and Hertzbleed not as a
catalogue of individual CVEs but as instances of a single
categorical fact: the silicon substrate produces observable
side-effects that the software-side threat model never modelled.
The contribution is the unifying frame ("silicon is the adversary")
plus a layered map of how defenders' tools — Speculative
Constant-Time, HTM-based cache cloaking, kernel page-table
isolation, microcode mitigation — sit *above* the threat layer and
why that asymmetry is the structural problem to reason about.
Each technical section ends with a paragraph naming the assumption
the corresponding attack invalidated and the abstraction at which
defense became newly possible (and impossible).

**Keywords:** microarchitectural security, Spectre, Meltdown,
Foreshadow, Hertzbleed, speculative constant-time, memory
deduplication, Rowhammer, side-channel, defensive engineering.

---

## 1. The Categorical Shift After 2018

### 1.1 Pre-2018 software security in three sentences

Before Spectre and Meltdown were disclosed in January 2018, the
software-side threat model treated the CPU as a deterministic
abstract machine. Architectural state — registers, memory,
flags — was the *only* state that mattered, and any optimization
the CPU performed under the hood (branch prediction, out-of-order
execution, cache replacement, store-to-load forwarding) was
defined to leave no observable trace beyond performance. The model
was inherited from textbook computer architecture and the von
Neumann picture, and it was the model every compiler, every
operating-system kernel, every cryptographic library, and every
formal verification tool had been built on top of.

That model was always wrong. It became *visibly* wrong on
2018-01-03.

### 1.2 Meltdown — the original-sin demonstration

Meltdown's PoC is a four-line pseudo-code that takes a Computer
Architecture II student about an afternoon to read and a senior
kernel engineer about a year to fully internalize:

```
mov rax, [kernel_secret]       ; would fault, but speculation runs anyway
shl rax, 12                    ; secret × 4096 → distinct cache line per value
mov rbx, [oracle + rax]        ; secret-dependent cache fill (transient)
                               ; → architectural rollback, but the cache state stays
```

The kernel-secret load faults; architectural state is rolled back;
*the cache fill happens anyway*. An attacker who can FLUSH+RELOAD
the `oracle[]` array reads which of the 256 possible cache lines
got warmed, and that index is the byte.

What is interesting about Meltdown is not the four lines. It is
that the assumption being broken — *speculative state has no
observable trace* — was load-bearing for the entire architectural
abstraction. Kernel page-table isolation (KPTI / KAISER) is the
mitigation: the kernel pages stop being present in the user-mode
page table at all, so even the speculative load cannot find an
address to fault on. KPTI is structurally a workaround. It does
not fix the model; it constructs a separate page-table view in
which the model happens to still be true for user space.

### 1.3 Spectre v1 — and the realization there will be many

Spectre v1 follows the same pattern, but it does not need a fault
to drive it — the misprediction itself is the vehicle.

```c
if (x < array1_size)
    y = array2[array1[x] * 4096];   // safe under bounds, but the predictor
                                    // can be trained to enter the branch
                                    // with an out-of-bounds x; the load
                                    // happens transiently, and array2
                                    // gets cache-warmed by the secret byte
```

What was *new* in Spectre's reading was not the leak channel — that
was already Meltdown. It was the realization that the misprediction
is **a primitive an attacker can construct on demand**, on
arbitrary user-controllable branches, without needing a privileged
fault. Branch predictors are global state. They are *trained*
state. The Spectre family explodes from this observation into v2
(branch target injection), v4 (store-to-load aliasing), v5 / Ret2spec
(return address prediction), and onward.

Spectre's mitigations are diverse and structurally unconvincing
when read together. Retpoline replaces indirect branches with a
trampoline that the predictor cannot poison. IBRS / IBPB ask the
CPU to flush predictor state at privilege boundaries. `lfence`
serializes execution at the program-order point it is placed.
Each of these works on *one* gap. None of them closes the category.

### 1.4 The ontological lift

The right reading of Spectre and Meltdown — together, not
separately — is the one a sibling writeup in this collection,
*Speculation Barrier Illusion*, names directly: there are two
distinct objects in the picture, and the threat model conflates
them. **ISA-level speculation** is the abstract-machine notion —
transient deviations from program order that the ISA's
formal semantics allows. **Microarchitectural speculation** is the
silicon notion — cache fills, predictor updates, branch-target
buffer writes, DRAM row activations, frequency adjustments.
The two have the same name and entirely different referents.
The defender's tools (`lfence`, retpoline, KPTI, IBRS) live in
the first category. The threats live in the second. Calling them
both "speculation" was the original sin.

This is not a vendor failure. It is a vocabulary failure with
real consequences. The rest of this writeup is what happens once
you read post-2018 microarchitectural attacks through that lens.

**Assumption invalidated by this section.** *Speculative state
has no observable trace.* The corollary the defender has to start
from now: every architectural optimization the CPU performs is, by
default, an information channel until proven otherwise. The
default direction of "proven" reverses post-2018: the prior is
*leaky*, and silence is the burden of proof.

---

## 2. Speculative Constant-Time

### 2.1 Why classical constant-time was not enough

For decades the rule for security-sensitive code was simple:
no secret-dependent branches, no secret-dependent memory accesses.

```c
// VULNERABLE — secret-dependent branch
if (secret_key[i] == 0)
    result = lookup_table[0];
else
    result = lookup_table[1];

// SAFE under the classical model — branchless, masked
uint8_t mask = (secret_key[i] == 0) ? 0xFF : 0x00;
result = (lookup_table[0] & mask) | (lookup_table[1] & ~mask);
```

The classical reading is correct *under the architectural
abstraction*. Both branches are taken in the data path; both
lookup-table reads are performed; the timing is symmetric and
the cache footprint is invariant under the secret.

After Spectre, neither claim holds. The microarchitecture is
allowed to *speculate* on a fictional branch the program never
took, and a branch predictor trained on the wrong direction will
produce a transient execution that touches secret-dependent
addresses regardless of how branch-free the source looks. The
guarantee evaporated; it was never grounded in the silicon.

### 2.2 The formal answer — Speculative Constant-Time

The academic response to this — most cleanly captured in *Constant-
Time Foundations for the New Spectre Era* (Cauligi, Disselkoen,
Watt, et al., PLDI 2020) — is a precise re-definition.

A program **P** is **Speculative Constant-Time (SCT)** if, for any
two initial configurations **C** and **C'** that agree on the
public inputs, executions of **P** under all *speculative*
schedules produce identical observation traces and identical
public final states:

$$
\forall\, C,\, C'.\;\; C \simeq_{\text{pub}} C'
\;\;\Longrightarrow\;\;
\Big(
  C \Downarrow^{O}_{D} C_1
  \;\Longleftrightarrow\;
  C' \Downarrow^{O'}_{D} C'_1
\Big)
\;\wedge\;
C_1 \simeq_{\text{pub}} C'_1
\;\wedge\;
O = O'.
$$

The novelty is *D*. **D** is the speculation schedule — the
adversary's choice of when to mispredict, what to speculate on,
how long to delay branch resolution, which store-to-load forwarding
hazard to inject. Classical constant-time asked the same question
without **D**; SCT adds it. A program is SCT iff its observable
trace is independent of secret inputs **across all D**.

The picture this draws is grim and clarifying:
- **Public equivalence** is preserved (`C ≃_pub C'`). The defender's
  contract about public data still holds.
- **Observation equivalence** must hold under *every* schedule the
  adversary can construct. The adversary is no longer just the
  network observer or the cache-occupancy observer; the adversary
  is *also* the branch-predictor trainer, the store-buffer
  filler, the cache pressure manufacturer.
- **D ranges over schedules, not over programs.** SCT is a
  property of the *interaction* between the program and the
  microarchitecture's degrees of freedom.

Classical CT was a property of the program in isolation. SCT
acknowledges there is no such thing as the program in isolation;
there is only the program-on-the-substrate, and the substrate is
the adversary.

### 2.3 Pitchfork — deciding SCT in practice

The companion contribution is the Pitchfork analyzer. Its
architecture is what an honest SCT check looks like when you
stop assuming the silicon is friendly:

```python
class PitchforkAnalyzer:
    def __init__(self, speculation_bound=250):
        self.bound = speculation_bound
        self.schedules = []

    def generate_worst_case_schedules(self, program):
        # Branch-misprediction schedules: explore both
        # directions and delay branch resolution
        for branch in program.branches:
            self.schedules.append(Schedule([
                Fetch(branch, predicted=True),
                Fetch(branch, predicted=False),
                # ... delay branch resolution by N μops ...
            ]))

        # Store-forwarding hazard schedules: load reads forwarded
        # data from an aliasing store before address resolution
        for load in program.loads:
            for store in program.stores_before(load):
                if may_alias(load, store):
                    self.schedules.append(Schedule([
                        Execute(store, resolve_addr=False),
                        Execute(load, forward_from=store),
                    ]))

    def check_sct(self, program):
        for schedule in self.schedules:
            observations = self.symbolic_execute(program, schedule)
            if self.has_secret_leakage(observations):
                return VIOLATION
        return SAFE
```

Two observations about this architecture:

1. **The schedule enumerator is the threat model.** Pitchfork's
   "worst case" is not arbitrary — it is exactly the set of
   speculative behaviors documented in vendor architectural
   guidelines for Intel and AMD, plus the academic-literature
   primitives (LVI, MDS variants, store-to-load). When a new
   primitive lands, the enumerator extends. This is what an
   honest defender's tool looks like: it admits, structurally,
   that the enumerator is incomplete.
2. **The bound is finite.** `speculation_bound=250` is the
   reorder-buffer depth on a typical Skylake-class core. The
   tool does not say "secret never leaks"; it says "secret
   does not leak under any schedule of length ≤ 250 μops *with
   the speculative primitives I know about*". Soundness is
   conditional. Completeness is structural.

### 2.4 What SCT accepts, what it gives up

SCT is the strongest software-side answer. What it gives the
defender:

- A *property to verify*, not a heuristic. Tools like Pitchfork,
  Spectector, and Blade decide it.
- A clean compositional handle: SCT composes — an SCT subroutine
  called from an SCT context stays SCT. Classical CT did not
  have this property cleanly under speculation.
- A way to talk about partial mitigation: "SCT under the v1+v4
  schedule set" is a meaningful claim, distinct from "SCT under
  v1+v2+v4+v5".

What it gives up:

- **Performance.** An SCT implementation of a cryptographic
  primitive is roughly 1.5–4× slower than its classical-CT
  equivalent, because every potentially-speculative branch
  must be lfenced or hardened with speculative-load-hardening
  masks. The cost is real and most production crypto libraries
  do not yet pay it.
- **Soundness against schedule extensions.** If a new
  microarchitectural primitive ships in a 2027 CPU that the
  enumerator does not know about, an SCT-verified program is
  no longer SCT against it. The verification is *only as
  current as the schedule set*.

This is the central honesty SCT enforces and the central
honesty most informal "we are constant-time" claims still
refuse to make. **The defense lives at the source-language and
compiler level; the threat continues to live at the silicon
level; the relationship between them is rented, not owned.**

**Assumption invalidated by this section.** *Branch-free
source code prevents secret-dependent execution.* The corollary:
branch-freeness is necessary but not sufficient; the silicon may
speculate on branches the source did not contain.

---

## 3. Cross-Domain Primitives

The post-Spectre threat surface is not a list of cache attacks.
It is a kit. Each new primitive crosses *one more boundary* that
the software-side threat model used to call solid. This section
walks three: memory deduplication (the OS abstraction crosses the
process boundary), Rowhammer (electrical row interference crosses
the page boundary), and Foreshadow (the cache crosses the SGX
enclave's encryption boundary).

### 3.1 Memory deduplication as a side-channel oracle

Same-content page deduplication (Linux's KSM, VMware's TPS,
Windows' shared memory) is a memory-saving optimization: two
processes (or two VMs) that hold a page with identical contents
get backed by a single physical page, copy-on-write enforced if
either writes. The performance win on cloud infrastructure was
large enough to ship.

The attack — *Dedup Est Machina* (Bosman et al., S&P 2016) and
follow-ups — is straightforward once read structurally:

```c
bool alignment_probe(uint8_t *secret_page, int offset) {
    uint8_t *probe = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    memset(probe, 0xAA, 4096);                  // known bulk
    probe[offset] = guess_byte;                 // attacker's guess for
                                                // secret_page[offset]

    madvise(probe, 4096, MADV_MERGEABLE);       // tell KSM "merge me"

    // Wait for KSM scan cycle; if guess matched secret_page[offset],
    // the two pages now share a physical frame copy-on-write.

    uint64_t t0 = rdtsc();
    probe[offset] = 0xCC;                       // first write after merge
    uint64_t t1 = rdtsc();

    return (t1 - t0) > CoW_THRESHOLD;           // slow = CoW fired = merged
}
```

Each guess costs one CoW-fault timing measurement. 256 guesses
extract a byte. The attacker's process and the victim's process
share *nothing* by software contract — different address spaces,
different protection rings, possibly different containers — and
the leak is mediated by an OS optimization that operates *above*
both of them.

The primitive's defensive answer is to turn deduplication off, or
to scope it (per-VM, never cross-tenant). This is the cheapest
answer in the writeup. It also illustrates the pattern: the
mitigation lives outside the layer the attack lives in. The
attack lives in the OS scheduler's same-content scanner; the
mitigation lives in the OS's deployment policy.

### 3.2 Rowhammer — the write primitive the architecture said could not exist

Rowhammer (Kim et al., ISCA 2014) is the demonstration that DRAM
electrical row interference is *exploitable*, not just a noise
phenomenon. Rapidly activating two adjacent rows (Row N-1 and
Row N+1) discharges cells in the row between them (Row N), and
some cells flip. The architectural abstraction said the page table
was the boundary; DRAM said the row was.

```
Row N-1     [Hammer]     // attacker-controlled
Row N       [Target]     // victim page — bit flip here
Row N+1     [Hammer]     // attacker-controlled
```

Pre-2014 software security never modelled DRAM rows because it
never needed to. The MMU was supposed to provide the abstraction:
a page belongs to a process; another process cannot reach it. DRAM
does not honor the abstraction. DRAM cells are physical things,
neighbors leak, and Rowhammer is the systematic reading of that
fact.

The interesting modern combination is **dedup + Rowhammer**:

```c
void rowhammer_dedup_attack() {
    uint64_t *victim_ptr = leak_pointer_via_dedup();
    FakeObject  fake     = build_fake_with_attacker_vtable();

    rowhammer_flip_bit(victim_ptr, /*bit_index=*/ 12);
    // victim's pointer now points into the fake object

    victim_function(victim_ptr);  // type confusion → code reuse
}
```

Deduplication leaks the pointer; Rowhammer mutates it. The
attacker never crossed the MMU boundary by abusing software; the
attacker mutated DRAM physically and got the MMU to dereference
the mutation. The page-table abstraction is intact for software
that doesn't know to worry. The silicon does what the silicon
does.

The defensive answer set for Rowhammer is ECC-aware DRAM (parity
catches single-bit flips, larger code catches more), target row
refresh (TRR, in DRAM controllers), and PARA / probabilistic row
adjacent activation. All three live in the DRAM controller and
DIMM design, not in the operating system. The defense layer is
*below* the OS, in firmware-and-silicon land. The attack layer is
*at* DRAM. They almost coincide; the defender is finally allowed
to be at the same depth as the attacker, and the cost was
redesigning the memory controller.

### 3.3 Foreshadow — the L1 cache is plaintext, the DRAM is not

Intel SGX promised an enclave whose memory is encrypted in DRAM
and decrypted only inside the cache hierarchy. The threat model
named the operating system as untrusted. The architecture said:
even a root user, even a kernel driver, cannot read enclave
plaintext, because the memory encryption engine (MEE) sits
between cache and DRAM and the OS never reaches the cache side
of MEE.

Foreshadow (Van Bulck et al., USENIX Security 2018) is the
observation that **the L1 data cache holds enclave plaintext** —
because that is the whole point of caching — and the same
Meltdown-style transient-execution primitive that reads kernel
memory can read enclave memory if it is in L1 at the right
moment.

```c
// Phase 1: bring enclave secret into L1
ecall_victim_function();

// Phase 2: transient read of "inaccessible" enclave page
mprotect(secret_va & ~0xFFF, 0x1000, PROT_NONE);
asm volatile(
    "movb (%1), %%al\n\t"
    "shl  $12, %%rax\n\t"
    "movq (%2, %%rax), %%rdi\n\t"
    :
    : "r"(secret_va), "r"(oracle)
    : "rax", "rdi", "memory");
// Page fault, architectural rollback. Cache trace remains.

// Phase 3: FLUSH+RELOAD the oracle.
for (int i = 0; i < 256; i++) timed_read(oracle + i*4096);
```

The follow-on demonstration is the *launch enclave* attack: the
authors used Foreshadow to extract the 128-bit launch key that
authorizes other enclaves to ship as production. The structural
break is one level beneath SGX's MEE: SGX assumes the cache and
the CPU pipeline are inside the trust boundary; Foreshadow
demonstrates that *speculative execution can read cache state
that the trust boundary said was unreachable*. SGX's
encryption is correctly implemented in DRAM. It is irrelevant.
The attack does not happen in DRAM.

The Intel mitigation (L1 cache flush on transitions, SGX
microcode update) closes this particular gap. The structural
fact — *trusted compute boundaries assumed a cache that does
not exist* — does not get closed by any single mitigation. It is
documented and lived with.

### 3.4 The pattern

All three primitives have the same shape:

| Primitive       | Layer the attack lives at         | Layer the abstraction was at  |
|-----------------|------------------------------------|-------------------------------|
| Dedup           | OS same-content scanner             | Process boundary              |
| Rowhammer       | DRAM cell-level interference         | Page boundary                 |
| Foreshadow      | L1 cache plaintext + transient exec  | SGX MEE / DRAM encryption     |

In each case the attack lives one level *below* where the
defender's model said the boundary was. In each case the
mitigation, when it lands, lives at the attack's layer or one
level beneath it. The defender is *always relocating downward*,
and the relocation costs are paid in firmware redesigns, memory
controllers, microcode updates — the parts of the stack the
software-security community does not typically touch.

**Assumption invalidated by this section.** *Software-defined
trust boundaries (process, page, enclave) survive at the silicon
level.* The corollary: every software boundary needs to be
re-derived from a model of the silicon underneath it before it
can be relied on for secrecy.

---

## 4. Power → Frequency → Timing — Hertzbleed and SIKE

Hertzbleed (Wang, Paccagnella, et al., USENIX Security 2022) is
the cleanest demonstration of the central thesis in this
writeup, because it stages the silicon-is-adversary point as
literal physics.

### 4.1 The chain

Modern Intel and AMD CPUs implement **DVFS** — dynamic voltage
and frequency scaling — to stay inside the thermal design power
envelope while still delivering peak performance when the
workload allows it. Higher instantaneous power draw → CPU clocks
down to stay within TDP → the same workload now finishes slower.
The frequency adjustment is *deterministic given the power*, and
power is a function of the data being computed:

$$
P \;=\; \alpha \cdot \mathrm{HW}(d) \;+\; \beta \cdot \mathrm{HD}(d, d_{\text{prev}}) \;+\; \gamma
$$

- **HW(d)** is the Hamming weight of the current data — the
  number of 1-bits, dominating static switching cost.
- **HD(d, d_prev)** is the Hamming distance between this and the
  prior data — the bit transitions, dominating dynamic switching.
- **α, β, γ** are silicon-specific coefficients an attacker can
  characterize once and reuse forever.

Frequency is a (decreasing) function of power:

$$
F \;=\; f(P), \quad f'(P) < 0.
$$

Wall-time over a fixed-instruction-count workload becomes:

$$
T \;\propto\; \frac{N}{F} \;\propto\; \frac{N}{f(P)}.
$$

A secret that influences the data being computed influences HW
and HD, which influence P, which influences F, which influences
T. **Constant-time code, written constant-time, executes in
secret-dependent wall-time on modern silicon.** The chain is

> *secret → bit pattern → power → DVFS → frequency → wall-time.*

The chain is not exotic. Every link is documented in vendor
documentation. The chain's *implication* — that the program's
clock-cycle count and its wall-time disagree on what they measure
— was simply never read together.

### 4.2 SIKE and the anomalous-zero ladder

Hertzbleed's headline demonstration is on SIKE — the
Supersingular Isogeny Key Encapsulation candidate from
NIST PQC Round 3. SIKE's Montgomery three-point ladder is
written constant-time:

```c
// SIKE Algorithm 1: three-point ladder, branch-balanced
Point ladder3pt(Integer m, Point P, Point Q, Point Q_minus_P) {
    Point X0 = Q, X1 = P, X2 = Q_minus_P;
    for (int i = 0; i < bit_length(m); i++) {
        if (m[i] == 1)  (X0, X1, X2) = xDBLADD(X0, X1, X2, A);
        else            (X0, X2)     = xDBLADD(X0, X2, X1, A);
    }
    return X1;
}
```

The branches are balanced. The data flow is symmetric. Under the
architectural abstraction this is constant-time. The attack:
craft a challenge ciphertext such that on a *specific* bit, the
intermediate point lands on the curve's identity element (the
"anomalous zero"). When the ladder hits the identity, subsequent
field-arithmetic operations *simplify drastically* — fewer
multiplications, sparser intermediate data, lower HW and HD.
Lower switching activity → lower power → higher DVFS frequency →
shorter wall-time.

The attacker times the decapsulation, not from a co-located
process, not from a cache-monitoring vantage, but **remotely
over the network**. Bit-by-bit, the secret key falls out:

| Bit range       | Signal strength     | Wall-time difference     |
|-----------------|----------------------|---------------------------|
| 0–19            | Strong               | Trivially separable       |
| 20–344          | Moderate             | Reliable                  |
| 345–364         | Weak                 | Increasing noise          |
| 365–377         | Lost                 | Brute-force (14 bits)     |

Total: 36 hours against the CIRCL implementation, 89 hours
against PQCrypto-SIDH, both running production-grade
constant-time SIKE.

### 4.3 What Hertzbleed actually proves

The temptation is to read Hertzbleed as a SIKE bug. It is not.
SIKE was correct under the architectural abstraction the
constant-time community had been using for thirty years. The
*abstraction* failed. Frequency, in the abstraction, was a
parameter the program did not control and the attacker could not
observe. In the silicon, frequency is *a function of the data
the program is computing*, observable by anybody who can time
the program.

The defensive answer set is two-layered. Inside the program,
you can no longer assume that masking and branchlessness give
you wall-time independence; you have to also keep HW and HD
of the data path invariant under the secret, which is a much
harder problem. Outside the program, you can disable DVFS
(frequency capping) — accepting the performance loss in exchange
for the abstraction being true again. Frequency capping is what
TLS implementations now use for SIKE-class algorithms. It is the
defensive answer, and it is *abandoning the optimization the
silicon was built around*. The defender, again, lives one
abstraction up; the silicon does what the silicon does; the
mitigation is the silicon's optimization being declined.

**Assumption invalidated by this section.** *Constant
instruction count implies constant wall-time.* The corollary:
the program and the silicon disagree on what "constant" means,
and the disagreement is observable to a remote attacker.

---

## 5. The Mitigation Lives Elsewhere

This section is the structural map of what defenders actually
have. It is honest about which mitigations answer the threats
of §1–§4 and which only re-locate the threat boundary.

### 5.1 The Cloak approach — HTM as cache enforcement

The Cloak system (Gruss et al., USENIX Security 2017) is the
most architecturally interesting defense in the post-Spectre
era because it co-opts a feature (Intel TSX hardware
transactional memory) into a use it was never designed for.

TSX gives the program two sets — a **read set** of cache lines
the transaction has read, and a **write set** of cache lines it
has written. Any external eviction of a read-set line, any
external write to a read-set line, or any L1 capacity overflow
aborts the transaction. Cloak's insight: that abort condition
is *exactly* the signature of a cache-side-channel attack.
Prime+Probe evicts cache lines to measure occupancy; that
eviction would abort the TSX transaction. FLUSH+RELOAD flushes
cache lines to measure subsequent reload time; that flush would
abort.

```c
if (xbegin() == XBEGIN_STARTED) {
    preload_secret_path_into_read_set();      // 31 KB read set
    preload_code_into_read_set();             // each cache line via call
    sensitive_operation();                    // runs entirely in L1
    xend();
} else {
    handle_abort();                            // attacker tried — abort
}
```

Empirically measured abort rates on AES T-table operations
inside a Cloak-protected transaction:

| Workload                    | Abort rate                  |
|-----------------------------|------------------------------|
| Baseline, no attacker        | 0%                          |
| With Prime+Probe attacker     | 82.7%                       |
| With FLUSH+RELOAD attacker    | 99.97%                      |

The cost is real: SGX decision-tree workloads inside Cloak run
at +79% to +248% overhead depending on batch size, and TSX has
been disabled by microcode update on most Intel parts post-2019
due to *unrelated* attacks (TAA, ZombieLoad). Cloak as deployed
is mostly historical.

The interesting *structural* fact remains. Cloak demonstrated
that a transactional-memory primitive — sold for performance
reasons — could be turned into a cache-side-channel defense by
treating the abort condition as the defense's positive signal.
The defense, again, lived *one layer up* from the silicon: the
transaction's failure semantics were the abstraction; the cache
behavior was the silicon.

### 5.2 Partitioning — the brute-force answer

The next category of defense is partitioning: ensure attacker
and victim cannot share the resource the side-channel travels
on. Cache partitioning (Intel CAT / Cache Allocation
Technology) lets the OS assign last-level-cache ways to
specific cores or processes. Memory bandwidth partitioning
(MBA) does the same for memory bandwidth. Hyper-threading
disablement — turned on at most cloud providers post-MDS — is
the partitioning answer applied to logical-core sharing.

Partitioning works. It is also the cheapest in engineering
effort and the most expensive in deployed performance. A
hyperscaler that disables hyper-threading globally is leaving
~20% of its compute on the floor. The conversation is not
about whether partitioning is a defense; it is about whether
the secret being protected is worth the partition's cost. The
defense is *paying for itself*, in performance, in workload
density, in capex.

### 5.3 Kernel-side: retpoline, IBRS, KPTI

The Spectre-family mitigations are now standard kernel infrastructure
on every supported Linux/Windows build. Their composition is
informative:

| Mitigation        | Target attack vector                | Mechanism                                       |
|-------------------|--------------------------------------|--------------------------------------------------|
| KPTI / KAISER     | Meltdown                             | Separate page table for user mode (no kernel pages)|
| Retpoline         | Spectre v2 (BTI)                     | Replace indirect jump with predict-trap thunk   |
| IBRS / IBPB / STIBP | Spectre v2 (BTI)                   | Microcode: flush predictor on privilege transition |
| SSBD              | Spectre v4 (SSB)                     | Disable speculative store bypass on demand       |
| Microcode TSX/Async-Abort fixes | TAA, ZombieLoad      | Microcode patch                                  |

Two things to note. First, every entry except KPTI is microcode-
adjacent — the defender is reaching into a layer (microcode)
that historically was vendor-only and is now part of the
operating-system trust boundary by necessity. Microcode updates
ship in initrd. They are read by the BIOS and the OS both. The
attack surface of "microcode update channel was tampered with"
is now part of the threat model. The defense layer kept moving
down until it ran into firmware.

Second, the performance impact composes. KPTI is ~5–10% on
syscall-heavy workloads. Retpoline is ~3% on indirect-call-
heavy workloads. SSBD's per-process or per-syscall toggle is
~2–5% on relevant code. A modern Linux server runs all of
these. The performance recovery, in 2026, has been claw-back
work by silicon vendors implementing the mitigations in
hardware (Intel CET shadow stack, AMD's AutoIBRS, ARM's BTI),
which is the defense layer finally being granted residence at
the silicon level — by silicon vendors, not by defenders.

### 5.4 Compiler-side: speculative load hardening, SCT-aware codegen

The compiler community has added speculative-load-hardening
(SLH) passes to LLVM and GCC that compile sensitive code with
data-dependent index masks that *track* the predicted/actual
branch direction and zero out loaded data on a misprediction.
The SCT-aware compilation effort (Blade, Spectector,
Pitchfork) gives a defender a path to verified SCT for
specific workloads.

This is the layer at which defense most cleanly *answers*
threats from §1–§2. The compiler can re-shape code into a form
that the speculative microarchitecture cannot exploit. The
cost is the 1.5–4× performance hit named in §2.4. The benefit
is a verified property, not a heuristic.

### 5.5 The structural map

Each row of the map below is one of the threats discussed.
Each column is the layer the defense lives at.

| Threat              | Microcode                  | Kernel                   | Compiler                 | Application                       | Operational           |
|---------------------|-----------------------------|---------------------------|---------------------------|-----------------------------------|------------------------|
| Spectre v1          | —                           | —                         | SLH, SCT-aware codegen    | `lfence` at audited points         | —                      |
| Spectre v2          | IBPB, IBRS                  | Retpoline                 | —                         | —                                  | —                      |
| Meltdown            | —                           | KPTI                      | —                         | —                                  | —                      |
| Foreshadow / L1TF   | L1 flush on transitions      | Per-tenant cache scrub    | —                         | Avoid SGX for adversarial tenants | —                      |
| Hertzbleed          | —                           | DVFS-disable policy        | Frequency-cap directive    | HW/HD-invariant rewriting          | Frequency capping       |
| Memory dedup        | —                           | KSM disablement           | —                         | —                                  | Per-VM dedup scoping    |
| Rowhammer           | DRAM TRR, PARA              | —                         | —                         | —                                  | ECC RAM procurement     |
| Cache side-channels | —                           | CAT partitioning          | —                         | Cloak (HTM-as-fence, historic)     | Hyperthreading disable |

What the map shows: **no row has a single-layer answer**. Every
real-world defense is a composition across at least two columns,
and the most expensive deployments compose four or five. The
defender's life, post-Spectre, is *spreading the defense across
layers because no single layer has the leverage to close the
threat alone*.

This is the structural fact the title of the writeup names.
Silicon is the adversary because the silicon is, definitionally,
the layer none of the defender's tools live in.

---

## 6. Conclusion

The eight-year arc from Spectre to Hertzbleed is, read together,
a single argument. Microarchitectural optimization is a
substantive engineering achievement; modern CPUs do extraordinary
things to extract performance from silicon. They also, by the
same engineering process, expose state that the software
abstraction had been written under the assumption was hidden.
The exposure is not a defect to be patched. It is the silicon
doing exactly what it was designed to do, observed through a
channel the abstraction did not enumerate.

The defender's response, layered across firmware, microcode,
kernel, compiler, and application, is the right shape — but it
is best understood as *a continuing renegotiation of the
contract between software and silicon*, not as a security
checklist that can be completed. Each new attack invalidates
one more assumption that was sitting unstated in the
abstraction. Each new mitigation re-establishes the assumption
at a cost. The contract is rented; the rent is paid in
performance, in deployment complexity, in microcode-update
channels, in compiler passes, in operational policy.

A defender entering this field in 2026 inherits eight years of
that renegotiation. The right reading discipline is the one
this writeup has tried to demonstrate: read each attack for the
assumption it invalidates, locate the layer where the
mitigation lives, and accept that the gap between the attack's
layer and the mitigation's layer is itself the structural
problem — not a missing CVE, not a vendor failure, not an
inevitable consequence to be patched, but a *geometric fact*
about how the field is built.

The silicon will keep optimizing. The optimizations will keep
producing observable state. The threat model will keep
expanding *downward*, into firmware, into DRAM controllers,
into MSR-exposed thermal sensors, into the next layer of
silicon engineering that has not yet been read as a side
channel. There is no version of this story that ends with
silicon-as-defender; there is only the version that ends with
the defender's tools matured at every layer above silicon and
the operational discipline to compose them.

That is the work.

---

## References

[Kocher et al. 2018] Kocher, P., Horn, J., Fogh, A., Genkin, D.,
  Gruss, D., Haas, W., et al. *Spectre Attacks: Exploiting
  Speculative Execution.* IEEE S&P 2019.

[Lipp et al. 2018] Lipp, M., Schwarz, M., Gruss, D., Prescher, T.,
  Haas, W., Fogh, A., et al. *Meltdown: Reading Kernel Memory
  from User Space.* USENIX Security 2018.

[Cauligi et al. 2020] Cauligi, S., Disselkoen, C., Watt, C.,
  von Tessin, M., Brown, F., Stefan, D. *Constant-Time
  Foundations for the New Spectre Era.* PLDI 2020.
  *(Speculative Constant-Time, Pitchfork analyzer.)*

[Van Bulck et al. 2018] Van Bulck, J., Minkin, M., Weisse, O.,
  Genkin, D., Kasikci, B., Piessens, F., et al. *Foreshadow:
  Extracting the Keys to the Intel SGX Kingdom with Transient
  Out-of-Order Execution.* USENIX Security 2018.

[Wang et al. 2022] Wang, Y., Paccagnella, R., He, E. T.,
  Shacham, H., Fletcher, C. W., Kohlbrenner, D. *Hertzbleed:
  Turning Power Side-Channel Attacks Into Remote Timing Attacks
  on x86.* USENIX Security 2022.

[Bosman et al. 2016] Bosman, E., Razavi, K., Bos, H., Giuffrida,
  C. *Dedup Est Machina: Memory Deduplication as an Advanced
  Exploitation Vector.* IEEE S&P 2016.

[Kim et al. 2014] Kim, Y., Daly, R., Kim, J., Fallin, C., Lee,
  J. H., Lee, D., et al. *Flipping Bits in Memory Without
  Accessing Them: An Experimental Study of DRAM Disturbance
  Errors.* ISCA 2014. *(Rowhammer foundational paper.)*

[Gruss et al. 2017] Gruss, D., Lettner, J., Schuster, F.,
  Ohrimenko, O., Haller, I., Costa, M. *Strong and Efficient
  Cache Side-Channel Protection using Hardware Transactional
  Memory.* USENIX Security 2017. *(Cloak.)*

[Schwarz et al. 2019] Schwarz, M., Lipp, M., Moghimi, D.,
  Van Bulck, J., Stecklina, J., Prescher, T., et al.
  *ZombieLoad: Cross-Privilege-Boundary Data Sampling.*
  ACM CCS 2019. *(Microarchitectural Data Sampling family.)*

[Ragab et al. 2021] Ragab, H., Milburn, A., Razavi, K., Bos, H.,
  Giuffrida, C. *Crosstalk: Speculative Data Leaks Across
  Cores Are Real.* IEEE S&P 2021.

[Intel SDM] Intel Corporation. *Intel® 64 and IA-32
  Architectures Software Developer's Manual.* Volumes 2 and 3.
  *(MSR specifications, microcode update semantics, MDS
  mitigation guidance.)*

[ARM ARM] ARM Limited. *Arm® Architecture Reference Manual for
  A-profile (Armv8-A).* Section D5 (Pointer Authentication),
  Section B2 (Memory Model). *(PAC, BTI.)*

[Linux kernel docs] *Hardware vulnerabilities documentation.*
  `Documentation/admin-guide/hw-vuln/`. *(Living index of
  kernel-side mitigations for the Spectre/MDS/L1TF/Hertzbleed
  families.)*

---

## Appendix A — Relationship to this collection

This writeup sits at the wide-survey end of a cluster of
collection pieces that all read microarchitectural security as
*a structural problem*, not as a list of CVEs.

- *Mathematical Collapse* gives the general theory across six
  abstractions (continuous-and-discrete power, BTI aging,
  speculative ghost state, ISA atomicity, privilege isolation,
  verified compilers). It is the high-altitude argument that
  classical mathematics is itself a DSL for a domain that does
  not include the silicon we run on.

- *Speculation Barrier Illusion* is a focused single-instance
  case study at the laser end: it shows, through a complete
  CBMC bounded-model-check, that "`lfence` stops speculation"
  is a category error between ISA-level speculation (which
  CBMC verifies) and microarchitectural speculation (which
  exists outside the model's domain). It is the clean
  reproducible instantiation of one row of the table in §5.5.

- This writeup is the wide-survey middle. It treats seven
  attack families as instances of the same categorical fact
  and walks the defender's response across all of them, in
  the same structural register.

Read in order — Mathematical Collapse → this writeup →
Speculation Barrier Illusion — the cluster reads as
*theory → map → reproducible instance*. The defender finishing
the three has, in roughly that order:

1. A philosophical reason to distrust the architectural
   abstraction.
2. A structural map of the threats that distrust applies to.
3. A reproducible, model-checked demonstration of why the
   defender's most-trusted tool against one of those threats
   is misnamed.

That triple is the contribution the cluster is engineered to
make. This writeup is the middle of the triple.

---

*This writeup is a structural reading of an eight-year
research arc. The intent is not to celebrate the attacks or
to indict the silicon, but to make the geometry of post-Spectre
microarchitectural security legible to a defender who is just
arriving. With acknowledgement to the academic communities — at
TU Graz, IBM Research, ETH Zurich, Tel Aviv University,
Vrije Universiteit Amsterdam (VUsec), UIUC, KU Leuven, and many
others — whose patient enumeration of the threat surface this
writeup synthesizes.*
