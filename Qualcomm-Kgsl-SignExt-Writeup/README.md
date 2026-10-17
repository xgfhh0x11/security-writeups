---
title: "The Alignment Collapse"
subtitle: "Sign Extension, Invariant Breakdown, and the Epistemology of Silent Overflow in the Qualcomm kgsl Graphics Driver (CVE-2026-21385)"
author: Utku Erol
date: "2026-05-17"
keywords: [integer overflow, sign extension, CWE-190, kgsl, Qualcomm graphics, domain narrowing, precondition enforcement, invariant collapse, type confusion, kernel privilege escalation, CISA KEV, emergent inconsistency, cross-layer visibility, CWE-190]
companion_writeup: "Mathematical-Collapse-Writeup — formal invariant collapse at the hardware-software interface; BFS2019-Master-Writeup — kernel exploitation chain anatomy"
---

# The Alignment Collapse
## Sign Extension, Invariant Breakdown, and the Epistemology of Silent Overflow in the Qualcomm kgsl Graphics Driver (CVE-2026-21385)

> **Cluster siblings:** *Mathematical Collapse*, *Silicon Is the Adversary*, *BFS2019 Master Writeup*, *Speculation Barrier Illusion*.
> **Collection role:** low-level exploitation laser; primary focus on cross-layer invariant failure and the structural reason silent overflows survive tooling.

---

## Author's Note

There is a category of kernel vulnerability that is more interesting than a null dereference or a use-after-free, not because it is necessarily harder to trigger, but because it is architecturally revealing. CVE-2026-21385 belongs to that category.

The surface description is unremarkable: an integer overflow in Qualcomm's `kgsl` graphics driver that allows a malicious application to corrupt kernel memory and escalate privileges. CWE-190, CVSS 7.8, active exploitation in the wild, CISA Known Exploited Vulnerabilities list. The disclosure record is clean and the patch is obvious — a one-line cast change and three boundary checks.

What makes this worth a careful read is not the mechanism but the *structure* of the failure. The bug is not a miscalculation in the ordinary sense. Every individual operation in the vulnerable path is semantically valid at the layer where it executes. The cast from `uint32_t` to `int32_t` is legal C. The `align_up` computation is arithmetically correct given its inputs. The kernel allocator accepts the resulting size without complaint. The write that follows the allocation is the first operation in the entire chain that violates a postcondition — and by that point, the original input that caused the violation has been processed, transformed, and structurally forgotten across three intermediate layers.

This is what the bug is about: *distributed wrongness*. The error is introduced at layer one, carried silently through layers two and three, and made visible only at layer four, where the information needed to reconstruct the causal chain is no longer in scope. The four layers are not pathological; they are the ordinary pipeline of a POSIX-style kernel driver. What is pathological is the absence of any cross-layer consistency check — any mechanism that asks, at any intermediate point, "does the value I am passing downstream preserve the invariant that the calling contract assumed?"

The formal framing is direct. The allocation invariant is universal:

$$
I_{alloc}:\ \forall\ \text{write}(p, n):\ p + n \leq \text{alloc\_end}(p)
$$

To violate a universal invariant, an attacker needs exactly one counterexample. The structural asymmetry between the defender's obligation (every input must be safe) and the attacker's requirement (one input sufficient) is not a cryptographic observation — it is a logical one. What CVE-2026-21385 demonstrates is that the asymmetry can be exploited at a type-system level, in a component that no static analyzer flagged, because the invariant the attacker violates is *semantic* (alignment values must be positive) and the type system enforces only *syntactic* validity.

The fix does not change `align_up`. It changes the domain from which `align_up` may be called. This is domain narrowing by precondition — the standard response when a function has a narrow valid domain and the code around it was not enforcing that narrowness. The response is structural, not mechanical. It belongs to the same family as the formal-verification-era approach of strengthening preconditions at trust boundaries rather than hardening function bodies against all inputs.

This writeup is an anatomical study of that structure. The technical sections are necessary — the specific fields, the specific arithmetic, the specific layers — but the payload is the structural fact: *a system whose layers each preserve local consistency can nonetheless produce a globally inconsistent output, and the gap between local and global consistency is the space in which this class of vulnerability lives.*

---

## Abstract

CVE-2026-21385 is an integer overflow in Qualcomm's `kgsl` kernel graphics driver affecting 235+ Qualcomm chipsets. A userland application passes a crafted `alignment` parameter to the `kgsl_ioctl_gpumem_alloc` interface; the driver processes the value under a signed integer context, producing a sign-extended negative alignment that collapses the `align_up` computation to a value far smaller than the requested allocation size. The kernel allocator succeeds on the underflowed size. The subsequent write of `requested_size` bytes into a buffer of `tiny_size` bytes overflows into adjacent kernel memory, yielding a controlled kernel memory corruption primitive usable for privilege escalation. The bug is actively exploited in the wild (CISA KEV, Android Security Bulletin 2026-03-05).

The technical contribution of this writeup is not a new attack nor a new defence. It is an *anatomical framing* of a structural failure pattern that recurs throughout the driver-interface literature: an invariant that holds in the mathematical domain (alignment values are positive) is silently invalidated at a type-level boundary (unsigned-to-signed cast), and the invalidation propagates through two additional layers before producing an observable symptom. Each intermediate layer is individually correct. The whole is inconsistent. No standard tooling — neither the compiler nor a conventional static analyzer — flags the vulnerability, because the violation is semantic rather than syntactic, and because the path from source to symptom crosses multiple translation units with no shared invariant carrier.

The patch is a domain restriction at the trust boundary: `uint32_t` cast plus power-of-two and upper-bound checks before `align_up` is called. The algebra is straightforward; the structural lesson is that *fixing a domain-violation bug means closing the domain, not hardening the function body*.

**Keywords:** `kgsl`, Qualcomm graphics, sign extension, integer overflow, CWE-190, domain narrowing, precondition enforcement, emergent inconsistency, cross-layer invariant failure, kernel privilege escalation.

---

## §1. The kgsl Allocation Interface

The Qualcomm Kernel Graphics Support Layer (`kgsl`) is the kernel-mode component of the Adreno GPU driver stack. It exposes a POSIX `ioctl` interface to userland — specifically to the Android graphics runtime, OpenGL ES drivers, Vulkan loaders, and, crucially, to any application with a file descriptor on `/dev/kgsl-3d0`.

The GPU memory allocation path is `IOCTL_KGSL_GPUMEM_ALLOC`. Its user-visible structure includes:

```c
struct kgsl_gpumem_alloc {
    uint64_t gpuaddr;   /* output: GPU virtual address */
    size_t   size;      /* input:  requested allocation size */
    uint32_t flags;     /* input:  allocation flags */
    uint32_t alignment; /* input:  alignment requirement */
};
```

The driver's mental model for `alignment` is:

```
PRECONDITION (assumed, not enforced):
  alignment > 0
  alignment is a power of two
  alignment ≤ some reasonable upper bound

POSTCONDITION (what the driver relies on downstream):
  aligned_size = align_up(requested_size, alignment)
  aligned_size ≥ requested_size
  allocated_buffer is at least aligned_size bytes
```

Both the precondition and the postcondition are *assumed* at the call site. Neither is *checked*. The input crosses the kernel boundary with no validation.

### The Trust Boundary

The `ioctl` interface is a trust boundary by definition: it is the point at which userland-controlled data enters a kernel-privilege execution context. The relevant invariant at any trust boundary is that all inputs satisfy the preconditions assumed by the code that will process them. Here, the assumed precondition is `alignment ∈ ℤ⁺`. The code enforcing that precondition did not exist.

```
┌─────────────────────────────┐
│  Userland (unprivileged)    │
│                             │
│  param.alignment = 0xFFFF   │  ← attacker controls this
│  ioctl(fd, GPUMEM_ALLOC, p) │
└─────────────┬───────────────┘
              │ trust boundary — no validation
              ▼
┌─────────────────────────────┐
│  kgsl driver (ring 0)       │
│                             │
│  int32_t a = param.align;   │  ← type confusion here
│  align_up(size, a);         │
│  alloc(align_up_result);    │
└─────────────────────────────┘
```

The driver is not adversarial software. It was written with the assumption that `param.alignment` would arrive from a cooperative runtime — the OpenGL ES stack, the Vulkan loader — that would never pass a negative alignment value because doing so would defeat the purpose of the allocation call. That assumption is correct for cooperative callers. It is incorrect at a trust boundary, where the caller is the attacker.

---

## §2. Sign Extension and the Collapsing Invariant

### 2.1 The Arithmetic Failure

The vulnerable assignment:

```c
int32_t alignment = param->alignment;
```

`param->alignment` is `uint32_t`. The assignment performs an implicit widening from 32-bit unsigned to 32-bit signed. For values in the range `[0, 2³¹ − 1]`, the widening preserves the value. For values in `[2³¹, 2³² − 1]`, the widening performs a sign extension: the most-significant bit, which in the unsigned interpretation is a magnitude bit, is reinterpreted as a sign bit.

```
uint32_t  0xFFFFFFFF  =   4294967295
int32_t   0xFFFFFFFF  =           -1     ← sign extension
```

After this assignment, `alignment` is `-1` in the signed integer domain. The driver then calls:

```c
size_t aligned_size = align_up(requested_size, alignment);
```

The standard `align_up` formula is:

```c
size_t align_up(size_t size, size_t align) {
    return (size + align - 1) & ~(align - 1);
}
```

Substituting `align = -1` (as `size_t`, which is unsigned, so `-1` becomes `0xFFFFFFFF` or `0xFFFFFFFFFFFFFFFF` depending on platform width):

```
align     = 0xFFFFFFFF
align - 1 = 0xFFFFFFFE
~(align-1)= 0x00000001

size      = 4096 = 0x1000
size + align - 1 = 4096 + 0xFFFFFFFF - 1
                 = 4096 + 4294967294
                 = 4294971390 = 0x100000FFE  ← wraps to 0x000000FFE on 32-bit

result    = 0x000000FFE & 0x00000001 = 0
```

On a 32-bit `size_t` context, `align_up(4096, -1)` returns `0`. On a 64-bit context with appropriate widening, the result is `1` or another small value. In either case, the result is far below `requested_size`.

### 2.2 The Invariant Breakdown

The allocation invariant requires:

$$
\text{aligned\_size} \geq \text{requested\_size}
$$

The normal case guarantees this:

$$
\forall s, a \in \mathbb{Z}^+ :\ \text{align\_up}(s, a) \geq s
$$

After sign extension, `a` leaves `ℤ⁺`:

$$
a_{user} \in [2^{31}, 2^{32}-1]\ \xrightarrow{\text{sign\_ext}}\ a_{signed} \in [-2^{31}, -1]
$$

$$
\text{align\_up}(s,\ a_{signed}) \ll s\ \ \ (\text{invariant broken})
$$

The guarantee collapses. The driver does not detect this because no check after `align_up` verifies that the result satisfies the postcondition `≥ requested_size`. The allocator receives a tiny value and succeeds. The caller proceeds to write `requested_size` bytes into a buffer of `aligned_size` bytes.

```
requested_size  = 4096
aligned_size    = 1        ← overflow result
allocated       = 1 byte
subsequent write= 4096 bytes → 4095 bytes beyond allocation boundary
```

---

## §3. Arithmetic Model vs. Silicon Reality

### 3.1 The Programmer's Model

When a programmer writes `align_up(size, alignment)`, the implicit model is:

```
Domain:    size      ∈ ℤ⁺
           alignment ∈ ℤ⁺
Guarantee: result    ∈ ℤ⁺, result ≥ size
Invariant: the allocated region can accommodate size bytes
```

This model is mathematically sound. On any positive integer inputs, `align_up` produces a result no smaller than the first argument.

### 3.2 The Silicon Execution

What the hardware actually processes:

```
Domain:    size_t   ∈ {0 .. 2⁶⁴−1}    (register width, platform-specific)
           int32_t  ∈ {−2³¹ .. 2³¹−1}
Guarantee: none — the guarantee was a property of the model's domain,
                  not of the arithmetic operation
Invariant: BROKEN — once alignment crosses the sign boundary
```

The tension is not between two implementations of `align_up`. It is between two *domains*:

```
Mathematical domain:    alignment ∈ ℤ⁺  →  align_up has the property ≥ size
Silicon domain:         alignment ∈  ℤ  →  align_up has no such property
```

The driver was implemented against the mathematical domain. It executes in the silicon domain. The gap between them is one implicit cast.

### 3.3 Why Tooling Misses It

Three tooling layers that should catch this class of bug — the C compiler, a static analyzer, and a runtime sanitiser — each fail for a distinct structural reason.

**Compiler.** The C standard defines `uint32_t → int32_t` assignment as implementation-defined (not undefined) behaviour when the value is not representable; on two's-complement targets (all modern architectures), the result is the bit-reinterpretation. The compiler generates no warning at default settings because this is a *legal* conversion under `-Wall` without `-Wsign-conversion`. Even with `-Wsign-conversion`, the warning is advisory; the code compiles and runs.

**Static analyser.** A conventional dataflow analyser tracks values and types, not *semantic domains*. The type of `alignment` after the assignment is `int32_t`. The call `align_up(size, alignment)` is a legal function call with correctly-typed arguments. The analyser has no encoding of the semantic constraint `alignment ∈ ℤ⁺`; that constraint exists only in the programmer's mental model and in the downstream postcondition that depends on it. The analyser cannot flag a violation of an invariant it cannot represent.

**Runtime.** There is no undefined behaviour to detect. The cast is defined. The arithmetic is defined (unsigned arithmetic does not overflow in C; the multiplication and masking in `align_up` are entirely defined). The allocator call succeeds (a small allocation is valid). The violation is only manifest at the subsequent write — at which point a sanitiser like KASAN *will* fire (out-of-bounds write). But KASAN operates at runtime with a specific input; it fires on the test vector that triggers the bug, not as a static guarantee.

```
Layer       Check performed                         What it sees
─────────── ─────────────────────────────────────── ────────────────────────────
Compiler    type correctness of the assignment      legal (implementation-defined)
Analyser    type correctness of the function call   legal (int32_t arg, no UB)
Runtime     memory-safety of the write              fires here — but only on hit
```

The bug inhabits the gap between the type system and the semantic domain. The type system says the program is correct. The semantic domain says it is not. The gap is not detectable without an explicit encoding of the semantic constraint.

---

## §4. The Epistemological Gap — Distributed Wrongness

### 4.1 Layer Anatomy

The failure path has four distinguishable layers:

```
K1  Type layer:        uint32_t → int32_t     ← error introduced here
K2  Arithmetic layer:  align_up(s, -1) = 1   ← error propagated, transformed
K3  Allocation layer:  alloc(1) succeeds      ← error carried silently
K4  Write layer:       write(4096 bytes)      ← error becomes observable
```

The error is *introduced* at K1. The error *manifests* at K4. K2 and K3 are silent carriers: each performs its operation correctly given its local inputs, and neither has visibility into the global invariant that the chain as a whole must preserve.

This is structurally different from a *local* error (null dereference, use-after-free), where the source and the symptom are co-located or adjacent. In a local error, the question "what went wrong?" is answerable at the fault site. In a distributed error, the fault site and the crash site are separated by layers of individually-correct operations, and reconstructing the causal chain requires inverting the transformation at each layer.

```
K4 crash:   OOB write at kernel address 0xXXXX
  → K3:     allocation was 1 byte — why?
  → K2:     align_up returned 1 — why?
  → K1:     alignment was -1 — why?
  → input:  userland passed 0xFFFFFFFF — deliberate
```

Each arrow is a separate debugging step. Each step requires recovering information that the executing code no longer holds: at K4, the alignment value from K1 is not in scope and is not in the crash dump. The investigation is forensic reconstruction, not direct observation.

### 4.2 Emergent Inconsistency

The term for this structural pattern is *emergent inconsistency*: a system in which no individual component is incorrect, but the composition of components violates a global invariant.

Emergent inconsistency arises when a system decomposes a global invariant into local obligations — "this layer receives valid inputs", "this function preserves its postcondition" — but does not instrument the transitions *between* layers to verify that the local obligations jointly imply the global invariant. In this case:

```
Local obligation 1 (K1→K2):  "the alignment value passed to align_up is positive"
                              — assumed, not checked

Local obligation 2 (K2→K3):  "aligned_size ≥ requested_size"
                              — assumed, not checked

Local obligation 3 (K3→K4):  "the allocated buffer accommodates the subsequent write"
                              — assumed, not checked
```

Each local obligation, if satisfied, would imply the global invariant. None of them is checked. An attacker who violates obligation 1 thereby violates all three, and the global invariant, without any individual layer detecting the violation.

The defensive response — `−Wsign-conversion` at K1, a postcondition `WARN_ON(aligned_size < requested_size)` at K2, KASAN at K4 — is not redundant. It is a direct response to the distributed structure of the error: since the gap cannot be closed at a single point, each layer's boundary must be instrumented independently. The fix's explicit precondition enforcement is the K1 version of this; the three-condition validation closes the semantic gap at the only point where the original intent (alignment ∈ ℤ⁺) can still be enforced before it is lost.

---

## §5. Formal Framing — Domain Narrowing by Precondition

### 5.1 The Allocation Invariant

Let `alloc_end(p)` be the first address past the end of the allocation at base pointer `p`. The allocation invariant is:

$$
I_{alloc}:\ \forall\ \text{write}(p, n):\ p + n \leq \text{alloc\_end}(p)
$$

This is a universal statement over all writes into allocated regions. Every write must fit within its allocation.

### 5.2 The Violation Condition

The invariant is violated when:

$$
\exists\ a_{user} \in [2^{31},\ 2^{32}-1]:
$$

$$
a_{signed} = \text{sign\_ext}(a_{user}) < 0
$$

$$
\text{align\_up}(s,\ a_{signed}) < s
$$

$$
\Rightarrow\ I_{alloc}\ \text{violated on the subsequent write}
$$

The existential quantifier is the attacker's handle. A single input from the range `[2³¹, 2³²−1]` is sufficient. The defender must close the invariant for *all* inputs. The asymmetry between the existential (attacker) and the universal (defender) is the structural statement of why a single-point patch is sufficient: if the patch eliminates all inputs from the exploitable range, the existential witness is removed, and the universal invariant is restored.

### 5.3 What the Patch Does

```c
/* Before — vulnerable */
int32_t alignment = param->alignment;
size_t  aligned   = align_up(requested_size, (size_t)alignment);

/* After — fixed */
uint32_t alignment = param->alignment;
if (!alignment || !is_power_of_2(alignment) || alignment > SZ_2M)
    return -EINVAL;
size_t aligned = align_up(requested_size, (size_t)alignment);
```

The `uint32_t` cast eliminates sign extension. The three-condition guard enforces:

```
alignment ≠ 0              (division-by-zero / infinite-loop guard)
alignment is power of two  (canonical alignment semantics)
alignment ≤ SZ_2M          (upper bound prevents wrap-around in other paths)
```

After all three checks, `alignment ∈ {1, 2, 4, 8, ..., 2ᵏ | 2ᵏ ≤ SZ_2M}`. Every element of this set satisfies `sign_ext(a) > 0` (the values are small enough that the sign bit is not set in any integer width). For every such `a`:

$$
\text{align\_up}(s, a) \geq s\ \ \forall s \in \mathbb{Z}^+
$$

The invariant is restored. The function body of `align_up` does not change; the domain from which it may be called is narrowed.

Formally, the fix implements **domain narrowing by precondition**:

```
Unsecured: f : A → B,    A wide,  some a ∈ A violate I_alloc
Fixed:     f : A′ → B,   A′ ⊂ A, all  a ∈ A′ preserve I_alloc
```

The guard at the trust boundary is the mechanism that enforces `A \ A′ = ∅` — no input outside the safe subdomain reaches `f`. This is the standard response to this class of vulnerability, and it is structurally preferable to adding checks inside `align_up` itself (which would need to be repeated in every caller and would move the invariant enforcement away from the trust boundary, where it belongs).

### 5.4 Why `uint32_t` Alone Is Not Sufficient

The first instinct is to change `int32_t` to `uint32_t` and stop there. This eliminates sign extension, but it does not close the domain to `ℤ⁺`. It changes the domain from `{−2³¹ .. 2³¹−1}` to `{0 .. 2³²−1}`, which still contains `0` (zero alignment is undefined for `align_up`), non-powers-of-two (which produce non-aligned results), and very large values (which may wrap in arithmetic further downstream). The full three-condition guard is not defensive excess; it is the minimal set of checks that fully characterises `A′`.

```
uint32_t alone:   A  = {0, 1, 2, ..., 2³²−1}     — contains invalid inputs
full guard:       A′ = {1, 2, 4, 8, ..., 2ᵏ ≤ SZ_2M} — the safe subdomain
```

---

## §6. Exploitation Surface

### 6.1 Attack Primitive

```
Step 1:  Attacker opens /dev/kgsl-3d0
Step 2:  Calls IOCTL_KGSL_GPUMEM_ALLOC with
           .size      = 0x1000  (4096 bytes)
           .alignment = 0xFFFFFFFF
Step 3:  Driver sign-extends alignment to -1
Step 4:  align_up(0x1000, -1) → underflow → result = 1
Step 5:  Kernel allocates 1-byte buffer at kernel address p
Step 6:  Driver writes 0x1000 bytes starting at p
Step 7:  4095 bytes written beyond p corrupt adjacent kernel structures
Step 8:  Adjacent-object corruption → kernel privilege escalation
```

### 6.2 Why the Graphics Driver Is an Attractive Target

Performance-critical kernel interfaces accumulate attack surface through the combination of:

- **Direct userland exposure** — `/dev/kgsl-3d0` is world-readable on Android; no elevated permission required to open the file descriptor
- **Minimised validation** — graphics drivers are latency-sensitive; historically, validation in hot paths is pruned; alignment checks are off the critical path but were never added
- **Complex input surface** — the `kgsl` ioctl interface has dozens of commands; a comprehensive audit requires examining each independently
- **Kernel privilege** — ring-0 execution; successful corruption of a kernel object directly yields privilege escalation without a further privilege-escalation primitive

The combination makes graphics drivers consistently productive targets. The Qualcomm kgsl driver in particular has a documented history of integer-type vulnerabilities at the alignment arithmetic boundary (see §7).

### 6.3 Counterfactual Input Space

The binary split `alignment < 2³¹ / alignment ≥ 2³¹` is the attacker's primary degree of freedom, but the overflow surface has additional structure:

```
alignment = 0xFFFFFFFF:  align_up result = 0 or 1 (minimum possible)
alignment = 0x80000000:  align_up result depends on size, but << size
alignment = 0x7FFFFFFF:  does NOT sign-extend (< 2³¹), align_up normal
alignment = 0x00000001:  align_up(s, 1) = s, no overflow
```

The exploitable range is strictly `alignment ∈ [2³¹, 2³²−1]`. Within this range, the specific overflow result varies, but any value in the range produces `aligned_size < requested_size`. The attacker needs only to land in this range; the precise value selects the *degree* of underflow, which may affect heap-layout choices in an exploitation chain but does not affect whether the primitive is available.

A secondary degree of freedom is `requested_size`. A larger value extends the corruption range and increases the probability of hitting a sensitive kernel structure. A smaller value reduces the overflow byte count and may require a more targeted heap spray. An experienced kernel exploit developer would choose both values in concert to maximise the probability of a stable privilege-escalation chain.

---

## §7. Historical Pattern in the Qualcomm Graphics Driver

CVE-2026-21385 is not the first Qualcomm graphics driver vulnerability in this structural family:

| CVE            | Year | Component              | Bug class                          |
|----------------|------|------------------------|------------------------------------|
| CVE-2019-10538 | 2019 | Qualcomm GPU           | Integer overflow, alignment path   |
| CVE-2021-1905  | 2021 | Qualcomm graphics      | Memory corruption, driver boundary |
| CVE-2023-33106 | 2023 | Qualcomm, GPU path     | Integer overflow                   |
| CVE-2026-21385 | 2026 | Qualcomm kgsl          | Sign extension → alignment collapse|

The pattern is not coincidental. The same architectural assumption — *that alignment values arriving from the graphics runtime are well-formed* — has been inherited across driver versions and has survived multiple audit cycles. This is the class of bug that static tools that track values without tracking semantic domains reliably miss, and that manual audit reliably catches only when the auditor is specifically looking at trust boundaries.

The recurring trigger is the combination of a performance-sensitive interface (the graphics path) and a semantic constraint (alignment ∈ ℤ⁺) that is enforced by caller convention rather than by explicit validation. Every time the interface is called from a cooperative runtime, the constraint holds. Every time it is called from an attacker, it does not. The interface has no way to distinguish the two — it receives a bit pattern, not a certificate of origin.

The patch history also shows that individual fixes do not propagate to sibling paths: CVE-2021-1905 was patched in a different code region from CVE-2026-21385, which was itself in a different region from CVE-2019-10538. Structural fixes (a library function for alignment validation used at all trust boundaries) are not present in the disclosed history. Each patch closes one entry point; the architecture of the interface remains unchanged.

---

## §8. Related Writeups

This writeup is a *laser case study* in the cross-layer invariant failure pattern. Its structural claim is:

> A signed/unsigned confusion at a driver trust boundary introduces a semantic-domain violation that propagates through two additional individually-correct layers before producing an observable symptom. Standard tooling cannot detect the violation because the violated invariant is semantic (alignment ∈ ℤ⁺), not syntactic. The fix is a domain restriction at the trust boundary, not a hardening of the function body.

Within this collection, this writeup connects to:

**Mathematical Collapse Writeup** — that writeup examines the gap between the mathematical objects a proof system reasons about and the physical objects a processor executes on. This writeup examines the same gap in a narrower setting: the mathematical domain (positive integers) versus the C type domain (signed integers). Both writeups trace failures to the mismatch between model and substrate.

**Silicon Is the Adversary Writeup** — that writeup's central claim is that the silicon layer imposes behaviour the software layer did not model. Here, the silicon layer performs sign extension under C's implicit conversion rules, producing behaviour the caller's mental model did not anticipate. The claim instantiates at a different layer but the structural reading is the same.

**BFS2019 Master Writeup** — that writeup traces a full kernel exploitation chain. CVE-2026-21385 provides the corruption primitive that would be the starting point of an analogous chain on Android; the two writeups are complementary at the exploitation-methodology level.

**Speculation Barrier Illusion Writeup** — that writeup identifies a category error between ISA-level guarantees and microarchitectural behaviour. This writeup identifies a category error between the type-level contract (the compiler's domain) and the semantic contract (the driver's domain). Both writeups locate the error in the gap between two formally distinct but practically adjacent layers.

The collection's unifying methodological posture — that low-level systems behaviour is best characterised by identifying the precise layer at which a guarantee breaks, rather than by treating the symptom where it surfaces — applies here directly. The OOB write at K4 is the symptom. The sign extension at K1 is the diagnosis. The four-layer causal chain between them is the lesson.

---

## Technical Note and Scope

Technical details in this writeup are derived from public sources: the NVD advisory, the Android Security Bulletin (2026-03-05), the Qualcomm March 2026 Security Bulletin, the CISA KEV catalogue entry, and the publicly disclosed CodeLinaro commit "kgsl: Prevent sign extension on alignments". No exploit code is present in this repository. The actively-exploited chain referenced in the CISA KEV listing has not been publicly disclosed; this writeup reconstructs the vulnerability class from first principles and published patch analysis.

This writeup is research and educational documentation. It is not a disclosure, an exploit, or a toolkit.

---

## References

- NVD: CVE-2026-21385
- Android Security Bulletin, March 2026 patch level 2026-03-05
- Qualcomm Security Bulletin, March 2026
- CISA Known Exploited Vulnerabilities: CVE-2026-21385
- CodeLinaro commit: "kgsl: Prevent sign extension on alignments"
- CVE-2019-10538, CVE-2021-1905, CVE-2023-33106 — historical sibling disclosures
- Linux kernel documentation: `ALIGN()` macro, `is_power_of_2()` — `include/linux/log2.h`
- CWE-190: Integer Overflow or Wraparound — MITRE CWE catalogue
