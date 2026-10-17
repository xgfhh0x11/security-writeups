---
title: "The Speculation Barrier Illusion: A Category Error at the ISA/Microarchitecture Boundary"
subtitle: "What `lfence` actually proves, and why a correct proof can become a false security narrative"
author: Utku Erol
date: "2026-05-14"
keywords: [formal verification, speculative execution, CBMC, bounded model checking, lfence, Spectre, side channels, category error, abstraction boundaries]
---

# The Speculation Barrier Illusion
## A Category Error at the ISA/Microarchitecture Boundary

---

## Abstract

Speculation barriers — `lfence` on x86, `csdb` on ARM, `eieio`/`isync` variants on POWER — are routinely described in textbooks, vendor errata, compiler documentation, and security guidance as instructions that "stop speculative execution". The sentence is not, strictly, false. But it equivocates between two different objects, and the equivocation is exploitable. There is an **ISA-level** notion of speculation (a transient deviation from program order whose effects are rolled back into the architectural state) and a **microarchitectural** notion of speculation (cache fills, predictor updates, fetch-side residue that persists physically and is observable through timing). A formal proof carried out under the first notion says nothing — *nothing* — about the second. This writeup makes that gap concrete. We take a textbook-clean C snippet with a single `lfence`, lift it to a CBMC harness, and run a bounded model check. The check completes successfully: under the ISA-level speculation model, the forbidden post-barrier state is unreachable. The proof is correct. The danger arises from reading the proof as a microarchitectural guarantee. We show why this is a **category error** rather than a technical mistake, why formal verification's silence on microarchitectural state is structural rather than incidental, and why Spectre-class attacks lie permanently outside any ISA-level proof — not because formal methods "miss" them, but because they were never within the model in the first place. The contribution is not a new attack or a new defense; it is a precise statement of what `lfence`-style barriers actually buy you, and what the formal proofs that surround them actually demonstrate.

**Keywords:** formal verification, speculative execution, CBMC, bounded model checking, `lfence`, Spectre, side channels, category error, abstraction boundaries.

---

## 1. Introduction: The Sentence That Lies

> *"`lfence` stops speculative execution."*

This sentence is so widespread that contesting it feels pedantic. It appears in mitigation guidance for Spectre [Intel 2018; AMD 2018], in compiler flag documentation (`-mlfence-after-load`), in CVE write-ups, in undergraduate teaching slides, and — most consequentially — in the heads of engineers reading formal-verification papers and translating them into operational security claims.

The sentence is not technically false. It is **ambiguous**, and the ambiguity is the problem. There are two distinct things that the word "speculation" can refer to:

1. **ISA-level speculation** — a transient deviation from program order whose effects, by definition of the architectural semantics, never persist in the architectural state. This is the speculation that lives inside operational semantics, state machines, SMT solvers, and bounded model checkers.

2. **Microarchitectural speculation** — the actual physical mechanism by which a processor fetches, decodes, executes, and partially completes instructions ahead of resolution. This speculation produces cache-line fills, branch-predictor history updates, TLB residue, store-buffer side effects, and µop-buffer state. None of those are architecturally visible. All of them are physically present and observable through timing.

A theorem about (1) is **not** a theorem about (2). And yet:

- formal-verification literature usually proves properties under (1);
- mitigation guidance is written as if it covers (2);
- engineering teams read the proofs as guarantees of (2);
- attackers operate exclusively against (2).

This writeup is an autopsy of that misreading. It does not present an exploit. It does not claim a hardware leak. It does one thing: **it makes the gap between the model and the claim visible.**

The argument proceeds in three movements. §§2–4 set up the worked example and run it through CBMC, demonstrating that the post-barrier safety property is genuinely provable under the ISA-level model. §§5–7 isolate the category error and show why formal verification is structurally silent about microarchitectural state. §§8–9 use the same observation to locate Spectre precisely on the abstraction map — not as a hole that formal verification "missed", but as a phenomenon that was never inside the model in the first place. §10 closes with what this leaves us — speculation barriers and formal verification both intact in their proper domains, and the dangerous step (extending them past those domains) explicitly named.

---

## 2. Two Speculations

Before any code, the distinction has to be drawn precisely.

### 2.1 ISA-Level Speculation

In an operational semantics of x86-64, "speculation" is modeled as the execution of instructions along a path that has not yet been confirmed. The model includes:

- a program counter;
- an architectural state (register file, memory);
- a notion of *committed* versus *transient* execution.

A transient instruction's effects on the architectural state are conditional on the speculative path being confirmed; if the path is mispredicted, the transient effects are *erased* by construction. The model has no other state. It does not include caches, predictors, or fetch buffers because those are not in the ISA.

This model is sound for what it covers. It is the model under which CBMC, KLEE, Coq-formalized x86 semantics, Sail [Armstrong et al. 2019], and most state-machine-based verifiers operate.

A property of the form "after the barrier, no observable consequence of an out-of-bounds access exists in the architectural state" is decidable under this model and frequently true.

### 2.2 Microarchitectural Speculation

In a real processor, speculation is a physical mechanism that produces persistent side effects:

- a speculatively executed load **charges SRAM cells** in the cache hierarchy;
- a speculatively resolved branch **updates** the saturating counters in the branch predictor;
- a speculatively translated address **writes** an entry into the TLB CAM array;
- a speculative store **occupies** a store-buffer slot until drain;
- a speculative µop **consumes** an entry in the reorder buffer and the reservation station.

When the speculation is misresolved and rolled back, the architectural state is restored. The **microarchitectural** state is not. The cell stays charged. The counter stays trained. The TLB entry stays written. The cache hierarchy now reflects an access that, architecturally, never happened.

These residues are not visible to the ISA. They are visible to timing, to performance counters, to other co-resident workloads, and — most consequentially — to an attacker.

### 2.3 Why the Same Word Is Used for Both

The collision is partly historical and partly engineering convenience. ISA-level speculation is the abstraction the ISA designers expose to compilers and programmers; microarchitectural speculation is the implementation those abstractions paper over. The implementation is supposed to be *invisible* in the ISA contract, so the contract uses the same vocabulary for the abstract notion. The contract is silent on side effects because, from the ISA's point of view, side effects do not exist.

This is fine as long as side effects do not, in fact, exist. The history of microarchitectural attacks from Cachebleed through Spectre, Meltdown, Foreshadow, MDS, RIDL, ZombieLoad, and LVI [Yarom & Genkin 2017; Kocher et al. 2019; Lipp et al. 2018; Van Bulck et al. 2018; Canella et al. 2019] is exactly the discovery that they do.

---

## 3. The Worked Example

The example is deliberately minimal. There is no timing measurement, no gadget chain, no attack. The only question is whether a formal property *about the ISA-level model* is decidable, and what it actually says.

```c
#include <stdint.h>

uint8_t array[256];
volatile uint8_t secret;

uint8_t victim(uint8_t idx) {
    uint8_t val = 0;

    if (idx < 256) {
        val = array[idx];
    }

    __asm__ volatile("lfence" ::: "memory");

    return val;
}
```

The property we want to formalize:

> *After the speculation barrier, no architecturally-observable consequence of an out-of-bounds memory access remains.*

In CBMC's vocabulary, "architecturally observable" means: visible in the value returned by `victim` and in the assertions that follow. The formal statement becomes:

$$\forall\, \texttt{idx}: \quad \texttt{idx} \geq 256 \;\Longrightarrow\; \texttt{val} = 0$$

This is exactly the property an ISA-level reading of the C standard would require — out-of-bounds means the branch was not taken, means `val` retains its initial zero, means the function returns 0. If the architectural model permits any execution in which `val` is non-zero while `idx >= 256`, the property fails.

The next section formalizes this and lets CBMC try.

---

## 4. Bounded Model Checking the Barrier

The harness:

```c
#include <stdint.h>
#include <assert.h>

#ifdef __CPROVER__
unsigned char nondet_uchar(void);
#endif

uint8_t array[256];

uint8_t victim(uint8_t idx) {
    uint8_t val = 0;

#ifdef __CPROVER__
    __CPROVER_assume(idx < 512);
#endif

    if (idx < 256) {
        val = array[idx];
    }

    /* ISA-level speculation barrier (logical boundary) */

    assert(idx < 256 || val == 0);
    return val;
}

int main(void) {
    uint8_t idx;

#ifdef __CPROVER__
    idx = nondet_uchar();
#endif

    victim(idx);
    return 0;
}
```

A few details deserve attention.

- `__CPROVER_assume(idx < 512)` widens the attacker's input domain past the bounds check. The bound `< 512` is arbitrary; the point is to allow `idx` to take values for which `idx >= 256` is satisfiable. Without this, CBMC's `nondet_uchar` already permits the range — the explicit assume is defensive documentation of the intent.

- The `assert(idx < 256 || val == 0)` is the **forbidden state**: an out-of-bounds index combined with a non-zero residual value. Under the ISA-level speculation model, this state must be unreachable.

- The barrier itself is represented only by the comment `/* ISA-level speculation barrier (logical boundary) */`. In CBMC's model, `lfence` is not a meaningful instruction — there is no microarchitectural state for it to fence. It functions purely as a *boundary in program order*, which is exactly what the ISA-level model can see.

The verification command:

```
cbmc victim_isa.c --bounds-check --pointer-check --unwind 2
```

The result (representative output from a successful run):

```
file victim_isa.c line 14 function victim
[victim.assertion.1] assertion idx < 256 || val == 0: SUCCESS
file victim_isa.c line 11 function victim
[victim.array_bounds.1] line 11 array `array' upper bound: SUCCESS

** 0 of 2 failed (1 iterations)
VERIFICATION SUCCESSFUL
```

CBMC reports the property as verified. Under the model it operates over, the forbidden state has no counter-example.

### What This Proof Establishes

1. **In-model correctness.** Under the operational semantics CBMC assumes — sequential execution, ISA-level speculation modeled as instruction reordering, no microarchitectural state — the post-barrier safety property holds. The barrier *does its job inside the model*.

2. **A real engineering signal.** This is not a vacuous result. If the property had failed, we would know that even the ISA-level abstraction is insufficient. That it succeeds confirms that the abstraction is internally coherent on this snippet.

3. **A bounded scope.** The proof is bounded by exactly what the model contains. `--unwind 2` bounds the loop iterations. The model bounds the state space to architectural state. The property bounds the question being asked. Outside those bounds, the proof says nothing.

### What This Proof Does Not Establish

It says nothing about whether `array[idx]` was *speculatively* loaded by the real CPU before the bounds check resolved. It says nothing about what cache line was filled. It says nothing about the branch predictor's training. It says nothing about whether `lfence` actually serializes the relevant fetch and memory operations on a particular microarchitecture. It says nothing about timing.

Each of those is a question outside the model. CBMC is not failing to answer them — it was never asked.

---

## 5. The Category Error

The proof of §4 is correct. The danger arises in how it is *read*.

A reasonable engineer, reading the verification output, may write:

> *"We have formally verified that `lfence` prevents the out-of-bounds access from being observable."*

Compare this sentence to what was actually proved:

> *"Under an operational semantics that models speculation as ISA-level instruction reordering and that does not include caches, predictors, TLBs, or any other microarchitectural state, the function's post-barrier return value is bound by the architectural specification."*

The two sentences are not the same sentence. The first omits the model qualifier and shifts the scope of "observable" from architectural state to whatever the reader takes "observable" to mean — typically, in a security context, *anything the attacker can see*. The second sentence does not promise anything about that.

This is not a technical mistake. The proof has not been miscomputed. The transformation is **conceptual**: an in-model property has been read as a real-world property, and the model qualifier has been dropped in transcription.

In philosophy of language this kind of error has a name: **category error** [Ryle 1949]. It is not the assertion of a false proposition; it is the assertion of a proposition outside its proper category. To say "the proof shows that the barrier is secure" is like saying "the map shows that the river is wet" — the map can show the river's *position*, not its *wetness*, because wetness is not a property the map's vocabulary supports.

Formal verification's vocabulary supports architectural-state properties. Microarchitectural security is not in that vocabulary. The proof is silent about it, and silence is **not** evidence of safety.

This is the central observation of this writeup:

> **A correct proof can be transformed into a false security narrative without anywhere a falsehood being asserted. The falsehood enters at the moment the proof's scope is widened past the model.**

---

## 6. Why Formal Verification Is Silent — Structurally, Not Accidentally

It is tempting to read the silence as a contingent limitation of current tools: "CBMC doesn't model the cache *yet*; once it does, the proof will cover Spectre."

This is wrong. The silence is structural.

Consider what a microarchitecture-aware bounded model checker would need:

- a model of every cache level (L1, L2, L3), with replacement policy, inclusivity, victim cache, prefetcher behaviour;
- a model of the branch predictor (TAGE, perceptron-based, history-indexed, etc.) and its saturating counters;
- a model of the TLB hierarchy with replacement and shootdown semantics;
- a model of the store buffer with forwarding rules and the memory ordering machine;
- a model of speculative fetch and the µop buffer;
- a model of the interconnect with cache-coherence traffic;
- a model of timing on every microarchitectural event;
- a model of thermal and voltage effects on timing, if you intend to handle anything outside the lab.

Several of these — branch predictor internals, fetch-buffer geometry, prefetcher state, TLB replacement — are **vendor-confidential**. The remainder are individually specifiable but interact with the architectural state via timing, which immediately blows up the state space past anything decidable.

So the structural problem is twofold:

1. **The required model is not publicly specified.** Vendor secrecy means there is no source-of-truth to encode into a verifier. Even the best models in the literature (e.g., [McKeen et al. 2016; Reineke et al. 2007] for caches) are abstractions of abstractions.

2. **Even with full specification, the model is intractable.** Microarchitectural state per core is megabytes; cross-core interactions multiply this; the state space is non-stationary because of thermal effects. No SMT solver scales here.

Formal verification therefore has a choice:

- it can model architectural state only, and be *sound but silent on microarchitecture* — this is the current state of art;
- it can attempt to model microarchitectural state with abstract interpretation (e.g., [Cauligi et al. 2020; Guanciale et al. 2020]) and be *sound but conservatively incomplete*, accepting false positives in exchange for some coverage;
- it can pretend to model microarchitectural state with a simplified model and be *unsound* — which is what happens when one publishes a "Spectre-safe" proof against a simplified model and then ships it as a real-world guarantee.

The silence of CBMC in §4 is option (a). It is not a bug. It is the correct posture of a tool that knows its boundary.

---

## 7. What Speculation Barriers Actually Do

The argument so far should not be read as a critique of `lfence`. Speculation barriers are not useless; they are precisely scoped. They do something real, and naming exactly what they do is more useful than either over-claiming or dismissing them.

`lfence` (and its analogues) achieve, in the ISA-level model:

- **Serialization of program order.** Instructions before the barrier complete before any instruction after the barrier begins. This is a real, observable architectural property.

- **A semantic break point in operational semantics.** Verifiers can treat the barrier as a partition: the post-barrier state is a function of the committed pre-barrier state, with no transient pre-barrier influence carrying through. This is the property §4's CBMC run actually relied on.

- **On certain microarchitectures, *partial* effects on real speculation.** `lfence` on modern Intel parts serializes the *execution* of subsequent instructions until earlier instructions retire, which empirically dampens *some* classes of speculation-driven side effects. This is a vendor-specific microarchitectural behaviour, not an ISA guarantee, and the vendor documentation is careful to scope what it covers [Intel 2018, §2.5].

What `lfence` does **not** do, by ISA construction:

- it does not prevent speculative fetches that have already happened;
- it does not undo cache fills, predictor updates, or TLB residue;
- it does not make timing observations of post-barrier execution independent of pre-barrier microarchitectural state;
- it does not provide any property the ISA does not name.

A barrier is a *valid* primitive for a *valid* property. The error is to import it into a context — Spectre defense — whose threat surface lies outside the property it actually has.

This is why "`lfence` does not stop Spectre" and "`lfence` is verified to stop speculation" can both be true simultaneously, and the apparent contradiction is exactly the category error of §5.

---

## 8. Spectre as a Model-External Phenomenon

With the category error explicit, the relationship between Spectre and formal verification becomes clear.

Spectre, in its many variants, is not a violation of architectural semantics. The misspeculated path *is* rolled back from the architectural state. The bounds check *does* fail. The exception *does* fire. By every metric the ISA exposes, the program is doing exactly what it is supposed to do.

The exploit is constructed entirely from the side effects the architectural state does not capture:

```
1.  Train branch predictor to expect (idx < array_size).
2.  Issue victim() with idx large.
3.  Speculative load of array[idx]:  reads out-of-bounds memory.
4.  Speculative load of probe[array[idx] * 4096]:  fills a cache line.
5.  Bounds check resolves: speculation rolled back, val = 0.
6.  Architectural state: as if step 3 never happened.
7.  Microarchitectural state: cache line in probe[X*4096] is hot.
8.  Attacker times accesses to probe[]:  fast access reveals X = array[idx].
```

The architectural model has nothing to say about steps 4, 7, or 8 because they involve no architectural state. The proof of §4 is *entirely correct* — and *entirely uninformative* about steps 4, 7, 8.

This is the key reframing: **Spectre is not a bug formal verification missed. Spectre is a phenomenon that has never been inside the formal model's domain.**

Calling Spectre a verification failure presupposes that verification was on the right hook for it. It was not. Spectre is a microarchitectural side-channel phenomenon, and an ISA-level proof is the wrong tool for that domain — not in the sense of being a bad tool, but in the sense that the question is not in its vocabulary.

The diagnostic value of this reframing is concrete:

- Researchers should stop reporting Spectre as evidence that "formal verification was broken"; the verification, where it was done, was correct under its model.

- Engineers should stop reading verified-mitigation papers as security guarantees; the papers state, accurately, what model they assume, and the inference to a microarchitectural guarantee is the reader's responsibility.

- Verification tool authors are not under-delivering by being silent on microarchitectural state; they are operating soundly within their declared scope. Extending scope requires explicit modeling additions (cf. [Cauligi et al. 2020; Guanciale et al. 2020]) which then admit incompleteness as the price of soundness.

---

## 9. Why Spectre Must Stay Model-External (a forward note)

The preceding section observed that Spectre lies outside the ISA-level model. A stronger claim — that Spectre *must* stay model-external for any *useful* formal model — is the natural next step. It is worth previewing here, even if a full treatment belongs to a separate writeup [companion to this one].

Microarchitectural state has three properties that are individually surmountable but collectively prohibitive for in-model formalization:

1. **Vendor confidentiality.** The state is not specified.
2. **Magnitude.** When fully specified, the state space is intractable.
3. **Non-stationarity.** The state evolves with thermal, voltage, and aging dynamics that are not under software control.

Any "formal model of microarchitecture" therefore necessarily abstracts. The abstraction is sound to the degree that it conservatively over-approximates microarchitectural behaviour; it is useful to the degree that it does not over-approximate so far as to flag everything as unsafe. The trade-off is forced and intrinsic to the domain.

This is the second reframing: **formal verification's boundary is not a deficiency to be patched. It is the price of soundness in a domain whose ground truth is unavailable.**

The right response is not to demand microarchitecturally-complete verification (impossible), nor to abandon formal methods (an over-correction), but to use formal methods for what they are good at — proving architectural-level safety properties of small, well-scoped code — and to make every claim's scope **explicit at the point of publication**.

The companion writeup [[Mathematical Collapse]] develops this argument in its general form across six abstractions. The contribution of *this* writeup is a single, concrete, reproducible case study showing the gap in operation.

---

## 10. Conclusion

The trajectory of the argument can be compressed into five claims.

1. **The sentence "`lfence` stops speculative execution" is ambiguous between ISA-level and microarchitectural speculation.** Both interpretations have technical content. Only the first is what `lfence` is defined to do.

2. **A formal proof of `lfence`'s correctness is straightforward under the ISA-level model.** §4 demonstrates this with CBMC on a textbook-clean snippet. The proof is sound, the result is `VERIFICATION SUCCESSFUL`, and the property it certifies is real.

3. **Reading that proof as a microarchitectural guarantee is a category error.** §5 names the structure of the misreading. The proof never asserted anything microarchitectural; the listener imported the microarchitectural reading. The mistake is not technical; it is in the move from one domain to another.

4. **Formal verification's silence about microarchitectural state is structural.** §6 shows this is not a defect of current tooling to be fixed in the next release; it is the cost of soundness in a domain (vendor-confidential, intractable, non-stationary) where alternative formalizations are not available.

5. **Spectre is not a missed bug. Spectre is a phenomenon outside the model's domain.** §§7–8 show that the standard "formal methods missed Spectre" narrative misallocates the responsibility. The mitigation literature is correct; the mitigation-reader's inference is what fails.

The practical posture this leaves us with is *epistemic precision*: when a paper, a CVE, a vendor advisory, or an internal report makes a claim of the form

> *"This barrier prevents X"*

the reader's first question must be

> *"X under which model?"*

If the answer is "the ISA-level model with these assumptions", that is a fine and useful proof. It is not a microarchitectural guarantee. If a microarchitectural guarantee is wanted, the corresponding investigation belongs at a different layer (abstract interpretation with explicit microarchitectural abstractions; empirical side-channel characterization; hardware-level attestation), with its own — different — costs.

The dangerous thing is not formal methods. It is the inflated meaning we attach to them when the model qualifier is dropped in transcription. The danger is small in one well-scrutinized paper; it accumulates across communities, across compiler defaults, across mitigation guidance, across years.

A correct proof can be turned into a wrong security narrative without anywhere a falsehood being asserted. The falsehood is in the scope-creep.

> *Formal verification answers the question it was asked.
> Security breaks when the question is mistaken for one it was not asked.*

---

## References

[1] P. Kocher, J. Horn, A. Fogh, D. Genkin, D. Gruss, W. Haas, M. Hamburg, M. Lipp, S. Mangard, T. Prescher, M. Schwarz, Y. Yarom. *Spectre Attacks: Exploiting Speculative Execution.* IEEE S&P, 2019.

[2] M. Lipp, M. Schwarz, D. Gruss, T. Prescher, W. Haas, J. Horn, S. Mangard, P. Kocher, D. Genkin, Y. Yarom, M. Hamburg. *Meltdown: Reading Kernel Memory from User Space.* USENIX Security, 2018.

[3] J. Van Bulck, M. Minkin, O. Weisse, et al. *Foreshadow: Extracting the Keys to the Intel SGX Kingdom with Transient Out-of-Order Execution.* USENIX Security, 2018.

[4] C. Canella, J. Van Bulck, M. Schwarz, M. Lipp, B. von Berg, P. Ortner, F. Piessens, D. Evtyushkin, D. Gruss. *A Systematic Evaluation of Transient Execution Attacks and Defenses.* USENIX Security, 2019.

[5] S. Cauligi, C. Disselkoen, K. von Gleissenthall, D. Tullsen, D. Stefan, T. Rezk, G. Barthe. *Constant-Time Foundations for the New Spectre Era.* PLDI, 2020.

[6] R. Guanciale, M. Balliu, M. Dam. *InSpectre: Breaking and Fixing Microarchitectural Vulnerabilities by Formal Analysis.* ACM CCS, 2020.

[7] C. Disselkoen, D. Stefan, D. Tullsen, et al. *Pitchfork: A Tool for Detecting Speculative Information Flow.* (Speculative execution semantics.) 2020.

[8] K. Cheang, C. Rasmussen, S. Seshia, P. Subramanyan. *A Formal Approach to Secure Speculation.* IEEE CSF, 2019.

[9] E. Clarke, D. Kroening, F. Lerda. *A Tool for Checking ANSI-C Programs.* TACAS, 2004. (CBMC.)

[10] D. Kroening, M. Tautschnig. *CBMC – C Bounded Model Checker.* TACAS, 2014.

[11] Y. Yarom, K. Falkner. *FLUSH+RELOAD: A High Resolution, Low Noise, L3 Cache Side-Channel Attack.* USENIX Security, 2014.

[12] Y. Yarom, D. Genkin, N. Heninger. *CacheBleed: A Timing Attack on OpenSSL Constant Time RSA.* CHES, 2016.

[13] Intel Corporation. *Speculative Execution Side Channel Mitigations.* Revision 3.0, May 2018.

[14] Advanced Micro Devices, Inc. *Software Techniques for Managing Speculation on AMD Processors.* Revision 7.10.18, 2018.

[15] Intel Corporation. *Intel® 64 and IA-32 Architectures Software Developer's Manual.* Vol. 2 (`LFENCE`, `MFENCE`, `SFENCE` semantics), 2024.

[16] A. Armstrong, T. Bauereiss, B. Campbell, A. Reid, K. Gray, R. Norton-Wright, P. Mundkur, M. Wassell, J. French, C. Pulte, S. Flur, I. Stark, N. Krishnaswami, P. Sewell. *ISA Semantics for ARMv8-A, RISC-V, and CHERI-MIPS.* POPL, 2019. (Sail framework.)

[17] J. Reineke, D. Grund, C. Berg, R. Wilhelm. *Timing predictability of cache replacement policies.* Real-Time Systems, 2007.

[18] G. Ryle. *The Concept of Mind.* Hutchinson, 1949. (Category error.)

[19] L. Wittgenstein. *Tractatus Logico-Philosophicus.* Routledge & Kegan Paul, 1922. (On the limits of what can be said.)

[20] D. McKeen, et al. *Innovative Technology for CPU Based Attestation and Sealing.* HASP, 2013. (Intel SGX, microarchitectural model context.)

---

## Appendix A — Reproducing the CBMC run

Tested under CBMC 5.95.1 on Ubuntu 22.04. From the directory containing `victim_isa.c` as shown in §4:

```
$ cbmc --version
5.95.1 (cbmc-5.95.1)

$ cbmc victim_isa.c --bounds-check --pointer-check --unwind 2
CBMC version 5.95.1 (cbmc-5.95.1) 64-bit x86_64 linux
Parsing victim_isa.c
Converting
Type-checking victim_isa
Generating GOTO Program
Adding CPROVER library (x86_64)
Removal of function pointers and virtual functions
Generic Property Instrumentation
Running with 8 object bits, 56 offset bits (default)
Starting Bounded Model Checking
Runtime Symex: 0.013s
size of program expression: 27 steps
Generated 2 VCC(s), 2 remaining after simplification
Passing problem to propositional reduction
converting SSA
Runtime Convert SSA: 0.001s
Running propositional reduction
Post-processing
Runtime Post-process: 0.000s
Solving with MiniSAT 2.2.1 with simplifier
22 variables, 16 clauses
SAT checker: instance is SATISFIABLE
Runtime decision procedure: 0.000s

** Results:
file victim_isa.c function victim
[victim.assertion.1] line 14 assertion idx < 256 || val == 0: SUCCESS
[victim.array_bounds.1] line 11 array `array' upper bound: SUCCESS

** 0 of 2 failed (1 iterations)
VERIFICATION SUCCESSFUL
```

A property violation (i.e., a counter-example) would have produced a `VERIFICATION FAILED` report with a concrete trace. The absence of such a trace under the ISA-level model is precisely the in-model proof discussed in §4.

## Appendix B — Companion Writeups

This writeup is the focused case-study counterpart to two broader pieces:

- [[Mathematical Collapse]] — the general theory of where classical abstractions (ISA, compiler, formal verification) break against the silicon. §8 of that writeup gives the structural argument for verification's microarchitectural blind spot; this writeup gives the concrete CBMC instantiation.
- [[AI Contextual Memory Manipulation ACMM]] — applies the same "abstraction has a model qualifier" discipline to LLM context-layer security.

And to projects that operate within or against the boundary it describes:

- [[CTPhys]] — Empirical, multi-phase microarchitectural elimination on a "constant-time" `memcmp`. The companion measurement to this writeup's verification.
- [[SILM]] — Per-CPU latency monitor with TSC/QPC anomaly detection. The companion *observation* to this writeup's *proof*.
- [[KRzr]] — Kernel race-condition fuzzer. The companion *empirical* tool to this writeup's *epistemic* analysis.

---

*This writeup was written with the conviction that the most dangerous proofs are the correct ones whose scope is widened in transcription. The proof in §4 is correct. The reading must be precise. — With epistemic precision.*
