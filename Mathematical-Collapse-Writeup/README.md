---
title: "Where Classical Mathematics Collapses: The Silicon Substrate and the Hardware-Software Boundary"
subtitle: "An epistemological autopsy of mathematical abstraction in microarchitectural systems"
author: Tyler
date: "2026-05-14"
keywords: [microarchitecture, formal verification, side channels, Spectre, Meltdown, speculative execution, BTI, hardware-software boundary, epistemology, domain-specific languages]
---

# Where Classical Mathematics Collapses
## The Silicon Substrate and the Hardware-Software Boundary

---

## Abstract

Modern security and systems research stands on a tacit assumption: that the mathematics taught in undergraduate programs — Riemann integrals, Gaussian probability, discrete state machines, operational semantics — is the right language for reasoning about real silicon. This writeup argues that it is not, and that this mismatch is not a pedagogical inconvenience but an exploitable property of the systems we build. We trace the failure at two levels. At the **silicon level**, we show that the primitives of classical mathematics — continuous time, well-defined functions, additive accumulation, stationary distributions — cannot represent phenomena that actually occur on a 7 nm die: non-uniform power dissipation, multi-scale aging, retroactively-invalidated speculative state. At the **hardware-software boundary**, we show that these silicon facts surface as deterministic gaps in every higher abstraction: ISA atomicity collapses into 95-cycle temporal smearing, privilege isolation falls to speculative pre-check execution, "verified" compilers preserve semantics but not side channels, and formal verification proves architectural safety while microarchitectural state leaks beneath it. The contribution of this work is not a new attack or a new defense; it is the recognition that classical mathematics is itself a Domain-Specific Language — useful, but for a domain that does not include the silicon we run on. We close by enumerating the new primitives that a successor DSL would need: environment-conditioned distributions, multi-scale temporal accumulators, multi-level semantics with explicit leakage, and microarchitecture-aware verification. The cost of these primitives is uncomputability and epistemic humility. The alternative is the lie that exploits live in.

**Keywords:** microarchitecture, formal verification, side channels, Spectre, Meltdown, speculative execution, BTI, epistemology, domain-specific languages.

---

## 0. Introduction: The Lies We Tell Ourselves

We model microarchitecture with classical mathematics. We assume transistors obey differential equations. We believe pipeline behavior can be captured by discrete state machines. We expect deterministic replay. We trust ISA atomicity. We treat privilege levels as isolation. We are lying.

We are lying not because we are dishonest, but because **classical mathematics was never designed for the ontology of silicon**. Mathematics grew out of counting, geometry, and the smoothness fantasies of calculus. It knows nothing about:

- quantum tunneling at 7 nm process nodes;
- thermal gradients producing spatial non-uniformity within a single die;
- electromagnetic coupling between angstrom-separated traces;
- speculative execution that creates causal paradoxes in time.

When a security researcher uses a Monte Carlo simulation to model cache-timing attacks, they participate in a ritual of epistemological self-deception. When a performance engineer fits a Gaussian distribution to interrupt-latency measurements, the battle is already lost. When a kernel developer assumes ISA isolation, the abstraction has already cracked. When a hypervisor engineer expects deterministic VM replay, the silicon has already moved on.

This is not a critique. **This is an autopsy.**

The autopsy proceeds in four parts.

- **Part I — The Silicon Substrate.** What silicon-level physics actually does: continuous-and-discrete power dissipation across orthogonal time scales, aging that accumulates over months while being driven by nanosecond switching, speculative ghost state that is physically real even when architecturally rolled back.
- **Part II — Manifestations at the Boundary.** What happens when those silicon facts hit ISA, compiler, and verification abstractions: atomicity collapses, privilege isolation breaks, semantic equivalence preserves nothing security-relevant, formal proofs cover the wrong state.
- **Part III — The DSL Reconstruction.** What we would need to build to model the real thing: environment-conditioned distributions, multi-scale temporal accumulators, multi-level semantics with explicit leakage maps, microarchitecture-aware verification with sound-but-incomplete approximation.
- **Part IV — Security as Experimental Metaphysics.** Why offensive research at this level *is* metaphysics: the attacker's epistemology, worked examples (Spectre, Meltdown, KPTI bypass via TLB, cross-VM cache side channels), and what the existence of these exploits implies about the abstractions they break.

A final section closes the loop with epistemic humility: a forward path for the researchers, kernel writers, compiler writers, and verification engineers who are now stuck between unsound models and intractable ones.

---

# Part I — The Silicon Substrate

## 1. The Integral That Isn't: Power Dissipation as a Failed Function

### 1.1 The Classical Illusion

The Riemann integral promises:

$$\int_a^b f(t) \, dt = \lim_{n \to \infty} \sum_{i=1}^{n} f(t_i) \, \Delta t$$

Beautiful. Elegant. **Useless** for silicon. The construction assumes:

1. **Time is a continuum** — $a$ to $b$ flows smoothly;
2. **A function $f(t)$ exists** — there is a *thing* to integrate;
3. **Addition is valid** — parts compose into a whole;
4. **The limit exists** — infinite subdivision converges.

### 1.2 Silicon Reality

Consider power consumption on an x86-64 core during speculative execution:

```
Time scale:       1 clock cycle (~0.3 ns at 3.5 GHz)
Event:            Branch misprediction triggers pipeline flush
Physical reality:
  - Transistor switching: 10–50 femtojoules per switch
  - Dependent on:        instantaneous V_dd, local T, manufacturing variation
  - Coupled via:         substrate noise into adjacent lanes
  - History-dependent:   weeks of BTI degradation
```

What are we integrating? The "function" $P(t)$ does not exist in the classical sense:

$$P(t) = \mathrm{???}\Big(V_{dd}(t, x, y),\; T(t, x, y),\; \mathrm{Age}(t),\; \mathrm{SpecState}(t),\; \ldots\Big)$$

where:
- $V_{dd}(t, x, y)$: supply voltage, varying spatially across the die due to IR drop;
- $T(t, x, y)$: temperature gradients radiating from hotspots, with millisecond time constants;
- $\mathrm{Age}(t)$: NBTI/PBTI degradation, cumulative over months;
- $\mathrm{SpecState}(t)$: speculative state that is retroactively invalidated.

**Time is not continuous.** Events are clocked. Between clock edges, analog physics governs: capacitors charge, inductors ring, thermal diffusion proceeds.

**The function is not a function.** It is a stochastic process across multiple time scales with non-local coupling.

**Addition does not work.** Switching activity creates crosstalk that affects neighboring gates' thresholds, so power consumption is non-additive.

**The limit does not exist.** Below certain time scales, quantum effects dominate. Above them, the system has already moved to a different state.

### 1.3 What a Replacement Would Have to Look Like

We need a primitive that is not an integral. Something like:

$$\mathcal{P}[t_0, t_1] = \mathrm{MultiScaleAccumulator}\left\langle
\begin{array}{l}
\text{ClockDomain}:    \Delta t_{\text{clock}} \\
\text{ThermalDomain}:  \Delta t_{\text{thermal}} \\
\text{AgingDomain}:    \Delta t_{\text{aging}} \\
\text{Coupling}:       \Gamma(x, y, t) \\
\text{Stochastic}:     \mathcal{N}(\mu(t), \sigma(t))
\end{array}
\right\rangle$$

This is not mathematical notation. It is a **DSL primitive** that admits:

- multiple simultaneous time scales;
- spatial coupling that does not reduce to temporal integration;
- stochastic non-determinism with time-varying statistics;
- history effects that violate the Markov property.

**You cannot write this in classical mathematics. Hence you write a new language.**

## 2. The Spiral of Time: Multi-Scale Temporal Ontology

### 2.1 The Aging Problem

Consider Bias Temperature Instability (BTI) — the phenomenon by which transistors slow down over months due to trapped charges in the gate oxide. Degradation depends on:

- **Voltage stress** — how long the transistor is in the "on" state;
- **Temperature** — accelerates degradation exponentially;
- **Recovery** — some degradation is reversed when the transistor is "off".

**Time scale:** degradation accumulates over months. **Drivers:** nanosecond switching events.

How do you model this?

### 2.2 Why the Classical Reliability Equation Fails

Standard reliability engineering uses:

$$\mathrm{MTTF} = A \cdot e^{E_a / kT} \cdot V^{-n}$$

This is a lie. It assumes:

- **Constant stress** — transistor always at the same voltage and temperature;
- **No recovery** — damage is monotonic;
- **Independence** — one transistor's degradation does not affect others.

In a real CPU all three are false:

- **Variable stress.** Transistors switch billions of times per second; stress is pulsed, not continuous.
- **Recovery.** When a transistor is off, some trapped charges escape; recovery time constants ~100 μs.
- **Coupling.** Degradation in one path changes its timing, which changes workload distribution, which changes stress on every other path.

### 2.3 The Fifteen-Orders-of-Magnitude Problem

A faithful BTI model must operate at four nested time scales:

| Scale         | Resolution     | What is tracked                                  |
|---------------|----------------|--------------------------------------------------|
| Nanosecond    | 1 clock cycle  | Per-transistor switching activity                |
| Microsecond   | 100 cycles     | Recovery events                                  |
| Millisecond   | thermal const. | Thermal evolution feeding back into degradation  |
| Months/years  | reboot cycles  | Cumulative damage; must persist across power-off |

These scales span **fifteen orders of magnitude**. Classical mathematics says: just integrate.

$$\mathrm{Degradation}(t) = \int_0^t f\bigl(\mathrm{stress}(\tau), T(\tau)\bigr) \, d\tau$$

But you cannot evaluate this integral. The function $f$ depends on history at nanosecond resolution, evaluated over years. The state required to do so is, in bits:

$$10^9 \, \text{transistors} \times 3.5 \times 10^9 \, \text{cycles/s} \times 3 \times 10^7 \, \text{s/yr} \approx 10^{26} \, \text{bits/yr}$$

This is not "a lot of data". It is more than the total information capacity of the device.

### 2.4 Time Is Not a Line

The problem is that we draw time as a single axis:

```
Past ──────► Present ──────► Future
```

In silicon, time is a **multi-dimensional manifold**:

```
Nanosecond axis:   |---clock-tick-tick-tick---|
Microsecond axis:    |--recovery--| |--recovery--|
Millisecond axis:       |---thermal-diffusion---|
Year axis:              |---------aging---------|
```

These axes are **orthogonal**. Events on one axis do not add up to events on another.

**BTI degradation is not an integral over time. It is a functional over a multi-dimensional temporal manifold.**

### 2.5 The Hierarchical Reconstruction

A DSL that takes this seriously would represent time as a *scale hierarchy*:

```rust
struct MultiScaleTime {
    fast:    FastDomain,     // ns:   detailed tracking, short memory
    medium:  MediumDomain,   // μs:   statistical summary, medium memory
    slow:    SlowDomain,     // ms:   aggregate state, long memory
    glacial: GlacialDomain,  // months: cumulative damage, persistent
}

impl MultiScaleTime {
    fn accumulate_degradation(&mut self, event: TransistorEvent) {
        self.fast.record(event);
        if self.fast.should_compress()    { self.medium.absorb(self.fast.compress()); }
        if self.medium.should_compress()  { self.slow.absorb(self.medium.compress()); }
        if self.slow.should_persist()     { self.glacial.accumulate(self.slow.compress()); }
    }

    fn predict_degradation(&self) -> DegradationEstimate {
        // hierarchical fusion across scales — NOT a sum.
    }
}
```

Each time scale is a helix. Fast events spiral quickly. Slow events spiral slowly. But the helices are **nested** — the fast helix is embedded in the medium helix, which is embedded in the slow helix.

**You cannot flatten this into a single integral. The topology is wrong.**

---

# Part II — Manifestations at the Boundary

The silicon facts of Part I do not stay at the silicon level. They surface, predictably, as gaps in every abstraction layered on top. This part walks through those gaps in order: ISA atomicity (§3), the histogram paradox in timing measurement (§4), the impossibility of deterministic exploit replay (§5), the collapse of privilege isolation (§6), and the failure of compiler and formal verification to preserve what matters (§§7–8).

## 3. The First Death of Determinism: ISA Semantics vs Execution Reality

The x86-64 ISA specification states:

```
MOV r64, [m64]
  Destination ← Memory[Address]
  Atomically: load value from memory into register.
```

The classical reading: an atomic, deterministic copy from memory to register. Point.

The execution reading, from the kernel's perspective:

```
Cycle 0:   Decode MOV
Cycle 1:   Check TLB for address translation
Cycle 2:   TLB miss → page table walk begins
Cycle 45:  Page table walk completes
Cycle 46:  Check cache for physical address
Cycle 47:  L1 miss
Cycle 50:  L2 miss
Cycle 94:  L3 hit
Cycle 95:  Load data into register
```

What happens during those 95 cycles?

- Another thread can modify the memory location (TOCTOU).
- The page-table entry can be invalidated (TLB shootdown race).
- The cache line can be invalidated by another core (MESI race).
- An interrupt can arrive (timing perturbation).

The ISA says "atomically". Execution is smeared over 95 cycles.

The classical model assumes:

- **State is discrete.** A before-state, an `execute`, and an after-state.
- **Execution is deterministic.** Same input → same output.
- **Instructions are isolated.** One instruction's execution does not affect others.

At the hardware-software boundary, all three are false.

**State is continuous.** Over 95 cycles there is no "before" and "after", only continuous transition.

**Execution is non-deterministic.** The same instruction, in the same architectural state, takes:

- ~4 cycles if cache is hot;
- ~200 cycles if cache is cold;
- ~1000+ cycles on a page walk;
- ~50 000+ cycles on an SMI.

**Instructions are not isolated.** During execution: cache lines are evicted to other cores, TLB shootdown interrupts arrive, the branch predictor is trained, store-buffer drainage stalls other threads.

The model collapses here for the first time: **ISA promises atomicity; execution delivers temporal smearing and cross-thread side effects.**

## 4. The Histogram Paradox: The Ontology of Timing

### 4.1 The Measurement

A textbook interrupt-latency measurement:

```c
uint64_t measure_interrupt_latency(void) {
    uint64_t t0 = rdtsc();
    asm volatile("int $0x80");
    // handler captures t1
    return t1 - t0;
}
```

Run it 10 000 times. The histogram looks like this:

```
Latency (cycles)  Count   Likely cause
─────────────────────────────────────────────────────────────────
180–200           2 891   Fast path  (cache hot, no contention)
200–220           4 521   Normal     (L2 hit)
220–240           1 844              (L3 hit)
240–280             512              (DRAM hit after cache miss)
280–350             156   Contention (cross-core coherence traffic)
350–500              58   Page fault in handler
500–1 000            15   SMI during handling
1 000–5 000           3   Thermal throttling mid-interrupt
```

The classical approach: take the mean ($\mu = 215$), the standard deviation ($\sigma = 45$), fit a Gaussian. Done.

This is epistemologically bankrupt.

### 4.2 Why the Histogram Lies

This is a **mixture distribution** drawn from at least eight distinct causal mechanisms. Each is a different execution path:

1. **Fast path.** IDT, handler code, and stack all in cache.
2. **Normal path.** Handler in L2.
3. **Cache-pressure path.** Other-core activity has evicted lines.
4. **TLB-miss path.** Handler code page not in TLB.
5. **Page-fault path.** Handler stack page swapped out.
6. **SMI path.** SMM interrupt has preempted.
7. **Thermal path.** CPU is throttling.
8. **NMI path.** Non-maskable interrupt race.

Each path is a different **epistemic category**. Collapsing them into a single distribution **destroys the ontology**.

### 4.3 Where Probability Theory Breaks

Classical probability assumes:

- **IID samples.** Each measurement is independent.
- **Stationarity.** The distribution does not change over time.
- **Single underlying distribution.** There is one "true" distribution.

At the hardware-software boundary, all three fail.

- **Dependence.** The previous interrupt's cache warmth changes the next interrupt's path.
- **Non-stationarity.** Thermal state evolves on millisecond scales; cache pressure tracks the workload; aging shifts every transistor's threshold over months.
- **Multiple distributions.** Eight causal paths, eight different ontological categories.

### 4.4 Environment-Conditioned Distributions

What we need is a histogram **conditioned on the execution environment**:

$$H(t \mid \mathcal{E}), \qquad \mathcal{E} = \{T_{\text{die}}, \text{CacheState}, V_{dd}, \text{Age}, \text{SMI phase}, \ldots\}$$

```rust
struct ExecutionEnvironment {
    cache_state:    CacheWarmth,     // L1/L2/L3 occupancy
    tlb_pressure:   TLBPressure,     // miss rate over last 1000 ops
    thermal_zone:   ThermalState,    // Normal | Warm | Hot | Throttling
    smi_phase:      SMIPhase,        // SMI timing window
    contention:     ContentionLevel, // cross-core activity
}

struct LatencyModel {
    conditional_distributions: HashMap<ExecutionEnvironment, EmpiricalDistribution>,
}

impl LatencyModel {
    fn predict(&self, env: ExecutionEnvironment) -> LatencyDistribution {
        // nearest-neighbour over training data — a learned phenomenological mapping,
        // not classical statistics.
    }
}
```

A latency model is no longer a probability distribution; it is a *function from execution environment to probability distribution*. And the environment itself evolves stochastically, so a meta-model is required for environment dynamics.

Classical mathematics has no vocabulary for this. The second collapse: **ignoring timing destroys ontology, and timing is observable, and observable means exploitable.**

A concrete artefact of this approach lives in the companion [[SILM]] project: a per-CPU interrupt-latency monitor whose first concrete result is a TSC/QPC ratio detector — a per-event microarchitectural witness that fires precisely when an event progresses one clock without progressing the other (SMM transitions, hypervisor preemption, induced glitches). The detector is exactly the "environment-conditioned" view in §4.4 made concrete on commodity hardware.

## 5. The Second Death of Determinism: Why Exploit Replay Is Impossible

### 5.1 Setup: A Race-Condition Exploit

```c
// victim (kernel thread)
if (user_ptr < USER_SPACE_END) {        // time of check
    kernel_value = *user_ptr;            // time of use
    process_data(kernel_value);
}

// attacker (user thread)
while (1) {
    *user_ptr = safe_value;
    *user_ptr = malicious_kernel_ptr;    // race between victim's check and use
}
```

You captured an execution trace where the race won. You replay it. Result: **70 % success rate** — and that is on a good day.

### 5.2 Why Determinism Collapses

What the trace captures:

```
t = 0 ns   Core 0   MOV user_ptr, RAX
t = 1 ns   Core 0   CMP RAX, USER_SPACE_END
t = 2 ns   Core 0   JGE .fail
t = 3 ns   Core 1   MOV malicious_ptr, [user_ptr]   ← race won here
t = 4 ns   Core 0   MOV [RAX], RBX                  ← kernel reads malicious_ptr
```

What the trace does not capture:

1. **Cache state.** Original: `user_ptr` was hot in L1. Replay: cold start; +40 cycles. Race timing shifts.
2. **Branch predictor state.** Original: JGE mispredicted, speculation began. Replay: correctly predicted. Pipeline timing differs. Race flips.
3. **TLB state.** Original: `user_ptr`'s page was in TLB. Replay: TLB miss; +200 cycles. Race lost.
4. **Store-buffer state.** Original: Core 1's store buffer was empty; the store became visible immediately. Replay: store buffer full, draining; timing shifts.
5. **Interrupt timing.** Original: timer interrupt at $t = 10$ ns. Replay: at $t = 5$ ns. Thread scheduling changes. Race lost.

Every one of these is invisible to the architectural state, and every one changes execution timing.

### 5.3 The State-Space Ontology Problem

The classical model:

$$\text{State} = (\text{Registers}, \text{Memory}, \text{PC}), \qquad \text{Execute}: \text{State} \to \text{State}$$

The real state, in code:

```rust
struct RealExecutionState {
    // architectural (in the ISA specification)
    registers: RegisterFile,
    memory:    MemoryImage,
    pc:        Address,

    // microarchitectural (NOT in the ISA, but determining execution)
    cache_state:        CacheHierarchyState,
    tlb_state:          TLBState,
    branch_predictor:   BranchPredictorState,
    store_buffer:       StoreBufferContents,
    rob_state:          ReorderBufferState,

    // external asynchronous (not deterministic)
    interrupt_state:    InterruptControllerState,
    smi_phase:          SMMPhase,
    thermal_state:      ThermalZone,

    // cross-core coupling (not isolated)
    interconnect:       InterconnectState,
    coherence_state:    MESIProtocolState,
}
```

Architectural state is on the order of gigabytes. Microarchitectural state is megabytes. The trace captures only architectural state.

**Full state cannot be captured** because it is too large, partially unobservable (vendor-internal), and subject to observer effect: instrumentation perturbs the state being measured.

### 5.4 The Silicon Cross-Reference

And underneath, silicon adds its own non-determinism. The same instruction sequence in the same architectural state:

- runs ~1.5 % slower at +3 °C die temperature (transistor mobility);
- runs ~2 % slower under voltage droop;
- adds ~60 cycles when crossing a DRAM refresh window.

This is a cross-reference, not the main point: the architectural model is already broken without invoking thermal physics. But it explains why some replays *almost* work and then flip on a hot day.

### 5.5 Constraint-Based Probabilistic Replay

Deterministic replay is impossible. Probabilistic replay with explicit constraints is not:

```rust
struct ConstrainedReplay {
    trace:       Vec<ArchitecturalEvent>,
    constraints: Vec<MicroarchConstraint>,
}

enum MicroarchConstraint {
    CacheMustHit       { addr: Address },
    BranchMustMispredict { pc: Address },
    TLBMustHit         { page: Page },
    StoreBufferMustBeFull,
    InterruptMustNotFire { window: (u64, u64) },
    RaceMustWin        { a_instr: u64, b_instr: u64, max_delta_cycles: u64 },
}

impl ConstrainedReplay {
    fn replay_with_constraints(&mut self) -> Result<ReplaySuccess, ConstraintFailure> {
        for _ in 0..MAX_ATTEMPTS {
            self.setup_cache_for_constraints();
            self.prime_branch_predictor();
            self.control_thermal_state();

            let result = execute_trace(&self.trace);

            if self.all_constraints_satisfied(&result) {
                return Ok(ReplaySuccess { result, satisfaction: self.measure() });
            }

            self.adjust_environment_based_on(self.identify_failed(&result));
        }
        Err(ConstraintNotSatisfiable)
    }
}
```

This is not deterministic replay. It is search through the microarchitectural state space, guided by which properties the exploit actually needs.

A defensive variant of the same idea — using a lockset and synthesized concurrent kernel objects rather than user-space traces — lives in the companion [[KRzr]] project: a Windows kernel-mode race-condition fuzzer whose output is a *classification* of candidate races (TOCTOU, double-free, lock-bypass) rather than a weaponized payload. The shared methodology is to give up on determinism and characterize the space probabilistically.

The third collapse: **the model promises deterministic replay; execution delivers a probability distribution over outcomes.**

## 6. The Crack in Abstraction: Privilege Isolation as Illusion

### 6.1 The ISA's Privilege Model

x86-64:

```
Ring 0 (Kernel):  full privileges, all memory accessible
Ring 3 (User):    restricted, no kernel memory access

privilege check:
  if (CPL > required_privilege_level) #GP exception
  else                                execute instruction
```

Classical model: perfect isolation. User code cannot see kernel memory.

### 6.2 Spectre v1: The First Crack

```c
// user code
if (user_controlled_index < array_size) {     // bounds check
    value = array[user_controlled_index];      // potentially OOB
    dummy = probe_array[value * 4096];         // side channel probe
}
```

ISA semantics: safe. The bounds check guarantees no OOB access.

Microarchitectural execution:

```
Cycle 0   Predict branch (index < size) → TRUE
Cycle 1   Speculatively load array[index]         ← may be kernel memory!
Cycle 2   Speculatively load probe_array[value*4096]  ← cache line loaded
Cycle 3   Check actual condition
Cycle 4   Condition FALSE → flush speculation
          BUT: cache side effect persists.
Cycle 5   Attacker times accesses to probe_array[]:
            fast = cache hit  → value == X
            slow = cache miss → value != X
```

The privilege check happens at cycle 3. The speculative kernel-memory read happens at cycle 1.

### 6.3 Ghost-State Ontology

The classical model:

$$\text{State} = \text{Committed state}; \qquad \text{Invalid speculation} \Rightarrow \text{fully rolled back}$$

The actual structure:

```rust
struct ExecutionState {
    committed:   ArchitecturalState,
    speculative: Vec<SpeculativePath>,
}

struct SpeculativePath {
    architectural_effects:        ArchState,    // committed OR discarded
    microarchitectural_effects:   MicroarchState,  // ← PERSIST even if discarded
}
```

Speculative state is *architecturally* rolled back, but *microarchitecturally* persistent:

- cache lines from speculative loads remain;
- TLB entries from speculative translations remain;
- branch-predictor counters trained by speculative paths remain;
- store-buffer entries from speculative stores can leak.

"Ghost state" — architecturally absent, physically present.

### 6.4 The Silicon Cross-Reference, Again

The ghost is not metaphorical. It is physical:

- a speculative cache load *charged SRAM cells*;
- a speculative TLB write *updated CAM arrays*;
- a speculative branch update *moved a saturating counter*.

Speculation is rolled back; silicon is not. The cross-reference: when the abstraction says "no state change", the silicon still moved.

### 6.5 Meltdown: The Second Crack

```c
// user code
char value = *(char*)kernel_address;       // should fault
char dummy = probe_array[value * 4096];
```

ISA semantics: #GP exception; user code cannot read kernel memory.

Microarchitectural execution:

```
Cycle 0   Speculatively load kernel_address          ← privilege check has not happened yet
Cycle 1   Speculatively load probe_array[value*4096]
Cycle 2   Check privilege
Cycle 3   #GP exception → rollback
          BUT: probe_array[] is in cache.
```

The privilege check happens *after* the speculative read. Isolation is now completely cracked.

### 6.6 Multi-Level Semantics with Explicit Leakage

What we need: explicit semantics at every abstraction level and an explicit **leakage map** between them.

```rust
trait ExecutionSemantics {
    type State;
    type Observable;
    type SideEffects;
    fn execute(&self, i: Instruction, s: Self::State)
        -> (Self::State, Self::Observable, Self::SideEffects);
}

impl ExecutionSemantics for ArchitecturalSemantics {
    type State       = (RegisterFile, Memory);
    type Observable  = ArchitecturalTrace;
    type SideEffects = ();                              // ideal — no side effects
}

impl ExecutionSemantics for MicroarchitecturalSemantics {
    type State       = (ArchState, CacheState, TLBState, PredictorState, …);
    type Observable  = (ArchTrace, CacheTiming, TLBTiming, …);
    type SideEffects = (CacheLineLoads, TLBEntries, PredictorUpdates);  // ← PERSIST
}

fn architectural_projection(s: MicroarchState) -> ArchState {
    s.committed_architectural_state
}

// the key new function — what leaks across the abstraction boundary
fn side_channel_leakage(e: MicroarchSideEffects) -> ObservableLeakage {
    ObservableLeakage {
        cache_timing:        e.cache_line_loads.timing_observable(),
        tlb_timing:          e.tlb_entries.timing_observable(),
        speculation_residue: e.speculative_state.ghost_state(),
    }
}
```

The classical verification statement is:

$$\mathrm{arch\_execute}(i, s) = \pi\bigl(\mathrm{microarch\_execute}(i, \pi^{-1}(s))\bigr)$$

The real verification statement we want is:

1. architectural equivalence (classical);
2. side-channel leakage bounded (new);
3. speculative ghost state characterized (new);
4. timing variation quantified (new).

The fourth collapse: **the model promises perfect isolation; the silicon delivers a side channel.**

## 7. The Tragedy of Compiler Verification: Semantically Equivalent, Security-Wise Different

CompCert is a verified C compiler [Leroy 2009]; it proves that the compiled program is semantically equivalent to the source. The theorem:

$$T_S \approx T_C$$

where $T_S$ and $T_C$ are the source and compiled traces under a notion of trace equivalence. The traces include memory reads/writes, function calls and returns, and I/O. The traces **do not include** cache state, branch-predictor state, speculation events, or **timing**.

Consider this source:

```c
int sum = 0;
for (int i = 0; i < n; i++)
    sum += array[i];
```

Two equally "correct" compilations:

```asm
; Compiler 1 — sequential loads
xor eax, eax
.loop:
    add  eax, [array + rcx*4]
    inc  rcx
    cmp  rcx, n
    jl   .loop
```

```asm
; Compiler 2 — with software prefetch
xor eax, eax
.loop:
    prefetchnta [array + rcx*4 + 64]
    add  eax, [array + rcx*4]
    inc  rcx
    cmp  rcx, n
    jl   .loop
```

CompCert calls these equivalent: the final value of `sum` is the same.

In timing:

- Compiler 1 cache-cold: ~$200n$ cycles;
- Compiler 2 cache-cold: ~$10n$ cycles.

20× difference, "semantically equivalent".

In side-channel surface:

- Compiler 1 leaks which array elements were *accessed*;
- Compiler 2 leaks which elements were *accessed plus which were prefetched*.

For a hypervisor running two VMs compiled with different compilers, CompCert says: equivalent, isolated. The cache says: VM 2 perturbs VM 1's cache state more, giving cross-VM cache side channels. Isolation breach.

The real notion of correctness needs to be multi-observable:

```rust
trait CompilerCorrectness {
    fn semantic_equivalence(&self, source: Program, compiled: Program) -> bool;
    fn timing_equivalence_class(&self, compiled: Program) -> TimingClass;
    fn side_channel_profile(&self, compiled: Program) -> SideChannelProfile;
    fn speculation_footprint(&self, compiled: Program) -> SpeculationFootprint;
}
```

The fifth collapse: **the compiler proves functional correctness; the security surface is invisible to it.**

## 8. The Blind Spot of Formal Verification

Formal verification proves safety properties:

$$\text{State} = (R, M, \text{PC}), \qquad \forall \text{reachable states}: \mathrm{Invariant}(s)$$

For the Spectre snippet of §6.2, the invariant `index < size ⇒ no OOB` is trivially provable. The proof is correct. The cache is still polluted.

Two concrete kernel/hypervisor examples make the failure mode sharp.

### 8.1 KPTI Bypass via TLB Residue

Kernel Page Table Isolation (KPTI) unmaps kernel pages on user-mode entry. Verification: invariant holds — the user-mode page table contains no kernel entries.

But TLB entries from a prior kernel execution can persist:

```
Stale TLB entries:
  kernel_address_1 → physical_page_1 (VALID)
  kernel_address_2 → physical_page_2 (VALID)
```

A user-mode attacker:

```c
*(char*)kernel_address_1;   // should fault
```

Microarchitecturally:

1. TLB hit (stale entry) → translation succeeds.
2. Speculatively load `kernel_address_1`.
3. Privilege check fails → exception.
4. Data is now in cache.

The page table was correctly updated. The TLB cache was not flushed. Verification did not see TLB state because the verification model did not include it.

### 8.2 Cross-VM Cache Side Channel under EPT

Hypervisor verification:

$$\text{VM}_1.\text{memory} \cap \text{VM}_2.\text{memory} = \varnothing$$

Proved by disjoint Extended Page Tables. Conclusion: perfect isolation.

Cache reality:

```
VM 1 access: address_A → physical_page_X → L3 set k
VM 2 access: address_B → physical_page_Y → L3 set k     (set collision)
```

VM 1's access evicts VM 2's line. VM 2 measures its own timing changes. Prime+Probe across the supposed isolation boundary. EPT isolates address space; it does not isolate cache sets.

The pattern is general. The classical state $(R, M, \text{PC})$ is the wrong domain for the verification:

```rust
struct VerificationState {
    arch:               ArchitecturalState,
    cache_abstract:     AbstractCacheState,
    tlb_abstract:       AbstractTLBState,
    speculation_bound:  SpeculationDepth,
    timing_class:       TimingEquivalenceClass,
}

trait SecurityProperty {
    fn architectural_safety(&self, s: ArchitecturalState) -> bool;       // classical
    fn cache_non_interference(&self, s: VerificationState) -> bool;      // new
    fn timing_leakage_bounded(&self, s: VerificationState) -> bool;      // new
    fn speculation_safe(&self, s: VerificationState) -> bool;            // new
}
```

But the microarchitectural state is huge, partially specified (vendor-secret), and asynchronously evolving. Full verification is intractable. The only viable program is abstract interpretation — sound but incomplete — which acknowledges the silicon rather than ignoring it.

The sixth collapse: **the model proves architectural safety; the microarchitectural leakage is invisible.**

---

# Part III — The DSL Reconstruction

The pattern across §§3–8 is unambiguous. At every level, classical mathematics offers a clean abstraction; at every level, the silicon refuses to honour it; at every level, the gap is exploitable. The pattern is so consistent that it suggests the problem is not in any one abstraction but in the choice of *language* for all of them.

## 9. The DSL Imperative

The central thesis of this writeup:

> **Classical mathematics is a Domain-Specific Language for domains that do not include microarchitecture.**

Mathematics was built for:

- counting (discrete, finite);
- geometry (continuous, Euclidean);
- calculus (smooth functions, limits);
- probability (IID samples, stationary processes).

Microarchitecture is:

- hybrid discrete-continuous (digital logic + analog physics);
- non-Euclidean (event causality, not spatial distance);
- non-smooth (threshold effects, speculation rollback);
- non-stationary (thermal drift, aging, adaptive behavior).

Forcing microarchitectural reality into classical mathematical notation destroys the ontology. What we need is a DSL for the silicon.

### 9.1 Concrete Examples of New Primitives

**Cache coherence is not a finite-state machine; it is a stateful transition with timing:**

```rust
enum CacheLineState {
    Modified  { owner: CoreId, dirty_time: Timestamp },
    Exclusive { owner: CoreId, speculation_count: u32 },
    Shared    { sharers: BitSet<CoreId>, last_coherence: Duration },
    Invalid   { invalidation_source: CoreId, pending_fill: Option<FillRequest> },
}

impl CacheLineState {
    fn transition(&mut self, e: CoherenceEvent, env: &MicroarchState) -> Latency {
        match (self, e) {
            (Modified { .. }, ReadRequest(requesting_core)) => {
                let interconnect = env.interconnect.latency(self.owner, requesting_core);
                let mem_write   = env.memory.write_latency();
                *self = Shared { /* … */ };
                interconnect + mem_write
            }
            // … other transitions, each carrying its own latency.
        }
    }
}
```

A classical state machine has no time. A DSL state machine returns time.

**Speculative execution is not a control-flow event; it is a forking of reality:**

```rust
struct SpeculativeState {
    committed: ArchitecturalState,
    shadow:    Vec<SpeculativePath>,
    oracle:    BranchPredictor,
}

impl SpeculativeState {
    fn execute(&mut self, i: Instruction) -> ExecutionResult {
        if i.is_branch() {
            let p = self.oracle.predict(i);
            let mut path = SpeculativePath {
                depth:        self.current_depth() + 1,
                state:        self.committed.clone(),
                confidence:   p.confidence,
                side_effects: SideEffectLog::new(),
            };
            path.execute(i, p.target);
            self.shadow.push(path);
            ExecutionResult::Speculative(p.target)
        } else if self.in_speculation() {
            self.shadow.last_mut().unwrap().execute(i)
        } else {
            self.committed.execute(i)
        }
    }

    fn resolve_branch(&mut self, actual: Address) {
        let speculated = self.shadow.last().unwrap().target;
        if actual == speculated {
            self.committed = self.shadow.pop().unwrap().state;
        } else {
            let leftover = self.shadow.pop().unwrap().side_effects;
            self.committed.apply_side_effects(leftover);      // ← cache pollution remains
            self.committed.pc = actual;
        }
    }
}
```

Classical control flow is a single timeline. This DSL captures multiple simultaneous realities and the residue of the discarded ones.

### 9.2 The Cost of the New Language

The DSL primitives proposed across this writeup — multi-scale temporal accumulators, environment-conditioned distributions, multi-level semantics with leakage, microarchitecture-aware verification — all share a property: they admit that the problem is **uncomputable**.

- BTI degradation over years cannot be computed exactly.
- Exploits cannot be replayed deterministically.
- Microarchitectural security cannot be verified completely.

This is not a failure of the DSL. This is the DSL telling the truth about silicon.

The alternative — pretending classical mathematics suffices — is worse: it manufactures false confidence, hides real bugs, and ships the abstractions exploits live inside.

---

# Part IV — Security as Experimental Metaphysics

## 10. The Attacker's Epistemology

A security researcher who exploits a microarchitectural vulnerability is not doing classical computer science. They are doing **experimental metaphysics.**

They are asking: *what is the real ontology of this silicon?* Not the ontology in the ISA specification. Not the ontology assumed by the compiler. The **real** one — the one in which:

- branch-predictor state leaks across security domains (Spectre);
- speculative execution bypasses privilege checks (Meltdown);
- DRAM cell coupling violates memory isolation (Rowhammer);
- cache timing reveals secrets (Cachebleed);
- shared microarchitectural buffers leak data across SMT siblings (MDS, TAA, ZombieLoad).

**All of these exploits exist because the classical model is wrong.**

Where the formal verifier proves an invariant on $(R, M, \text{PC})$, the attacker observes a fact about $(\text{Cache}, \text{TLB}, \text{Predictor})$. The verifier is correct. The attacker wins.

## 11. Worked Example: Spectre v1 as an Ontology Bug

The defender's view:

```c
if (x < array_size) y = array[x];   // safe
```

The verifier's proof: invariant holds.

The attacker's experimental finding:

1. Train the branch predictor to expect `x < array_size`.
2. Issue with $x \gg \text{array\_size}$.
3. The CPU speculatively loads `array[x]` (out of bounds, possibly kernel memory).
4. The CPU speculatively loads `probe_array[array[x] * 4096]`.
5. The bounds check eventually fails; speculation is rolled back.
6. The cache footprint persists.
7. The attacker times accesses to `probe_array` and reads back `array[x]`.

The defender's mathematics is correct. The attacker's mathematics is *more correct*: it includes the cache.

Every "verified safe" attempt against the snippet implicitly used:

$$\text{State} = (R, M, \text{PC}); \qquad \text{Execute}: \text{State} \to \text{State}$$

The real state includes the cache, the predictor, the TLB, the ROB, the speculative paths. The verifier's ontology was wrong, and the wrongness was an exploitable invariant of the verifier.

## 12. Worked Example: Replay Cannot Recover the Exploit

The §5 race-condition exploit demonstrates the dual failure. The attacker landed it once; on replay it succeeds 70 % of the time. The trace captured architectural state. The microarchitectural state — cache warmth, predictor history, TLB residue, store-buffer fullness — was not in the trace and is not recoverable.

The honest defensive response is not to demand "perfect" reproducibility. It is to acknowledge that:

- the architectural trace is an underspecification of the exploit;
- the underspecification has a measurable size in bits;
- the gap is exactly the size of the microarchitectural state the architectural model abstracts away.

A constraint-based search through that gap is *the* method that survives the collapse. This is exactly what the [[KRzr]] race detector and the constraint-replay sketch in §5.5 implement at different levels.

---

# 13. Conclusion: The Uncomputable Truth, and Epistemic Humility

The pattern across §§1–12 is one observation made six times:

1. **Time.** The integral $\int P(t)\,dt$ does not exist for silicon; we need a multi-scale temporal accumulator.
2. **Aging.** The reliability equation $\mathrm{MTTF} = Ae^{E_a/kT}V^{-n}$ does not survive contact with pulsed stress, recovery, and coupling; we need hierarchical temporal accumulation.
3. **Atomicity.** ISA `MOV` is not atomic; it is smeared across 95 cycles and exposed to TOCTOU, TLB shootdown, MESI races, and interrupts.
4. **Determinism.** Replay of a captured trace recovers neither the cache nor the predictor nor the TLB; replay is a constraint-satisfaction problem, not a re-run.
5. **Isolation.** Privilege checks happen after speculation, not before; cache, TLB, and predictor cross privilege boundaries.
6. **Verification.** Architectural safety proofs are sound on the wrong state; the microarchitectural state where the exploits live is invisible to the proof.

What the six collapses share is not a list of bugs to fix. It is a methodological claim: **classical mathematics is a DSL, and microarchitecture lies outside its domain.** Inside the gap between the DSL and the silicon, exploits live.

The replacement is not "better mathematics". It is **more honest mathematics** — a set of DSL primitives that admit what they cannot compute:

- environment-conditioned distributions instead of stationary ones;
- multi-scale temporal accumulators instead of integrals;
- multi-level semantics with explicit leakage maps instead of single-level operational semantics;
- microarchitecture-aware verification, sound but conservatively incomplete, instead of architectural-only proofs.

The cost is uncomputability and epistemic humility. The benefit is honesty.

### 13.1 Forward Path

| Audience                            | Stop                                       | Start                                                                          |
|-------------------------------------|--------------------------------------------|--------------------------------------------------------------------------------|
| Microarchitecture researchers       | Gaussian fits over latency histograms      | Environment-conditioned distributions; characterize causal paths               |
| Microarchitecture researchers       | Expecting deterministic replay             | Probabilistic constraint-based replay; report confidence with results          |
| Kernel / hypervisor developers      | Trusting ISA isolation guarantees          | Assume microarchitectural leakage; design and audit accordingly                |
| Compiler writers                    | Optimizing for semantic equivalence only   | Preserve timing class and side-channel footprint as first-class targets        |
| Verification engineers              | Proving safety on $(R, M, \text{PC})$ only | Include an abstract microarchitectural state; accept sound-but-incomplete proofs |
| All of us                           | Pretending mathematics suffices            | Build the DSL that doesn't.                                                    |

### 13.2 Final Aphorism

> The map is not the territory.
>
> At the hardware-software boundary, the territory is speculative ghost states, cache-timing side channels, and non-deterministic execution.
>
> Underneath, the silicon is quantum tunneling, thermal kaos, and aging that propagates over months.
>
> The map says: *atomic, deterministic, isolated.*
>
> The territory says: *smeared, stochastic, coupled.*
>
> Inside the gap between map and territory, exploits live.
>
> Don't trust the map. Learn the territory.

---

## References

[1] P. Kocher, J. Horn, A. Fogh, et al. *Spectre Attacks: Exploiting Speculative Execution.* IEEE S&P, 2019.

[2] M. Lipp, M. Schwarz, D. Gruss, et al. *Meltdown: Reading Kernel Memory from User Space.* USENIX Security, 2018.

[3] D. Gruss, R. Spreitzer, S. Mangard. *Cache Template Attacks: Automating Attacks on Inclusive Last-Level Caches.* USENIX Security, 2015.

[4] J. Van Bulck, M. Minkin, O. Weisse, et al. *Foreshadow: Extracting the Keys to the Intel SGX Kingdom with Transient Out-of-Order Execution.* USENIX Security, 2018.

[5] C. Canella, J. Van Bulck, M. Schwarz, et al. *A Systematic Evaluation of Transient Execution Attacks and Defenses.* USENIX Security, 2019.

[6] R. Guanciale, M. Balliu, M. Dam. *InSpectre: Breaking and Fixing Microarchitectural Vulnerabilities by Formal Analysis.* ACM CCS, 2020.

[7] S. Cauligi, C. Disselkoen, K. von Gleissenthall, et al. *Constant-Time Foundations for the New Spectre Era.* PLDI, 2020.

[8] E. Bosman, K. Razavi, H. Bos, C. Giuffrida. *Dedup Est Machina: Memory Deduplication as an Advanced Exploitation Vector.* IEEE S&P, 2016.

[9] Y. Kim, R. Daly, J. Kim, et al. *Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors.* ISCA, 2014. (Rowhammer.)

[10] X. Leroy. *Formal verification of a realistic compiler.* Communications of the ACM 52(7), 2009. (CompCert.)

[11] Intel Corporation. *Intel® 64 and IA-32 Architectures Optimization Reference Manual.* 2024.

[12] A. Fog. *The microarchitecture of Intel, AMD and VIA CPUs.* 2024.

[13] J. L. Hennessy, D. A. Patterson. *Computer Architecture: A Quantitative Approach.* 6th ed., Morgan Kaufmann, 2017.

[14] M. A. Alam, S. Mahapatra. *A comprehensive model of PMOS NBTI degradation.* Microelectronics Reliability 45(1), 2005. (BTI physics.)

[15] J. Van Bulck, F. Piessens, R. Strackx. *SGX-Step: A Practical Attack Framework for Precise Enclave Execution Control.* SysTEX, 2017.

[16] K. Murdock, D. Oswald, F. Garcia, J. Van Bulck, D. Gruss, F. Piessens. *Plundervolt: Software-based Fault Injection Attacks against Intel SGX.* IEEE S&P, 2020.

[17] L. Wittgenstein. *Tractatus Logico-Philosophicus.* Routledge & Kegan Paul, 1922.

[18] L. Wittgenstein. *Philosophical Investigations.* Macmillan, 1953.

[19] S. Kripke. *Naming and Necessity.* Harvard University Press, 1980.

---

## Appendix A — Companion Writeups

This writeup is the theoretical companion to several measurement-oriented projects in the same collection:

- [[SILM]] — Per-CPU interrupt-latency monitor with online CUSUM change-point detection and a TSC/QPC ratio detector. Concrete realization of the "environment-conditioned distribution" thesis of §4.4.
- [[KRzr]] — Windows kernel-mode race-condition fuzzer. Concrete realization of the "constraint-based probabilistic replay" thesis of §5.5.
- [[CTPhys]] — Empirical four-phase elimination of microarchitectural leak sources in a textbook "constant-time" `memcmp`. Concrete realization of the "branchless ≠ leakless" claim implied by §7.
- [[SPIFault]] — Fault-injection campaign description framework (FCDF). Operates at the silicon layer the writeup discusses but does not measure.
- [[SYM_Triage]] — Symbolic IOCTL triage; the constraint-based reasoning the writeup proposes, applied at the binary level.

## Appendix B — Reading list for the disillusioned

*Epistemology and ontology.* Wittgenstein, *Tractatus*; *Philosophical Investigations*. Kripke, *Naming and Necessity*. Nietzsche, *The Gay Science*.

*Microarchitectural attacks (reality check).* Kocher et al. (Spectre); Lipp et al. (Meltdown); Gruss et al. (Cache Template); Van Bulck et al. (Foreshadow, SGX-Step); Canella et al. (Transient Execution Survey).

*Microarchitecture internals (know the silicon).* Intel Optimization Manual; Agner Fog, *The microarchitecture of Intel, AMD and VIA CPUs*; Hennessy & Patterson, *Computer Architecture*.

*Formal verification limitations.* Guanciale et al. (InSpectre); Cauligi et al. (Constant-Time Foundations).

*Kernel and hypervisor security.* Bosman et al. (Dedup Est Machina); Kim et al. (Rowhammer); Murdock et al. (Plundervolt).

*Your CPU's errata sheet.* The uncomputable truth, vendor-by-vendor.

---

*This document was written acknowledging that all models are wrong, that some are useful, and that classical mathematics, at the hardware-software boundary, is neither. — With epistemic humility.*
