# HBO NL Portfolio — Project Pitches

*One-paragraph elevator pitches for each project in this staging
folder. Drop-in for application essays, CVs, or repository
descriptions. Each pitch is ~80–120 words and follows the same
arc: **problem → contribution → method → outcome**.*

---

## Portfolio overview

Thirty-nine projects spanning offensive and defensive low-level
security, microarchitectural side channels, fault-injection
methodology, firmware-level fault surfaces, DRAM read-disturbance
phenomenology, Secure-Boot signature-chain auditing,
Confidential-Computing (SEV-SNP / TDX / CCA) attack surfaces,
hardware-assisted kernel mitigation assurance, trust-boundary
auditing across hypervisor / VBS / TEE layers, Linux
kernel-bypass networking and DDoS defense, Windows .NET runtime
telemetry, Windows BitLocker stack anatomy, GPU side-channels
in AI inference workloads, the emerging boundary between AI
systems and OS-layer threat models, the epistemology of
formal verification at the hardware-software interface,
cross-layer invariant failure in mobile graphics driver interfaces,
the hardware-software trust boundary at the physical memory layer
through DMA and IOMMU analysis, control-flow mitigation
bypass via Counterfeit Object-Oriented Programming against Intel CET,
hypervisor-level PatchGuard bypass via EPT shadowing and DPC
timer trap injection through VMX root, dynamic EDR API unhooking
via VMExit-driven ephemeral syscall stub restoration with
blue-team telemetry correlation, and Linux io_uring
use-after-free (CVE-2022-29582) as a concurrent lifecycle race
between flush path and timer path on a linked timeout object. The collection
is unified by a single methodological posture: low-level systems
behavior is best characterized by reproducible measurement plus a
clean threat model, not by exploit demonstrations. Each
repository ships with explicit scope limits, defensive framing,
and a roadmap that distinguishes what is implemented from what is
an integration point. The two theoretical writeups
(Mathematical Collapse, Speculation Barrier Illusion) serve as
the connective tissue that explains why the engineering choices
across the rest of the portfolio look the way they do.

---

## CTPhys — Empirical Walkthrough of *Physical* Constant-Time

Cryptographic implementations are required to be "constant-time"
to defeat timing side channels, but the textbook construction —
a branchless reduction over fixed-length inputs — is provably
insufficient on commodity x86 silicon. CTPhys is a four-phase
reproducible elimination experiment that isolates the dominant
microarchitectural leak source one variable at a time: cache
state, store-buffer pressure, and execution-port contention. The
analyzer ships with shipped reference histograms and a pytest
regression suite. The repository's contribution is pedagogic — a
defender can read it top-to-bottom and end up with a working
intuition for *why* a constant-time claim has to be argued
against the microarchitecture, not against the C source.

---

## HGS-Analyzer — Hyper-V Host Guardian Service Attestation Modeller

Microsoft's Host Guardian Service is the trust anchor for Hyper-V
shielded VMs; understanding which parts of its attestation,
key-protection, and policy chain produce which observable failure
modes is a prerequisite for rigorous evaluation of HGS
deployments. HGS-Analyzer is a C-based research framework that
reproduces the HGS request flow in user-mode and kernel-mode
simulators, exercises the attestation parsers and key-protector
modellers with synthesized inputs, and records observed RPC
sequences to disk. It does not touch any deployed HGS endpoint;
all activity is against synthetic streams in a lab. The
framework's value is as a modelling substrate for defenders
performing HGS hardening reviews.

---

## KRzr — Kernel Race Condition Detector

Synchronization mistakes, lock-bypass windows, and TOCTOU
sequences in kernel code paths are among the highest-impact bug
classes in modern systems software, yet remain under-instrumented
relative to memory-safety bugs. KRzr is a Windows kernel-mode
fuzzer (KMDF) paired with a Python orchestrator that drives five
cooperating modules: a thread-interleaving simulator, a shared
resource mutator, a lockset-based race detector, a fault-pattern
generator, and a coverage tracker biasing future trials. The
output is a structured *classification* of candidate races — bug
class only, not weaponized payloads. The tool is intended for
defensive research on dedicated kernel-debug VMs.

---

## KSIF — Kernel Semantic Integrity Framework

DKOM-class kernel rootkit attacks are not memory-safety
violations: they write legal values to legal fields while
breaking the *relational contract* those fields participate in
(unlinking an `EPROCESS` from `ActiveProcessLinks` while keeping
it scheduled; swapping a SYSTEM token onto another process).
Memory-safety tooling (HVCI, CFG, KASLR) does not address this
class. KSIF treats the problem at the right level: it enumerates
the semantic graph over six kernel structures, defines three
deviation metrics (Semantic Drift Score, Detection Delta,
Stability Envelope), and ships a CLI emitting the graph and
metric scaffold. The current build is read-only and observational
— a specification and measurement substrate for detection
engineers.

---

## Kernel-Mode Deception Framework (KDF)

Defenders against kernel-resident adversaries face an
observability asymmetry: privileged code can disable, hook, or
spoof every monitoring primitive that lives at its own level.
KDF is a six-layer kernel-mode honeypot for Windows that
inverts this asymmetry by redirecting probing into a fake
"universe" of synthetic kernel objects — `EPROCESS` / `ETHREAD`
structures with non-canonical addresses, periodic anti-fingerprint
mutation, and inline hooks on a curated syscall set. The driver
does not block, terminate, or unhook anything; it observes and
classifies. Output is a structured behavioral report suitable for
analyst review. Intended for research on dedicated lab hosts with
test-signing enabled.

---

## Decoy-Surface-Writeup — The Decoy Surface: Anatomy of Hypervisor-Mediated Kernel Deception

The anatomical research-side companion to KDF. Where the
engineering project ships a working honeypot, this writeup reads
the same techniques as a substrate question: a fake `DEVICE_OBJECT`
at a known constant handle value, an SSDT-routed IOCTL handler
returning structured decoy responses, a magic-triggered network
listener bound to a kernel driver, an APC-queued late-bound code
path, and the hypervisor-mediated observability layer that sits
beneath all of them. The contribution is the symmetry argument:
the same primitives appear in offensive rootkit campaigns
documented in the wild (LoJax, MosaicRegressor, Reign-class APT
toolchains) and in defensive honeypot research (Spitzner's
*Honeypots*, Provos's Honeyd, NIST SP 800-160 vol. 2's deception
patterns, KDF and its academic predecessors). The piece reads
SSDT hooking, handle-table semantic injection, APC code delivery,
and manual kernel-internal PE export resolution as architectural
features whose susceptibility is a structural fact about the
composition, not the moral failing of any one component.

---

## KMTO — Kernel Mitigation Telemetry Observatory

Modern kernels ship a dense stack of hardware-assisted mitigations
— SMEP, SMAP, PAC, CFG/KCFG, KASLR, KPTI, VBS, HyperGuard — each
individually vendor-documented; what is *not* documented is the
operational state on a delivered image: which control bits are
actually set, how long a STAC/CLAC bracket stays open under load,
whether observed PAC failures match the configured policy. KMTO is
a cross-platform C observation framework that distinguishes
*presence* (CPUID/HWCAP) from *enablement* (CR4/kernel state) from
*enforcement* (per-scenario fault classification), runs a
deterministic harness of eight scenarios against a 2³ configuration
matrix, and ships a Windows KMDF driver plus handshake CLI
demonstrating real kernel telemetry. The contribution is
reproducible, machine-parseable evidence — JSON, Markdown, Graphviz
DOT — that a configured mitigation stack is firing as designed.
Observation-only; no exploitation paths.

---

## StealthL4Guard — A Silent L4 DDoS Defense Pipeline

L4 DDoS defenses tend either to be *loud* — they send `RST` /
`ICMP unreachable` and announce their presence — or *coarse* —
they drop large prefixes and fall over under sophisticated mixed
traffic. StealthL4Guard is a Linux-native four-layer pipeline
(XDP → TC/eBPF → nftables/raw → HAProxy) that combines line-rate
filtering, per-flow behavioral classification, and silent kill
decisions, with no observable feedback to the attacker. The
layers communicate exclusively through one byte of `skb->mark`,
which keeps each layer independently reloadable. The repository
ships both eBPF programs (XDP header validation + LPM prefix
trie + per-IP rate maps; TC 5-tuple flow classifier with
`MARK_GREY` / `MARK_KILL` verdicts), the `nftables` ruleset that
runs at pre-conntrack priority, the HAProxy stick-table config,
the Makefile and CI to build them, and a deep-dive document
explaining why each layer is where it is. The contribution is
the architectural posture — *defense moves earlier as confidence
grows*, *silence is preserved by construction* — instantiated as
working data-plane code.

---

## SILM — Per-CPU Interrupt Latency Monitor

Interrupt latency is one of the few defensive signals that
crosses the hardware boundary into kernel-visible territory; it
also encodes signals from co-resident adversaries (SMM
transitions, hypervisor preemption, SGX-Step single-stepping).
Existing monitors (ETW, perfmon, xperf) aggregate at coarse
intervals. SILM is a KMDF driver + C++ daemon + Python analysis
stack that captures per-CPU ISR/DPC event traces with lock-free
acquisition and surfaces anomalies online via CUSUM change-point
detection over an EWMA-tracked baseline. The framework's first
concrete result is a TSC/QPC ratio detector that catches
microarchitectural events progressing one clock without
progressing the other — a candidate substrate for empirical
study of OS-layer leakage on commodity hardware.

---

## SPIFault — Fault Campaign Description Framework

The fault-injection literature consistently lacks a shared way
to describe a campaign — Plundervolt papers use English prose,
ChipWhisperer demos use Python snippets, VoltJockey uses Verilog
timing tables. SPIFault proposes a YAML schema (Fault Campaign
Description Format) with a Python validator and a reference
simulator backend, so that campaigns can be archived, diff'd,
hashed, and shared between labs. Five sample campaigns
(voltage glitch, single-bit flip, instruction skip, multi-glitch
burst, SPI boot replay) demonstrate the schema. Hardware backends
(ChipWhisperer, Raspberry Pi spidev, sigrok) are documented
integration points respecting the simulator's semantics. The
contribution is *specification and reporting*, not a rig.

---

## SPI-Firmware-Anatomy-Writeup — An Anatomy of Firmware Fault Injection: From SPI Bus to Bootloader

The content-side companion to SPIFault. Where SPIFault proposes
the *schema* for describing a fault-injection campaign, this
writeup is an anatomical dissection of the surface a campaign
targets — the SPI bus protocol, the SPI flash IC's die-level
state machine, the boot ROM's chain of signatures, and the four
physical fault-injection categories (voltage glitch, clock
glitch, electromagnetic fault injection, SPI bus interception).
The piece takes a deliberately research register — neither
attacker's how-to nor defender's checklist — and treats the
composition as a structural object: where the bus's properties,
the IC's control structures, and the chain's trust handoffs
admit fault states under documented physical conditions. The
empirical-literature section surveys two decades of work
(Bar-El's fault taxonomy, CLKSCREW, Plundervolt, VoltPillager,
BootStomp, LoJax, MosaicRegressor, the TPM-sniffing literature,
ChipWhisperer and EMFI tooling), with citations to the venue
of record for each result. The writeup closes with seven open
research questions where the published literature is incomplete
— variability across flash vendors, temperature dependence of
glitch success, formal models of boot-chain trust handoffs,
spatial-selectivity bounds on EMFI, observability of productive
glitches via system telemetry, the update-channel formal
verification gap, and the relationship between transient and
directly-persistent fault phenomena. Paired with SPIFault as a
mini-cluster on fault-injection research communication.

---

## Rowhammer-Decade-Writeup — A Decade of Rowhammer: From DRAM Disturbance to Production Mitigation

An anatomical synthesis of ten years of Rowhammer literature, from
Kim et al. (ISCA 2014, the foundational paper) through TRRespass
(Frigo et al., S&P 2020), Half-Double (Kogler et al., S&P 2022),
Blacksmith (Jattke et al., S&P 2022), Phoenix (DDR5, 2024), RowPress
(row-open-duration), ZenHammer (AMD Zen platforms), and the
PRAC/QPRAC vendor mitigations. Each section names the architectural
assumption a vendor mitigation depended on and the empirical finding
that invalidated it. The reading register is anatomical: DRAM
read-disturbance is a physical phenomenon of charge leakage at cell
boundaries, repeatedly demonstrated to be exploitable as each new
vendor mitigation reaches deployment. Pairs with SPI-Firmware-Anatomy
as the portfolio's second physical-hardware fault-surface reading,
the two together covering the firmware-level (SPI flash) and
DRAM-level (Rowhammer) sides of the substrate.

---

## Secure-Boot-Anatomy-Writeup — The Secure Boot Promise: Anatomy of a Signature Chain and Its Documented Bypasses

An anatomical read of the UEFI Secure Boot signature chain —
Platform Key (PK), Key Exchange Keys (KEK), Allowed Signatures
Database (DB), Forbidden Signatures Database (DBX) — as four
structural links, with each link's verification-ordering assumption
and the published bypass that invalidated it. Documents BootHole
(CVE-2020-10713, GRUB2 buffer overflow disclosed by Eclypsium 2020),
BlackLotus (ESET 2023, the first observed UEFI bootkit known to
bypass Secure Boot on fully updated Windows 11), BootStomp (Redini
et al., USENIX Security 2017), the long history of shim/grub2/winload
signature-bypass CVEs, and the DBX revocation-list maintenance gap.
Pairs with SPI-Firmware-Anatomy as the laser-focused signature-chain
instance for that piece's boot-ROM-chain section. The register is
anatomical: the chain's links are correctly implemented in isolation;
the documented failures are structural features of how the links
don't fully cover each other in composition.

---

## SYM-Triage — Static + Pattern-Based IOCTL Handler Triage

The BYOVD ("Bring Your Own Vulnerable Driver") attack class has
become a dominant post-exploitation primitive, and Microsoft's
Vulnerable Driver Blocklist exists precisely because manual
triage does not scale. SYM-Triage combines PE-aware static
analysis with a pattern-based handler-classification pass to extract
IOCTL codes from a driver binary, model each handler's input
buffer parsing, and emit *classifications* — "IOCTL X accepts a
buffer whose contents reach a kernel-memory write whose address
and size are caller-controlled" — never exploit payloads. The
shipped case study reproduces analysis of publicly disclosed
WinRing0 vulnerabilities (CVE-2020-14979). Output is JSON
amenable to diffing and downstream defensive triage.

---

## Observer-Defined Reality Engine

A small Python library implementing a strict state machine for
weighted-set selection under coordinated observation. Inspired
by the von-Neumann measurement picture but presented as a
concrete engineering artefact: an instruction set, a phase state
machine (IDLE → MW_OPEN → PROJECTION → DECISION_BOUNDARY →
POST_COLLAPSE → IDLE), and a Python API that enforces five
invariants — single-collapse-per-window, state immutability
during a window, question scoping, atomic collapse, and history
completeness. The engine is not a quantum simulator; it is a
transactional-semantics reference implementation useful for
DSLs over state-with-potentials, workflow engines with strict
commit boundaries, and pedagogy.

---

## ACMM-Writeup — AI Contextual Memory Manipulation: Architecture, Exploitation, and Defense

A standalone academic writeup arguing that the auxiliary memory
layer wrapping production LLMs (vector databases, similarity
scorers, retrieval policies, decay engines) is best understood
as a *virtual memory subsystem for an inference engine* — and
that this framing predicts an enumerable class of exploitable
behaviors. The paper details the low-level (SIMD / CUDA)
implementation of six ACMM components, maps classical
memory-corruption primitives onto the context layer (overflow,
heap corruption, use-after-free, syscall hijacking), characterizes
TOCTOU races in tool-augmented agents, and proposes a layered
defense program. Its contribution is the unified low-level
framing connecting binary exploitation methodology to emerging
AI safety research.

---

## Mathematical-Collapse-Writeup — Where Classical Mathematics Collapses: The Silicon Substrate and the Hardware-Software Boundary

A long-form academic writeup arguing that classical mathematics
is itself a Domain-Specific Language — useful, but for a domain
that does not include the silicon we run on. The paper traces the
failure at two levels: at the silicon level (continuous-and-discrete
power dissipation, BTI aging across fifteen orders of magnitude in
time scale, speculative ghost state that is physically real even
when architecturally rolled back), and at the hardware-software
boundary (ISA atomicity collapsing into 95-cycle temporal smearing,
privilege isolation falling to speculative pre-check execution,
"verified" compilers preserving semantics but not side channels,
formal proofs covering architectural state while microarchitectural
state leaks beneath). The contribution is the unified epistemological
framing across six observation points, with proposed DSL primitives
(environment-conditioned distributions, multi-scale temporal
accumulators, multi-level semantics with explicit leakage maps)
and explicit acknowledgement of the uncomputability cost.

---

## Silicon-Adversary-Writeup — Silicon Is the Adversary: Microarchitectural Threats from Spectre to Hertzbleed

A long-form writeup that re-reads the eight-year arc of post-2018
microarchitectural security — Spectre, Meltdown, Foreshadow,
deduplication-assisted Rowhammer, Hertzbleed — not as a catalogue
of CVEs but as instances of a single categorical fact: the silicon
substrate produces observable side-effects that the software-side
threat model never modelled. The contribution is a unifying frame
("silicon is the adversary") plus a layered defensive map that
makes structurally explicit why no single layer of the stack can
close any one of these threats: the attack lives at the
microarchitecture; the mitigation lives one layer up (compiler,
kernel, microcode, operational policy). The writeup develops
Speculative Constant-Time and the Pitchfork analyzer as the
strongest formal answer, walks the cross-domain primitive set
(dedup as oracle, Rowhammer as write, Foreshadow as L1 decloak),
and devotes a section to Hertzbleed as the cleanest demonstration
that "constant-time" was always a property of an abstraction and
never of the silicon. Companion to Mathematical-Collapse (the
high-altitude theory) and Speculation-Barrier-Illusion (the
laser-focused reproducible instance) — together the three pieces
read as theory → map → instance.

---

## Microarch-Isolation-Writeup — No Boundary Below the Architecture: VMScape, GhostRace, and the TEE Assumption

The vertical complement to *Silicon Is the Adversary*. Where that
piece treats post-2018 microarchitectural attacks as a horizontal
family, this one drills through five trust-boundary layers —
user / kernel / hypervisor / VBS / TEE — naming each layer's
load-bearing assumption and the microarchitectural reality that
breaks it. The operational core of the writeup is a TEE
guarantee matrix, item by item: enclave technology *does*
defeat direct memory read, DMA from compromised devices, and
crash-dump analysis; it *does not* defeat cache-timing
observation, branch-predictor poisoning, speculation-based
leakage, or FPU/AVX register-spill timing — and the matrix
makes the distinction explicit at the level of detail a defender
needs. The writeup then unpacks two 2024-era attacks chosen
because each demonstrates a different boundary failing in a
different layer: **VMScape** (ETH Zurich, S&P 2026; branch-
predictor state surviving VM exit by design) and **GhostRace**
(VUSec, USENIX Security 2024, CVE-2024-2193; speculative bypass
of mutex / atomic synchronization). A "Not a Bug" section names
the performance / confidentiality trade-off explicitly, and the
conclusion delivers the operational position: *trust boundaries
are architectural objects; the silicon beneath them does not
implement boundaries, only a shared microarchitectural fabric on
which the boundaries are an interpretation.* Cluster companion
to Mathematical-Collapse (theory), Silicon-Adversary (horizontal
map), and Speculation-Barrier-Illusion (laser instance) — together
the four read as theory → horizontal map → vertical map → instance.

---

## Confidential-VM-Writeup — The Confidential Computing Promise: Where SEV-SNP, TDX, and CCA Break

A structural survey of where AMD SEV-SNP, Intel TDX, and ARM CCA
fail to project their marketed isolation contract onto the shared
microarchitectural substrate. Reads each architecture's
components — memory encryption engine, the Platform Security
Processor / TD Module / Realm Management Monitor, the attestation
key hierarchies (VEK, TDX Quote, RAK) — and locates the published
attack literature (CacheWarp, StackWarp, WeSee, Heckler, HyperPill,
HyperHammer) at the specific substrate layer it breaches: cache,
register snapshot, interrupt injection, DRAM read-disturbance, or
firmware. The contribution extends Microarch-Isolation's TEE
chapter into the Confidential Computing era, naming the assumption
invalidated at each layer. The piece is intended for any deployment
or audit that treats CC as a confidentiality guarantee against the
cloud operator without enumerating the microarchitectural
sub-surfaces the contract does not cover.

---

## Interrupt-Injection-CC-Writeup — Interrupt Injection Across Confidential VM Boundaries: Heckler and WeSee

A focused case study of two 2024 attacks against AMD SEV-SNP and
Intel TDX — Heckler (Schlüter et al., USENIX Security 2024) and
WeSee (Schlüter et al., USENIX Security 2024) — both demonstrating
that Confidential VMs cannot refuse arbitrary interrupts from the
host hypervisor, even after the guest's memory and registers have
been encrypted and the attestation chain has measured the boot. The
contribution is the structural reading: the contract holds for
state confidentiality, but the *control-flow* surface (interrupt
vector, error code, GHCB fields) remained hypervisor-controlled by
architectural design. The piece names the specific architectural
fields (`EVENTINJ`, `#VC` error code, GHCB control fields) where
the gap lives, and pairs as a laser-instance case study to
Microarch-Isolation's broader trust-boundary read and Confidential-VM
Writeup's wider survey.

---

## GPU-Side-Channel-AI-Writeup — Amplified Leakage: How GPU Overclocking Widens the Side-Channel Surface for AI Workloads

A cross-cluster bridge between the portfolio's microarchitectural-
security pieces (Silicon-Adversary, Microarch-Isolation,
Speculation-Barrier-Illusion) and its AI-systems pieces
(ACMM-Writeup). Frames GPU overclocking as a *multiplicative
amplifier* on every GPU side-channel the literature already names —
DVFS-as-timing (the GPU analogue of Hertzbleed), cache contention
(Naghibijouybari et al., CCS 2018), electromagnetic weight
extraction (BarraCUDA), prompt extraction from LLM inference servers
(InputSnatch) — with AI inference workloads as the ideal carrier
wave because their data paths are large, regular, and
timing-instrumented for QoS. The piece argues the GPU side-channel
surface has been under-instrumented relative to its CPU equivalent,
lists six measurement gaps as open research questions, and positions
the AI-systems sub-surface (model extraction, training-data
membership inference, prompt reconstruction) as the part of the
surface most newly exposed.

---

## ETW-Mirage-Writeup — When .NET Telemetry Is Repurposed as a Security Boundary

A defensive writeup auditing the trust boundary of Event Tracing
for Windows (ETW) as it is used by EDR and SIEM platforms to
monitor .NET runtime activity. The thesis: ETW was specified as
a debugging primitive in Windows 2000 and has been repurposed by
the security industry as a behavior-monitoring channel, but its
trust boundary lies inside the monitored process — exactly where
no security boundary can sit. The writeup walks the CLR's ETW
registration path through `clr.dll`, locates the two structural
bypasses (`COMPlus_ETWEnabled=0` at configuration time and inline
patching of `ntdll!EtwEventWrite` at runtime), surveys the four
detection vectors (environment monitoring, memory-integrity
scanning, statistical anomaly detection, kernel-callback
validation) and shows each one's structural failure mode, and
generalizes the category — AMSI and user-mode API hooks live in
the same architectural class. The contribution is the
trust-boundary framing that makes the known bypasses structurally
legible, allowing blue teams to allocate detection budget against
the *category* rather than each individual instance.

---

## Speculation-Barrier-Illusion-Writeup — A Category Error at the ISA/Microarchitecture Boundary

A focused case study showing that the sentence "`lfence` stops
speculative execution" equivocates between two ontologically
distinct objects — ISA-level speculation (transient deviations
from program order, modelable by SMT solvers) and microarchitectural
speculation (cache fills, predictor updates, TLB residue that
persist physically). The writeup runs a textbook-clean C snippet
through CBMC's bounded model checker, demonstrates that the
post-barrier safety property is genuinely verified under the
ISA-level model (`VERIFICATION SUCCESSFUL`), and shows that
reading this proof as a microarchitectural guarantee is a
**category error** in Ryle's sense — not a technical mistake but
a confusion of domains. Spectre is reframed not as a missed bug
but as a phenomenon that has never been inside the formal model's
domain. The complement to Mathematical Collapse: where that paper
gives the general theory across six abstractions, this one gives
the concrete reproducible CBMC instantiation of one of them.

---

## BFS2019-Master-Writeup — BFS 2019 Master Exploitation: A Full Chain on eko2019.exe

A long-form CTF writeup re-reading the Blue Frost Security 2019
*eko2019.exe* challenge as a structural exercise rather than as a
checklist. The chain — signed-integer / 16-bit `movzx` type
confusion in the protocol's size-check, dynamic gadget-dispatcher
hijack instead of return-address overwrite, TEB / PEB / ImageBase
leak via a deliberately-planted `gs:`-prefixed gadget,
stack-cookie recovery via memory-scan + XOR, a COP-shaped ROP
chain reaching `WinExec("calc")`, and process continuation so the
service keeps accepting connections after the exploit — is
documented elsewhere. The contribution is the reading discipline.
Each stage of the chain is shown to be the inverse of a specific
design property of the target binary: the author of `eko2019.exe`
wrote the gadget dispatcher, the GS-prefixed leak primitive, the
COP gadget, the stack layout, and the cookie XOR key into the
image, and the exploit is the systematic mining of those choices.
The piece closes by extracting that reading discipline into the
methodological posture that the rest of the portfolio applies.

---

## BitLocker-Anatomy-Writeup — Anatomy of the BitLocker Stack: Kernel Driver, TPM Measurement, and the Encrypted Disk

A composite anatomical reading of Microsoft BitLocker as a four-layer
trust composition: the `fvevol.sys` NTFS volume-filter driver
intercepting sector I/O, the boot-time measurement chain
(boot ROM → bootmgr → winload → BitLocker key release), the TPM
seal/unseal flow over PCR-bound state, and the AES-XTS sector-level
cipher. Assembles the Microsoft documentation, Geoff Chappell's
IOCTL notes, Wong's 2021 LPC bus TPM sniffing demonstration,
Halderman et al.'s 2008 cold-boot result, and Sparks's 2006 TPM
Reset Attack into a single structural picture. The contribution
is the boundary-versus-mental-model contrast: a user who relies on
BitLocker for at-rest confidentiality is depending on the *full*
composition, but the published attack surface lives in the gaps
*between* the layers — key in DRAM, key over LPC, key in dump
capture, recovery key in Active Directory escrow. Pairs naturally
with the Microarch-Isolation TPM/TEE section and with the BFS 2019
piece as another Windows kernel internals reading.

---

## Qualcomm-Kgsl-SignExt-Writeup — The Alignment Collapse: Sign Extension and Invariant Breakdown in the Qualcomm kgsl Driver (CVE-2026-21385)

An anatomical writeup of a CISA KEV-listed integer overflow
(CVE-2026-21385, CVSS 7.8, actively exploited) in Qualcomm's
`kgsl` kernel graphics driver affecting 235+ chipsets. A
userland-controlled `alignment` parameter is processed under a
signed integer context, sign-extending `0xFFFFFFFF` to `-1`;
the `align_up` computation collapses from `≥ requested_size`
to `1`, the allocator succeeds silently, and the subsequent
write overflows into adjacent kernel memory. The writeup traces
the failure as *distributed wrongness* — the error is introduced
at the type-cast layer (K1), propagated silently through two
individually-correct layers (K2, K3), and manifests at the write
layer (K4) with no architectural signal between introduction and
symptom. The structural contribution is the formal framing:
`align_up`'s postcondition holds universally on `ℤ⁺` but not
on `ℤ`; the fix is domain narrowing by precondition at the
trust boundary, not hardening of the function body. Includes
analysis of why compiler, static analyser, and runtime tooling
each miss the bug for distinct structural reasons, and places
the CVE in a documented four-entry Qualcomm recurrence pattern
spanning 2019–2026.

---

## DMA-IOMMU-Writeup — Physical Memory as the Ground Truth

Process isolation is the foundational guarantee of every modern operating system — but it is a guarantee scoped to CPU instruction execution, not to hardware memory access. This writeup examines the IOMMU as the mechanism that extends isolation to the DMA path, and what happens in its absence. A kernel driver is built that calls `MmMapIoSpace()` with the physical address of LSASS's EPROCESS structure — an address derived from a CR3/page-table walk — and reads the structure's raw bytes directly from DRAM, bypassing every OS access-control layer. The contribution is the formal argument: on an IOMMU-disabled system, physical RAM is a flat, permission-free address space, and every isolation invariant stated above the hardware bus layer simply does not apply there.

---

## Double-Fetch-Race-Writeup — The Promise That Expires

Kernel security validation rests on an implicit assumption: if a value passes a check, it stays checked. This writeup dismantles that assumption. A double-fetch race condition arises when a kernel handler reads a user-mode value twice — once for validation and once for use — with no lock or copy between the reads. On modern multi-core hardware, an attacker thread on a parallel core can flip the value between the two fetches, making the check a lie. The writeup quantifies this: win rates scale from ~1/110s on single-core to ~10 million per second on six physical cores, driven by cache-disable and page-boundary amplification techniques that stretch the 2-cycle window to 2400 cycles. CVE-2013-1254 (27 win32k.sys handlers) and CVE-2013-1278 (write-what-where to HalDispatchTable) demonstrate the read and write primitive cases. Bochspwn's instrumentation methodology — full-system emulation with per-thread memory access logging — shows how 50+ CVEs were discovered from one pattern-detection pass.

---

## EPT-Hypervisor-Hook-Writeup — Ring -1 Memory Control

The OS is not the lowest privilege layer in a virtualized system. Intel VT-x introduces hypervisor mode (Ring -1), which controls Extended Page Tables — the second-level address translation mapping guest physical addresses to host physical addresses. This writeup implements an EPT-based hook from first principles: VMXON initialization, VMCS construction with full guest and host state, 4-level EPT table with identity mapping, EPTP encoding, and a VM-Exit handler that captures execution attempts on target pages by clearing their EPT Execute bit. When a hooked page is executed, an EPT violation VM-Exit fires, the handler reads GUEST_RIP, overwrites it with shellcode, and resumes the guest — which never observes a modification to its own page tables, SSDT, or inline code. A syscall argument logger demonstrates the interception: RAX (syscall number), RCX/RDX/R8/R9 (arguments) logged to shared memory on every hooked syscall invocation, invisible to PatchGuard and all Ring 0 integrity mechanisms.

---

## GDI-Bitmap-Abuse-Writeup — The API That Trusts Its Own State

Windows GDI bitmaps are kernel objects. Every `CreateBitmap` call allocates a `SURFOBJ` structure in the kernel heap, and the `SURFOBJ.pvScan0` field is a raw pointer to the bitmap's pixel data. `SetBitmapBits` and `GetBitmapBits` read and write through this pointer without validating that it still lies within the bitmap's legitimate allocation. If `pvScan0` is overwritten — via any prior kernel write primitive — both APIs become arbitrary kernel read/write. This writeup implements the Manager/Worker two-bitmap pattern: the Manager's `pvScan0` is redirected to point at the Worker's `pvScan0` field, turning the Manager into a "pointer controller." From there, arbitrary kernel addresses are read and written through one level of indirection using public GDI APIs. The chain terminates in a token steal: SYSTEM EPROCESS Token copied to the current process, SYSTEM shell spawned. Includes full IDA x86 disassembly of the compiled PoC, the PEB → GdiSharedHandleTable → GDI_CELL → SURFOBJ navigation chain, and a mitigation history covering the RS1 pool isolation patch that forced the transition to RS2 Necromancy.

---

## RS2-Bitmap-Necromancy-Writeup — Grave Robbery: UAF Heap Reuse and Desktop Heap

Windows 10 RS2 patched GDI Bitmap Abuse by bounds-checking `pvScan0` against the desktop heap range. RS2 Necromancy satisfies that check by maneuvering heap layout so that a newly-allocated bitmap's `pvScan0` lands inside the desktop heap — at an address the attacker already controls. The mechanism is UAF through session pool slot reuse: create a window with a large `lpszMenuName` buffer (0x8F0 bytes) to claim a predictable pool slot; leak the kernel address of that allocation via `ulClientDelta = kernel_heap_base − user_heap_base` (readable from TEB + 0x828 without any vulnerability); repeat create/destroy cycles until the kernel reuses the same slot address twice consecutively; destroy the window and immediately allocate a same-sized bitmap; the bitmap's `SURFOBJ.pvScan0` lands at `freed_lpszMenuName_base + 0x50`, within the desktop heap range, bypassing the RS2 patch. Two leak paths are demonstrated: TEB traversal and runtime `user32!HmValidateHandle` recovery via `IsMenu()` bytescan for opcode `0xE8`.

---

## CrackArmor-AppArmor-LPE-Writeup — Confused Deputy to Kernel LPE

AppArmor's policy management pseudo-files (`/sys/kernel/security/apparmor/{.load,.replace,.remove}`) carry mode 0666 — any user can call `open()`. The kernel's write-time authorization check queries `current->cred` (the writing process), not the fd's open credential. By duplicating the fd onto stdout and invoking `su -P` (PTY mode), an unprivileged user routes a root-context `write()` through their fd — the fd crosses the privilege boundary, the CAP_MAC_ADMIN check passes, and the attacker can load, replace, or remove any AppArmor profile. This confused deputy primitive (CVE-2026-23268, one of four historical recurrences in Linux pseudo-file interfaces since 2012) unlocks four attack branches: immediate DoS (rsyslogd unconfined, sshd deny-all), user-space LPE (deny CAP_SETUID to sudo → fail-open error path → sendmail as root → MAIL_CONFIG=/tmp/postfix → attacker postdrop as uid=0), and kernel-space exploitation (CVE-2026-23406: match_char() double-evaluation → 64KB OOB kernel heap read → KASLR bypass; CVE-2026-23410/411: rawdata UAF → PTE spray into freed slab → physical /etc/passwd overwrite → root shell). Nine CVEs, eleven patches, 12.6M+ affected systems. The fix is one line: `ns_capable` → `file_ns_capable(f, ...)`.

---

## Vsock-UAF-Writeup — CVE-2025-21756: Refcount Underflow at the VM Trust Boundary

`AF_VSOCK` — Linux's mechanism for VM guest-to-host socket communication — assigns each `vsock_sock` a refcount of 2 at creation: one held by the `struct socket` owner, one by the global `vsock_bind_table`. CVE-2025-21756 breaks the invariant that each reference source decrements exactly once. `vsock_remove_sock()` unconditionally calls `vsock_remove_bound()`, and `sock_orphan()` (which sets `SOCK_DEAD`) runs after `transport->release()` instead of before it. Two consecutive failed `connect()` calls to different CIDs trigger `vsock_remove_bound()` twice on the same socket — driving refcount from 2 to 0 — while the object remains linked in the bind table as a dangling pointer. The exploit builds on three careful observations: `vsock_diag_dump()` traverses the bind table without LSM hooks (bypassing AppArmor's null `sk_security` obstacle), which makes it a side-channel oracle for brute-forcing `init_net`'s address and leaking the kernel base; `vsock_release()` is also LSM-unprotected, making it the RIP-control delivery path via `sk->sk_error_report` overwrite and a stack pivot gadget; and `commit_creds(&init_cred)` (direct, not via `prepare_kernel_cred(NULL)` which crashes on modern kernels) converts kernel base knowledge into uid=0. The write also examines the VM trust boundary implications: guest LPE enables `/dev/kvm` ioctl access and expanded lateral movement in multi-tenant cloud deployments.

---

## CLFS-ZeroDay-Writeup — CVE-2022-37969: The Integrity Loop That Poisoned Itself

Windows CLFS (`CLFS.sys`) uses a six-block Base Log File format with a 512KB Base Block whose header carries a `SignaturesOffset` field at offset `0x6C`. The `ClfsEncodeBlockPrivate()` function — responsible for writing sector integrity signatures — iterates every sector and stores each 2-byte signature at `0x50 + (sector_index × 2)`. For sector index 14: `0x50 + 0x1C = 0x6C` — the `SignaturesOffset` field itself. An attacker maps the BLF file into user space and patches sector 14's signature to `0xFFFF`; when `FlushMetaData()` triggers the encode loop, the loop overwrites `SignaturesOffset` with `0xFFFF0050`. This corrupted value bypasses the bounds check in `AllocateSymbol()`, which computes available symbol zone space relative to `SignaturesOffset` — now garbage — and accepts an oversized `cbSymbolZone`, producing an out-of-bounds kernel pool write that corrupts a `CClfsContainer*` pointer. Dereferencing the corrupted pointer yields arbitrary kernel write capability, converted to SYSTEM via token-pointer overwrite in `EPROCESS`. The root cause isn't a missing check — it's an implicit aliasing assumption in the data layout that nobody validated: the sector index arithmetic was never audited against the fields it could silently overwrite.

---

## CET-COOP-Bypass-Writeup — Weaponizing CET's Trust Model Against Itself

Intel's Control-flow Enforcement Technology (CET) kills classical ROP and JOP by enforcing that every indirect branch lands on an `ENDBR64`-marked entry point (IBT) and that every `ret` matches a shadow-stack copy (Shadow Stack). Counterfeit Object-Oriented Programming exploits the gap between CET's enforcement granularity (single indirect branches) and the semantic level at which real attacks operate (sequences of function calls). By corrupting a C++ object's vtable pointer to aim at a counterfeit vtable — one populated with addresses of legitimate, ENDBR64-marked function entry points — COOP assembles a Looper/ArgLoaders/Invoker/Collector chain that CET considers indistinguishable from normal virtual dispatch. The WinDbg trace from the PoC shows `ntdll!LdrpDispatchUserCallTarget` — Windows' own CET enforcement trampoline — executing the final `jmp rax` to `WinExec("calc.exe")`; the mitigation itself delivers the payload. The writeup extends beyond the WinExec demo to a full file-I/O exfiltration chain (CreateFileA → ReadFile → WriteFile over a socket) and an 8-stage implant lifecycle (anti-debug, process enumeration, memory allocation, file ops, process injection, payload execution, cleanup, registry persistence) assembled entirely from CET-compliant Windows API calls.

---

## PatchGuard-Hypervisor-Bypass-Writeup — Ring -1 Owns the Checker

PatchGuard enforces Windows kernel integrity from Ring 0 — the same
privilege level it is protecting — which means any attacker who
reaches Ring -1 (Intel VMX root) can control what PatchGuard
observes. This writeup develops three bypass planes in order of
sophistication: EPT Shadowing maintains two physical pages behind
the same virtual address and switches between them on `CR3` match,
so PatchGuard's dump sees the clean page while execution continues
on the hooked one; DPC Timer Trap Injection intercepts
`EXIT_REASON_EXTERNAL_INTERRUPT (0x1F)` from the hardware timer,
identifies PatchGuard's DPC routine by RIP range, and redirects
guest execution to a fake NTOSKRNL-check shellcode that returns
success without inspecting anything; and a five-level VTL Trap
Chain uses a CPUID-signature VMExit to inject shellcode into VTL0,
overwrite an IDT entry, and gain interrupt-context execution.
The writeup also analyzes `SecureKernel.exe` internals — `ShvlVinaHandler`,
`_tlgKeywordOn` (keyword mask `0x400000000000`), `SkEtwWriteTransfer`,
`SkpgAmd64WriteRegister64` — to characterize the VBS/KDP upper
bound that moves the trust anchor above the hypervisor.

---

## VMExit-API-Unhook-Writeup — Ephemeral Unhooking at Hypervisor Speed

EDR products hook `ntdll` syscall stubs to intercept API calls
before the kernel transition. Every static counter-technique leaves
a forensic artifact: a second ntdll mapping, an anomalous syscall
number path, or a reflective-loader trace in the PEB. This writeup
implements a hypervisor-level alternative with no static artifact:
the monitored stub pages are marked EPT write-protected, so the
EDR's hook write causes a VMExit, the hypervisor restores the
original bytes, re-protects the page, and resumes the guest. The
unhook exists only during the VMExit window — shorter than any
polling interval. The system monitors three stubs
(`NtOpenProcess`, `NtReadVirtualMemory`, `NtWriteVirtualMemory`)
with per-stub gold copies and `restore_count` telemetry, classifies
hook type (`JMP`, `INT3`, `SYSCALL overwrite`, `INT 2E`), attributes
each event to a process via `CR3`→PID resolution, and writes
`before.bin`/`after.bin` forensic dumps. The blue-team section
develops an endpoint agent doing SHA-256 in-memory vs. on-disk hash
comparison, with SIEM correlation against VMExit rate and syscall
latency to achieve high-fidelity detection of exactly this
ephemeral-patch pattern.

---

## io-uring-UAF-Writeup — CVE-2022-29582: Two Paths, One Free, One Object

`io_uring`'s linked-timeout mechanism couples a target operation
`T` with a link-timeout `LT` that cancels it if the deadline
passes. The kernel defines two legitimate completion paths: the
flush path (T finishes first) and the timer path (LT's hrtimer
fires first). CVE-2022-29582 is the case where both fire
concurrently. Both paths call `io_put_req_deferred(LT, 1)`,
both see a refcount transition to zero, and both schedule a free.
SLUB immediately reuses the freed slot; the flush path's
subsequent dereference of `T->link_list` now touches the
replacement object. The writeup traces the race at microsecond
granularity (`t0`/`t0+ε`/`t1`/`t1+ε`), annotates the kernel
source (`io_kill_timeout()`, `io_link_timeout_fn()`,
`io_put_req_deferred()`) at the lines where the invariant
"unlink before drop before free" is violated, and walks the
exploitation chain: heap feng-shui to occupy the freed slot,
refcount corruption, function-pointer hijack via `f_op.release`,
and `commit_creds(prepare_kernel_cred(0))` to root — without
any user namespace requirement, making it practical for container
escape. The fix in kernel 5.17.3 is one line moved.

---

## How to use this file

- **Application essays:** lift the relevant paragraph verbatim;
  each is sized for a "selected projects" bullet.
- **Repository descriptions:** copy the first 2 sentences of a
  pitch into the GitHub repo's `Description` field (the box that
  appears next to the repo title).
- **CV / portfolio site:** the paragraphs are intentionally
  uniform in shape, so a list of all thirty-nine reads as one
  coherent collection rather than thirty-nine disjoint blurbs.
- **Cover letters:** combine the **Portfolio overview** with two
  hand-picked pitches that match the role.
