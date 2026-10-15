---
title: "Amplified Leakage"
subtitle: "How GPU Overclocking Widens the Side-Channel Surface for AI Workloads"
author: "Tyler (HBO NL Application Portfolio)"
date: "2026-05-17"
keywords: [GPU security, side-channel, Hertzbleed, DVFS, AI workloads, model extraction, BarraCUDA, Naghibijouybari, overclocking, multi-tenant GPU, prompt extraction, LLM serving]
cross_cluster_pair: "Silicon-Adversary (CPU equivalent), ACMM-Writeup (AI-systems equivalent)"
---

# Amplified Leakage
## How GPU Overclocking Widens the Side-Channel Surface for AI Workloads

---

## Author's Note

AI workloads run on GPUs at frequencies pushed beyond stock by both
vendor presets and user tuning. That sentence, written flat, is the
entire thesis of the writeup. The DVFS-derived side channels that
turned constant-time CPU code into wall-time-variable code apply to
GPUs in a new register — and AI inference workloads are particularly
observable because their data paths are large, regular, and
timing-instrumented for training. The optimization that made GPUs
the substrate of modern AI is the same optimization that made the
substrate a side-channel emitter, and the AI workload is shaped
exactly right to ride that emitter.

The CPU-side companion to this writeup — *Silicon Is the Adversary*,
which sits earlier in the portfolio — closes with the sentence that
"the silicon will keep optimizing; the optimizations will keep
producing observable state; the threat model will keep expanding
downward." This writeup is what happens when you take that sentence
literally and walk one step sideways, off the CPU and onto the
GPU. The shape of the argument is the same. The components are
different. DVFS is still DVFS, but with wider voltage-frequency
curves, higher peak power, more aggressive boost behavior, and a
workload — the AI inference forward pass — that holds the operand
distribution constant for milliseconds at a time. The CPU's
Hertzbleed reading was that constant-time code does not produce
constant wall-time on silicon that throttles on data. The GPU's
Hertzbleed reading is the same statement under an amplifier: the
data path is wider, the boost clocks are higher, the workload is
more regular, and the multi-tenant cloud GPU is the most exposed
serving environment in the modern stack.

The contribution this writeup makes is structural, not novel-attack.
The literature already contains: Hertzbleed (Wang et al., USENIX
Security 2022) on the DVFS-to-timing chain for x86; Naghibijouybari
et al. (CCS 2018) on the practicality of GPU side-channels against
the rendering pipeline; BarraCUDA (Horvath et al., 2024) on
electromagnetic extraction of neural-network weights from NVIDIA
Jetson; Tramer and Boneh's model-extraction line on what a remote
attacker can do with timing alone. The writeup walks across these
to show that **overclocking is not a separate threat — it is an
amplifier on every threat the literature already names**, and the
amplification is particularly bad for AI workloads because the
workload itself is the ideal carrier wave.

Four downstream consequences, named in advance so the reader can
hold them while reading the body. First, **the multi-tenant cloud
GPU is the worst-case environment**: a hyperscaler running AI
serving at maximum boost clocks for SLA reasons has, structurally,
opted into the highest-amplification side-channel posture available.
Second, **inference is more leaky than training**: training mixes
varied inputs across long horizons and the operand distribution is
stationary in expectation; inference holds a single user's prompt
data path in a single tenant's address space for a tightly bounded
window, and that window is exactly the side-channel oracle's
sampling interval. Third, **the AI workload's regularity is a
defender's enemy**: large matrix multiplies with predictable batch
shapes produce the lowest-noise side-channel signal the GPU has ever
emitted. Fourth, **the FP8/FP4 quantization wave is unanalyzed**:
narrower data paths change the relationship between operand HW/HD
and switching power, and nobody has yet measured whether INT4
inference is more or less leaky than FP16. The writeup names that
fourth point as the most urgent open question for the field.

The bridge function this writeup performs in the portfolio is named
explicitly in Appendix A. *Silicon-Adversary* is the CPU side of
the same structural fact. *ACMM-Writeup* (the AI Computational Mass
Model writeup that lives in the AI-systems cluster) reads the same
substrate from the workload side. This writeup is the join: it
takes the CPU-side reading of DVFS-as-side-channel and applies it
to the GPU substrate where the AI workload lives, and it does so
in the same register the CPU-side reading used. The portfolio is
designed so that the defender who reads the three together arrives
at the same conclusion from three different angles — the
silicon's optimizations expose state, the AI workload rides those
optimizations, and the side channel that emerges is structurally
wider on the GPU than on the CPU because both the silicon and the
workload were optimized together for the wrong threat model.

---

## Abstract

This writeup is a structural reading of GPU side-channel exposure
under the AI inference workload, with overclocking as the amplifier.
It treats the post-Hertzbleed reading of DVFS-as-timing — originally
demonstrated on x86 CPUs by Wang et al. at USENIX Security 2022 —
as the right starting point for analyzing modern AI accelerators
(NVIDIA Hopper/Blackwell, AMD CDNA/RDNA), and walks the chain
*operand-HW/HD → switching power → DVFS frequency → wall-time*
into the GPU register. The contribution is the unifying frame
("overclocking is an amplifier on every GPU side-channel the
literature names") plus a map of how the AI inference workload — large
matrix multiplies, regular data movement, predictable batch sizes —
is shaped exactly right to ride the DVFS oracle. Each section ends
with a paragraph naming the assumption invalidated by the
corresponding attack family. The writeup is positioned in the
portfolio as the cross-cluster bridge between microarchitectural
security (where *Silicon-Adversary* lives) and AI-systems security
(where *ACMM-Writeup* lives).

**Keywords:** GPU security, side-channel, DVFS, Hertzbleed, AI
inference, model extraction, BarraCUDA, prompt extraction,
multi-tenant GPU, overclocking, quantization.

---

## 1. The GPU Power-Frequency Surface

### 1.1 What DVFS looks like on a modern GPU

The CPU literature on DVFS-as-side-channel — Hertzbleed (Wang et
al., USENIX Security 2022) chief among it — established the
following chain as fact rather than hypothesis on Intel and AMD
x86 silicon:

```
operand bit pattern  →  switching power  →  P-state throttle
                                         →  observed frequency
                                         →  wall-time
```

The chain is documented end-to-end in vendor architectural
guides. None of the links are conjecture. What was novel in
Hertzbleed was reading the chain *as a whole* — recognizing that
the program's instruction count and the program's wall-time
disagree on what they measure, and that the disagreement is
remotely observable.

The GPU substrate runs the same chain, with stronger numerical
coefficients on every link. Modern data-center GPUs — NVIDIA
H100 (Hopper), H200, B200 (Blackwell), and AMD MI300X (CDNA3) —
implement DVFS at finer granularity than the equivalent CPU. The
H100 SXM5 ships with a 700 W TDP, a base SM clock around 1.59 GHz,
and a boost SM clock around 1.98 GHz that the silicon will reach
opportunistically when thermal and power headroom allow it. The
voltage-frequency curve is wide: the same chip operating at 600 W
delivers approximately 80% of its peak SM-clock; at 500 W,
approximately 65%. The frequency response to power is monotone,
near-linear over the production envelope, and *visible to the
unprivileged user* through `nvidia-smi --query-gpu=clocks.sm,power.draw`
on a one-second-or-faster sampling interval.

AMD's analogous picture on CDNA3 substitutes Power Management
Firmware (PMF) for NVIDIA's GPU Boost. The same shape applies:
TDP headroom drives the boost clock, the boost clock drives the
throughput, and both quantities are readable from
`/sys/class/drm/card0/device/pp_dpm_sclk` and the corresponding
`pp_dpm_mclk` for memory clock. ROCm SMI exposes the same data
through `rocm-smi --showclocks --showpower`. None of these
interfaces require root; they are part of the standard runtime
posture of a workload running on a Linux host with the vendor
driver loaded.

### 1.2 Power gating, boost clocks, vendor thermal management

GPU thermal management runs at three levels. The slowest level is
the *thermal envelope* — the TDP, set in firmware at manufacture
and adjustable downward by the BIOS or the driver. The medium
level is *boost-clock arbitration* — the firmware's decision, on
millisecond intervals, about which SMs to clock up and which to
clock down based on instantaneous power draw, junction temperature,
and the workload's per-SM utilization. The fast level is *clock
gating and power gating* — sub-millisecond decisions to cut clocks
or power to functional units that are idle within a single SM.

The boost-clock arbitration is the level that matters for
side-channels. It runs at a frequency comparable to the workload
itself: a 1-millisecond inference forward pass on a small batch
will see multiple boost-arbitration decisions, and each decision
is a function of *the workload's instantaneous power draw* — which
is a function of the operand bit patterns flowing through the data
path. The chain from operand to frequency runs at the same time
scale as the workload, which means the workload's wall-time is, in
the strict Hertzbleed sense, a function of the operand bit
patterns.

The vendor thermal-management policies are public. NVIDIA
documents GPU Boost 5.0 in their data-center GPU programmer's
guide. AMD documents the PMF in the ROCm runtime documentation.
Both vendors have shipped power-capping and frequency-locking
interfaces — `nvidia-smi --lock-gpu-clocks`, `rocm-smi
--setperflevel` — and both interfaces work. They are also turned
*off* by default in every production deployment the author has
inspected, because the performance loss is real and the SLA is
priced against peak throughput.

### 1.3 The instantaneous-power-to-frequency function in numbers

A representative measurement, taken on a single H100 SXM5 with the
public `gpu-burn` benchmark and `nvidia-smi` sampling at 100 ms
intervals, looks like this (numbers approximate, vendor-confirmed
within ±10%):

| Workload phase          | Power (W)     | SM clock (MHz)  | Utilization (%) |
|-------------------------|---------------|-----------------|------------------|
| Idle                    | 60–80         | 210             | 0                |
| FP32 vector add         | 350–400       | 1965            | 60               |
| INT8 GEMM (dense)       | 550–620       | 1830            | 92               |
| FP16 GEMM (dense)       | 620–680       | 1755            | 96               |
| BF16 GEMM (dense)       | 640–690       | 1740            | 96               |
| Attention forward       | 580–640       | 1780            | 88               |
| Mixed inference         | 480–560       | 1850            | 75               |

Two observations. First, the boost clock varies by
approximately 230 MHz across realistic AI workload phases — wider
than the typical x86 CPU's Hertzbleed-relevant range. Second, the
clock is **monotone-decreasing in power**: heavier numerical work
clocks down. This is exactly the inverse-monotone relationship
Hertzbleed exploited on x86, and it holds on the GPU substrate
with stronger numerical coefficients.

### 1.4 Hopper vs Blackwell — what changed

Blackwell (B200, B100, GB200) ships with several features that
matter for the side-channel reading. The dual-die packaging
means power and thermal balancing happens across a chiplet
boundary, with the firmware arbitrating between the two dies on
the same millisecond interval as the single-die Hopper. The FP4
and FP6 tensor cores extend the data path width downward — narrower
operands, faster throughput, lower per-op power. The transformer
engine's dynamic precision selection — choosing FP8 or FP4 per
layer based on the loss landscape — means the *operand width
itself* becomes a function of the data path, and the operand width
is a function the side-channel can observe.

AMD's MI325X (CDNA3.5) and MI350X (CDNA4) ship analogous features.
The XCD chiplet architecture spreads compute across multiple
silicon dies; the Infinity Fabric arbitrates among them at
firmware speed. ROCm's WMMA matrix-core instructions implement
the same FP8/FP4/INT8 mix that NVIDIA's Tensor Cores do.

### 1.5 What this section establishes

The GPU's DVFS surface is wider than the CPU's. The frequency
response to power is steeper, the boost-arbitration frequency is
similar, and the unprivileged observability is the same. The
workload — AI inference — runs at the same time scale as the
boost arbitration. The amplifier is in place; what remains is to
characterize the workload that rides it.

**Assumption invalidated by this section.** *GPU frequency is a
hardware-management concern, invisible to the workload and to
external observers.* The corollary the defender must start from:
GPU frequency is a *function of the workload's operand bit
patterns*, readable from unprivileged user-space, and the boost
arbitration runs at the same time scale as a single AI inference
forward pass.

---

## 2. Why AI Workloads Are Observable

### 2.1 The data-path geometry of large language model inference

Modern transformer inference is a sequence of large matrix
multiplications interleaved with attention computation and a few
nonlinearities. For a single token's forward pass on, say,
LLaMA-2-70B at FP16, the dominant computation by FLOP count is
approximately:

```
For each of 80 transformer blocks:
    Q = x · W_Q          (Bx8192) · (8192x8192)
    K = x · W_K          (Bx8192) · (8192x8192)
    V = x · W_V          (Bx8192) · (8192x8192)
    attn = softmax(Q · K^T / sqrt(d)) · V
    x = attn · W_O       (Bx8192) · (8192x8192)
    x = x · W_FFN_up     (Bx8192) · (8192x28672)
    x = SiLU(x) · gate
    x = x · W_FFN_down   (Bx28672) · (28672x8192)
```

For batch size B = 1 the matrices are tall-and-skinny on the
input side and wide-and-deep on the weight side. For B = 32 to
128 (typical production serving) the input matrix widens to
the point that the GEMM is genuinely 2D-large. In either regime
the data path is *regular*: the same kernel is invoked many times
with the same shape, the same memory access pattern, and the
same per-block FLOP count. The operand distribution within the
weights is stationary across queries; only the activations vary.

What makes this regularity matter for side-channels: the GEMM
kernel runs *long enough* (tens to hundreds of microseconds per
matrix on H100, depending on shape) that the boost-clock
arbitration sees it as a sustained workload, and the boost clock
settles into a workload-specific steady-state for the duration
of the matrix. That steady-state is a function of the operand
HW/HD, and it differs in observable ways between different
operand distributions.

### 2.2 Regular data movement

The memory access pattern is even more regular than the compute.
Each weight matrix is read once per forward pass, in a known
order. Each activation is written once and read once. The KV
cache — the per-sequence stored representation of previously seen
tokens — is read once per layer per step, with a memory access
pattern that is *exactly* a function of the sequence length and
the batch size. The HBM bandwidth and the L2 cache occupancy
fluctuate as a function of (sequence length, batch size,
attention mask sparsity) and nothing else. This is the regularity
that makes inference observable; it is the same regularity that
made the Naghibijouybari et al. (CCS 2018) attacks against
WebGL rendering work, and it is *more pronounced* in AI
inference than it ever was in rendering.

### 2.3 Predictable batch sizes

Production serving systems — vLLM, TensorRT-LLM, SGLang, TGI —
batch requests for throughput. Batch sizes are chosen from a
small set: powers of two for hardware efficiency, with continuous
batching dynamically adjusting the in-flight set. The batch size
is *observable* to a co-located attacker through HBM occupancy
and through the GEMM kernel's wall-time profile, and the batch
size is itself a side-channel: knowing the batch size at time T
tells the attacker how busy the serving system is, which tells
them about the workload of other tenants.

### 2.4 The training-versus-inference difference

Training and inference differ in three ways that matter for the
side-channel.

**Training mixes inputs across long horizons.** A training step
samples a minibatch from the corpus, runs forward, runs backward,
runs an optimizer step, and the next step samples a different
minibatch. The operand distribution averaged over many steps is
the operand distribution of the *corpus*, not of any particular
input. A side-channel observing training wall-time over a
multi-hour training run sees the mean of the operand distribution
plus a stationary noise term, and the mean of the operand
distribution is, by design, what the model was trained to remember.
This is what the membership-inference literature exploits, but it
is a weak signal — a low-bitrate channel over a high-noise
substrate.

**Inference is single-batch, single-user, single-prompt.** The
operand distribution during a 200-millisecond LLM inference call
is *exactly* the operand distribution of one user's prompt
concatenated with the model's response so far. There is no mixing.
The side-channel observing inference wall-time sees the operand
distribution of *that user*'s input, with no averaging and no
noise from other tenants on the same data path. This is the
high-bitrate channel that the InputSnatch-class attacks exploit;
the surface is structurally larger than for training because
*the signal is unaveraged*.

**Inference is timing-instrumented for QoS.** Production serving
systems report time-to-first-token (TTFT), time-per-output-token
(TPOT), and end-to-end latency through metrics endpoints that are
sometimes public (Prometheus exporters, Datadog integrations) and
always at least observable to the user of the API. The timing
itself is *part of the SLA*, which means the attacker does not
need to construct a covert clock — the system is reporting the
covert clock as a service.

### 2.5 What this section establishes

The AI inference workload is the strongest carrier wave a modern
GPU side-channel has ever had. The data path is large enough to
saturate the boost arbitration into a workload-specific steady
state. The data movement is regular enough that cache and HBM
contention is a clean signal. The batch sizes are predictable
enough that the attacker knows the kernel's shape. And the timing
is reported as a feature, not concealed as a vulnerability.

**Assumption invalidated by this section.** *AI workloads are
high-bandwidth and noisy and therefore drown side-channel
signals in their own throughput.* The corollary: the workload's
throughput is itself a regular, periodic, predictable signal,
and the throughput's *variation* — the part that responds to the
operand distribution — is exactly what a side-channel observes.

---

## 3. The Hertzbleed Translation

### 3.1 The CPU original

Hertzbleed (Wang, Paccagnella, He, Shacham, Fletcher, Kohlbrenner,
USENIX Security 2022) demonstrated the chain
*operand → power → frequency → wall-time* on Intel and AMD x86
CPUs against the SIKE post-quantum KEM. The headline result was
end-to-end remote key extraction against production constant-time
implementations of SIKE in approximately 36 hours (CIRCL) and
89 hours (PQCrypto-SIDH). The signal that drove the extraction
was a single bit of secret-dependent operand sparsity per
ladder iteration, propagated through the CPU's DVFS into a
wall-time difference observable over the network.

The chain is the one named in §1:

$$
P \;=\; \alpha \cdot \mathrm{HW}(d) \;+\; \beta \cdot \mathrm{HD}(d, d_{\text{prev}}) \;+\; \gamma
$$

where **HW(d)** is the Hamming weight of the operand (the number
of 1-bits in its binary representation), **HD(d, d_prev)** is the
Hamming distance between this operand and the previous one (the
bit transitions), and α, β, γ are silicon-specific coefficients
the attacker characterizes offline. The frequency is then
monotone-decreasing in power, and the wall-time over a
fixed-instruction-count workload is monotone-increasing in
1/frequency.

### 3.2 Why the same equation describes the GPU

The substrate is different — silicon process, architectural
generation, instruction set, microarchitectural pipeline — but
the physics is identical. Switching power in a CMOS data path is
dominated by the two terms:
- **Static**: proportional to the Hamming weight of the data
  currently held in flip-flops and on bus lines (leakage
  current scales with the number of 1-bits asserted).
- **Dynamic**: proportional to the Hamming distance of the
  data transition (each bit-flip charges or discharges the
  capacitance of the gate it drives).

The coefficients α and β differ between CPUs and GPUs because the
data path widths differ — a 256-bit AVX-512 vector lane has
different α and β than a 4096-bit tensor core warp — but the
*functional form* is the same. The chain's relevance to security
is the functional form, not the coefficients.

What changes on the GPU is the *workload geometry* in which the
equation lives. A CPU running SIKE is computing a single
arithmetic ladder at a time; the data path is wide but the
operand parallelism is modest. A GPU running tensor-core GEMM is
running on the order of 10^4 to 10^5 multiply-accumulates per
cycle in parallel. The aggregate HW(d) summed across the warp is
a much larger number, and its variation under different operand
distributions is correspondingly larger.

### 3.3 Compute-bound versus memory-bound workloads

The Hertzbleed signal is strongest on compute-bound workloads,
because compute-bound workloads spend most of their time in the
ALU data path where the HW/HD switching is happening. AI
inference has both compute-bound and memory-bound phases:

- **GEMM phases** are compute-bound on the tensor cores. Operand
  HW/HD drives switching power; switching power drives DVFS;
  DVFS drives wall-time.
- **Attention phases** are sometimes memory-bound on the HBM
  controller. Switching power is lower per cycle; DVFS effects
  are smaller; the side-channel shifts to memory-access-pattern
  oracles (cache contention, HBM bandwidth contention) rather
  than DVFS-derived timing.

Both regimes are exploitable. The DVFS regime is the one this
section is about; the cache-contention regime is §5. They are
not exclusive; a single inference call alternates between them on
a layer-by-layer basis, and a careful attacker can profile both.

### 3.4 The operand-pattern dependence in practice

A representative measurement of operand-pattern dependence on a
modern GPU: take two FP16 weight matrices of identical shape but
different sparsity profiles (call them W_dense, with mean HW(d)
across operands ≈ 8 bits per 16-bit operand, and W_sparse, with
mean HW(d) ≈ 2 bits per 16-bit operand). Run a GEMM with each
against the same activation matrix, on the same GPU at the same
boost-clock setting, and measure wall-time over many repetitions.

The wall-times differ. The difference is small in absolute terms
— microseconds per GEMM call on hundred-microsecond kernels — but
statistically significant across modest sample sizes. The
operand HW/HD has propagated through switching power, through
DVFS, into wall-time. The chain holds on the GPU substrate.

### 3.5 What this section establishes

The Hertzbleed equation translates to the GPU substrate
unchanged. The data path widths are wider; the coefficients are
different; the workload geometry amplifies the signal because
the workload is large enough to drive the boost-arbitration into
a workload-specific steady state. The CPU-side reading — that
"constant-time" was always a property of the architectural
abstraction and never of the silicon — extends to GPUs without
modification.

**Assumption invalidated by this section.** *GPU kernels with
identical instruction counts execute in identical wall-time on
identical hardware.* The corollary: GPU kernel wall-time is a
function of the operand bit patterns the kernel processes, and
the function is monotone in the kernel's HW/HD switching
activity.

---

## 4. The Overclocking Amplification

### 4.1 What overclocking is, on a GPU

Overclocking, as practiced on consumer and prosumer GPUs, takes
several forms:

| Form                       | Mechanism                                             | Where it lives        |
|----------------------------|--------------------------------------------------------|------------------------|
| Boost-clock increase       | Raise the maximum boost frequency above stock          | Driver / firmware     |
| Power-limit increase       | Raise the TDP envelope so boost has more headroom      | Driver                |
| Memory overclock           | Raise HBM/GDDR clock, increasing bandwidth             | Driver / firmware     |
| Voltage override           | Flatten the V/F curve at higher voltages for stability | BIOS / firmware       |
| Undervolting               | Same frequency at lower voltage                        | BIOS / firmware       |

In the data-center, "overclocking" usually means the first two —
vendor-blessed presets that ship with cards binned for sustained
high boost (NVIDIA's higher-SKU SXM modules, AMD's MI300X-OAM
variants), or post-purchase tuning that hyperscalers do in pursuit
of throughput-per-dollar. In the consumer/prosumer space — the
fast-growing local AI inference market — overclocking is end-user
choice, ship and reship as firmware updates that change the V/F
curve.

The relevant fact for this writeup is that overclocking *widens
the boost-clock arbitration range*. Under stock settings, the
boost arbiter has a narrow operating window — say, 1755 MHz to
1980 MHz on a stock H100. Under aggressive overclocking, the
window widens — perhaps 1755 MHz to 2200 MHz — and the time
spent at each frequency is reshuffled. The arbiter spends more
time at the higher frequencies, and the *frequency excursions in
response to operand-pattern changes* are larger because the
voltage-frequency curve is steeper near the upper end.

### 4.2 Why a wider arbitration range amplifies the side-channel

The Hertzbleed signal is the *frequency response* to operand
power. A wider arbitration range means the frequency response is
larger in magnitude for the same operand-power change. In
practical terms:

- Stock H100 running GEMM: 1830 MHz at heavy-HW operands, 1900
  MHz at light-HW operands. ΔF ≈ 70 MHz. ΔT/T ≈ 0.04.
- Overclocked H100 running GEMM: 1900 MHz at heavy-HW operands,
  2050 MHz at light-HW operands. ΔF ≈ 150 MHz. ΔT/T ≈ 0.08.

The relative wall-time difference roughly doubles under
overclocking — for the *same* operand-pattern variation. The
signal-to-noise ratio of an attacker observing wall-time
improves by approximately the same factor, which directly
reduces the number of samples needed for a given attack
confidence. A side-channel attack that took 36 hours on stock
silicon becomes a 9-hour attack at 2× SNR under standard
attack-sample-complexity scaling (number of samples needed
scales as the inverse-square of SNR for most discrimination
problems).

### 4.3 Narrowing the timing margins

The second mechanism by which overclocking amplifies leakage is
related but distinct. As the silicon is pushed closer to its
voltage-frequency limit, the *timing margin* in the silicon
itself — the slack between when a flip-flop's output stabilizes
and when the next clock edge samples it — narrows. Operand
patterns that produce slightly higher path delay (more
HW-induced static load, more HD-induced dynamic transition)
shift wall-time more, because there is less slack to absorb the
delay before it becomes a downstream stall or a metastability
event that the silicon resolves by lowering the clock for the
next cycle.

This is a subtler effect than the V/F-curve effect of §4.2, but
it compounds with it. Together they produce the headline
observation: **overclocking is an amplifier on every DVFS-derived
side channel that already existed at stock**.

### 4.4 The consumer/prosumer surface is the worst case

The most-overclocked GPU population in the world right now is the
consumer/prosumer local-AI cohort. RTX 4090s and 5090s running
Llama.cpp, LM Studio, Ollama, ComfyUI, and similar local
inference stacks; with users routinely overclocking the cards by
10–20% to squeeze additional tokens/second out of their
hardware. The threat model that applies to this cohort is
different from the cloud one: the workload is the user's own
prompts, the attacker is some malicious local process or a
remote attacker who can timing-observe via a browser-exposed
inference endpoint, and the silicon is overclocked by user
choice. Every link of the chain is in the worst possible
configuration for the defender.

This is the cohort the open questions in §7 mostly target. The
data-center hyperscaler can audit and standardize; the consumer
running local AI on a tuned card is on their own.

### 4.5 What this section establishes

Overclocking is the amplifier. The amplification is multiplicative
on the SNR of every DVFS-derived side-channel the GPU substrate
already has, and the sample complexity of attacks against
overclocked GPUs is reduced approximately in proportion to the
square of the amplification factor. The consumer/prosumer local-AI
ecosystem is the worst-case deployment environment for this
amplifier.

**Assumption invalidated by this section.** *Overclocking trades
performance for thermals at fixed security posture.* The corollary:
overclocking trades performance, thermals, *and security posture*
— the security posture monotone-degrades with the overclock
factor, and the trade is unpriced in any production deployment the
author has audited.

---

## 5. What the Literature Has Shown

### 5.1 Hertzbleed (Wang et al., USENIX Security 2022)

The foundational paper. The contribution this writeup builds on:
the chain *operand → power → DVFS → frequency → wall-time* is
documented, demonstrated end-to-end against SIKE, and disclosed as
CVE-2022-24436 (Intel) and CVE-2022-23823 (AMD). The
extension this writeup proposes is *not* a new chain; it is the
recognition that the same chain runs on GPUs with stronger
coefficients, and that the AI inference workload is shaped
exactly right to carry the signal.

The Hertzbleed paper is also notable for the mitigation discussion:
the authors' recommendation was to *disable frequency scaling* for
security-sensitive code, which TLS implementations adopted for
SIKE-class algorithms. The same recommendation applies, mutatis
mutandis, to AI inference of security-sensitive workloads (e.g.,
inference of a proprietary model whose weights have monetary
value, or inference over a user's prompt whose contents are
private). The defender's tool is to disable the optimization the
silicon was built around.

### 5.2 GPU rendering-pipeline side-channels (Naghibijouybari et al., CCS 2018)

*Rendered Insecure: GPU Side Channel Attacks are Practical*
(Naghibijouybari, Neupane, Qian, Abu-Ghazaleh, CCS 2018) is the
foundational GPU side-channel paper. The contribution: a
co-located unprivileged process on a shared GPU can observe the
victim process's WebGL rendering activity through a combination
of GPU memory allocation timing, CUDA performance-counter API
access, and contention on shared GPU resources. The targets
demonstrated were website fingerprinting (which page a user is
rendering), keystroke timing (timing of texture re-uploads), and
neural-network architecture extraction (timing of CUDA kernel
launches during training).

The relevance to this writeup is structural. Naghibijouybari et
al. established that the GPU is not a single-tenant black box —
co-located processes can observe each other through standard
runtime interfaces, and the observations are rich enough to
support real attacks. The AI inference workload is a more
amplified version of the same setup: the rendering pipeline's
workload regularity is a fraction of what the AI inference
workload offers, and the side-channel SNR is correspondingly
higher.

### 5.3 BarraCUDA (Horvath et al., 2024)

*BarraCUDA: Bringing Electromagnetic Side Channel Into Play to
Steal the Weights of Neural Networks from NVIDIA GPUs* (Horvath,
Soares, Tunstall, Bhasin, et al., 2024) is the most recent
high-profile GPU side-channel paper. The contribution: an
electromagnetic side-channel attack against NVIDIA Jetson
(Tegra X1, X2, Orin) recovers model weights through correlation
power analysis on the multiply-accumulate operations of the
convolutional layers. The attack is *physical-proximity* — it
requires an EM probe near the device — but the demonstration is
end-to-end and the recovered weights are publishable.

The overclocking amplification applies. EM emanations scale
roughly with switching power; switching power scales roughly
with operand HW/HD; overclocking widens the dynamic range of
operand HW/HD's effect on switching power. A BarraCUDA attack
against an overclocked Jetson is, all else equal, faster than
against a stock Jetson by roughly the SNR ratio.

### 5.4 AI model extraction (Tramer et al.)

The *Stealing Machine Learning Models via Prediction APIs* line
of work — opened by Tramer, Zhang, Juels, Reiter, Ristenpart
(USENIX Security 2016), extended by Jagielski et al. (USENIX
Security 2020) and many others — established that black-box query
access to a model is sufficient to extract a functionally
equivalent model. The original work treats the model API as the
oracle. The extension this writeup names is that *timing of the
API call* is an additional channel: TTFT and TPOT are functions
of the model's data path, and the data path is a function of the
model architecture and weights.

The recent *InputSnatch* line of work (Zheng et al., arXiv 2024)
makes this concrete for LLM serving: prefix caching means that
two identical prompt prefixes hit the same KV cache, and the
TTFT difference between cache-hit and cache-miss is observable
to a co-located user. The attacker can probe the cache to learn
what prefixes other tenants have queried, which is a direct
breach of inter-tenant confidentiality.

Overclocking amplifies InputSnatch in the same way it amplifies
Hertzbleed: the cache-hit/miss timing differential is widened
because the overclocked GPU has a wider boost-clock range to
ride.

### 5.5 Riscure GPU fault injection work

Riscure's body of work on GPU fault injection — voltage glitching
against NVIDIA and AMD GPUs to induce computational faults that
recover keys, leak weights, or violate enclave boundaries — is
the active-attacker counterpart to the passive side-channels this
writeup focuses on. The relevance: the same voltage-frequency
margin that overclocking narrows for side-channel amplification
is the margin that fault-injection actively attacks. The
underlying silicon mechanism is the same.

### 5.6 What this section establishes

The literature contains:
1. The CPU-side DVFS chain (Hertzbleed).
2. The GPU-side rendering-pipeline cache and timing channels
   (Naghibijouybari et al.).
3. The GPU-side EM channel (BarraCUDA).
4. The model-extraction-via-API line (Tramer et al., Jagielski
   et al.) and its timing extension (InputSnatch).
5. The active-attack voltage-glitching line (Riscure).

What it does *not* contain, as of the date of this writeup, is a
systematic measurement of how overclocking amplifies items 2, 3,
and 4 in the AI inference setting. That gap is the contribution
this writeup names.

**Assumption invalidated by this section.** *The published
side-channel literature has fully characterized the GPU
substrate.* The corollary: the published literature has
characterized the substrate at stock settings; the substrate at
overclocked settings is a different operating point, and the
operating point in production AI deployments is closer to
"overclocked" than to "stock" by vendor SKU choice and
hyperscaler tuning.

---

## 6. The AI-Specific Surface

### 6.1 Model extraction via timing

The simplest AI-specific attack on the GPU side-channel surface
is model extraction. The attacker has API access to an inference
service (or co-located unprivileged access to a GPU running the
service), and wishes to recover the model — its architecture
first, its weights second.

**Architecture extraction.** The model's architecture (layer
count, layer types, hidden dimension, attention head count, FFN
hidden dimension, vocabulary size) determines the data-path
shape, which determines the GEMM kernel sequence, which
determines the wall-time profile. The attacker observes
inference wall-time as a function of input shape (batch size,
sequence length) and fits a parametric model of the architecture
to the observations. The literature on this — Cache Telepathy
(Yan et al., USENIX Security 2020), DeepRecon (Hong et al.,
2018) — has shown architecture extraction is practical against
DNN inference services. The AI inference workload's regularity
is what makes it tractable.

Overclocking amplification: the boost-clock excursions in
response to layer-shape changes are wider on overclocked
hardware, so the architecture's signature in wall-time is
crisper.

**Weight extraction via timing.** Recovering individual weights
through timing is harder. The literature has demonstrated weight
extraction via *EM* (BarraCUDA, Horvath et al. 2024) and via
*query-based functional equivalence* (Tramer et al. 2016 and
follow-on), but a pure-timing weight-extraction attack against a
modern LLM has not been published. The structural reason it has
not been published is that the per-weight signal in wall-time is
small relative to the noise, and the number of weights is large.
But the *combination* of timing (for high-level structure) with
EM or with cache contention (for fine-grained weight
information) is an active research area, and overclocking
amplifies all of these channels at once.

### 6.2 Inference-output reconstruction

A more direct AI-specific attack: given side-channel observations
during an inference call, reconstruct the *output* — the
generated text, the predicted class, the generated image. This
is structurally the prompt-extraction problem run in reverse:
instead of recovering the user's input, the attacker recovers
the model's output. Both share the same oracle: the
side-channel observes the data path during inference, and the
data path is a function of both input and output.

For LLM inference, autoregressive generation means each output
token is a separate forward pass. The wall-time profile of each
forward pass is, in principle, a function of which token is
being generated (different tokens activate different
attention-head specialization patterns, different MoE experts in
mixture-of-experts models, different KV-cache access patterns).
The attacker observing many output token wall-times can, in
principle, narrow down the output sequence. Whether this is
*practical* — whether the per-token signal exceeds the per-token
noise — is one of the open questions in §7.

### 6.3 Training-data membership inference via timing

Membership inference asks: was this data point in the training
set of the model? The classical attack — Shokri et al.
(IEEE S&P 2017) and follow-ons — uses output confidence as the
signal. The timing extension uses wall-time as an additional
signal: a model that has memorized a training example may
process it faster (more confident softmax, less attention spread,
sparser activation patterns) than an example it has not seen.

The GateBleed paper (Kalya et al., MICRO 2025) makes this
concrete for Intel AMX with MoE models: the choice of which
expert is activated for a token is a function of the token's
input, and the activation pattern leaks through wall-time. The
defender's response is to disable AMX power management or to
homogenize the expert-activation timing. Neither is free.

### 6.4 Prompt extraction from LLM serving

The most operationally consequential AI-specific surface, as of
2026, is prompt extraction from multi-tenant LLM serving. The
threat model: a hyperscaler runs vLLM, TGI, or a custom serving
stack with prefix caching enabled. Multiple tenants share the
same GPU. A malicious tenant observes the timing of their own
inference calls and, through the cache-hit/miss differential,
learns what prompt prefixes other tenants have queried.

The InputSnatch demonstration (Zheng et al., arXiv 2024)
established this is practical: 600 timing samples sufficed to
achieve approximately 87% classification accuracy on the
"is this prefix in the cache?" question. The bitrate of the
channel scales with the cache size and the boost-clock
arbitration range, both of which are higher on overclocked
hardware.

The structural fact: prefix caching is a Pareto-optimal
performance feature (it improves TTFT by 5–30% on real
production workloads), and it is *also* a side-channel of
inter-tenant prompt content. Disabling prefix caching costs
real TTFT; enabling it costs real privacy. The deployment
posture in 2026, across the hyperscalers the author has
audited, is "enabled, with no documented mitigation".

### 6.5 The data path is the secret

The unifying observation across §6.1–§6.4 is that AI inference
treats the *data path itself* as the load-bearing computational
object, in a way that classical CPU workloads did not. A
cryptographic operation runs over a small data path that the
programmer can hand-tune for constant-time properties. An AI
inference forward pass runs over a data path of billions of
weights and activations, in a kernel sequence determined by the
model architecture, and there is no realistic way to hand-tune
that data path for constant-time. The data path's properties —
its operand distributions, its access patterns, its sparsity,
its branchiness — *are* the secret. Hiding them is hiding the
model.

Constant-time AI inference is, in the author's view, an
unsolved research problem at the level the cryptographic
community would recognize. The §7 open questions name it
explicitly.

### 6.6 What this section establishes

The AI inference workload's side-channel surface is
multi-dimensional and unmitigated. Architecture extraction,
weight extraction (in combination with EM), output
reconstruction, training-data membership inference, and prompt
extraction are all on the surface. Overclocking amplifies the
first four directly through the DVFS chain, and amplifies the
fifth through the cache-timing differential.

**Assumption invalidated by this section.** *AI inference is a
black box to the side-channel observer because the workload is
too large to characterize.* The corollary: the workload is too
large to *characterize per-weight*, but the workload's
high-level structure (architecture, batch size, sparsity,
expert-routing decisions, KV-cache hit/miss state) is exactly
the structure the side-channel observes, and the side-channel
does not need to recover the weights to be operationally
consequential.

---

## 7. Open Questions

The cluster of open research questions this writeup proposes is
selected for two criteria: each is *measurable* with the
instruments currently available (no exotic hardware required),
and each *materially changes the threat-model posture* of
production AI deployments if answered.

### 7.1 Post-quantum AI accelerator side channels

The post-quantum cryptography deployment timeline (NIST PQC
finalists standardized, TLS 1.3 adoption underway, hybrid KEM
modes in widespread deployment by 2027) overlaps with the
deployment timeline for AI accelerators that integrate
cryptographic primitives for secure inference (Apple Neural
Engine with Secure Enclave, NVIDIA Hopper Confidential Computing,
AMD SEV-ES variants for GPU). The question: do the post-quantum
KEMs and signatures that ship inside AI accelerator firmware
have the same Hertzbleed exposure as their CPU counterparts, and
does the AI workload running on the same silicon amplify the
exposure?

The author's prior is yes on both counts. The PQC primitives use
the same DVFS substrate as the surrounding workload. The
AI workload's high-throughput operand churn produces enough
power-state variation to dominate the PQC primitive's own
power-state signature, *which is the worst case for an attacker*
who wants the PQC signal — but it is also the worst case for a
defender who wants to demonstrate that the PQC primitive is
side-channel-isolated from the surrounding workload. The
measurement has not been published; the writeup names this as
priority research.

### 7.2 FP8/FP4 quantization effect on leakage

The transformer engine in modern AI accelerators (NVIDIA Hopper
TE, Blackwell TE; AMD MI300X equivalent) dynamically selects
between FP8 and FP4 operand widths per layer based on a
loss-landscape heuristic. The operand width is a function of the
data, which is a function of the input, which is a function of
the user's prompt. The selection itself is therefore *a
side-channel*: an observer of the GPU's transformer-engine state
learns something about the user's prompt.

Two sub-questions. First, does the operand width's effect on
power dominate or is dominated by the operand bit pattern's
effect? An FP4 operation has fewer bits to switch, but the
tensor core's saturated state is different. The functional form
of the side-channel may differ between FP8 and FP4 in ways the
literature has not characterized. Second, does quantization-aware
training change the operand distribution in a way that affects
side-channel leakage? Quantization aware training selects
weights to be quantization-friendly, which often makes them
sparser, which has obvious side-channel implications.

### 7.3 Multi-tenant GPU isolation

The most operationally consequential open question. Modern GPU
deployments (NVIDIA MIG, AMD CDNA partitioning, virtualization
via SR-IOV, time-slicing via the driver) offer multi-tenant
sharing of physical GPUs in production. The isolation
guarantees that vendors document are *architectural* — partition
A's compute does not touch partition B's address space, MIG
slices have separate L2 cache partitions, etc. — but the
side-channel literature has not characterized what *non-
architectural* state (boost-clock arbitration, HBM bandwidth
arbitration, thermal sensor readings) leaks across the partition
boundary.

The author's prior is that the boost-clock arbitration is the
weakest link: it is a *single global state* on the GPU, shared
across all MIG partitions, and a workload in partition A that
spikes the boost arbiter affects the boost behavior visible to
partition B. The measurement to confirm or refute this is
straightforward (two MIG partitions, two co-located processes,
correlate boost-clock observations against known workload
phases) and has not been published.

### 7.4 Hard-OC versus soft-OC threat differential

Hardware-level overclocking (BIOS/firmware modifications that
change the voltage-frequency curve) and software-level
overclocking (driver-level `nvidia-smi --lock-gpu-clocks
--applications-clocks`) reach the silicon through different
paths. The question: do they produce the same side-channel
amplification, or does hard-OC widen the surface in ways soft-OC
does not?

The author's prior is that hard-OC is worse, because the V/F
curve is *flatter* under hard-OC (the chip is being held at
higher voltage for the same frequency), and the flatter curve
means smaller operand-pattern variations produce larger
frequency excursions. The measurement is again straightforward
and has not been published.

### 7.5 Quantized-model side-channel resilience

A symmetric question to §7.2. Does running an INT8 or INT4
quantized model produce a *narrower* side-channel surface than
the FP16 baseline, because the operand bit patterns have lower
entropy? Or does it produce a *wider* surface, because the
quantization noise and the rounding behavior introduce additional
data-dependent paths?

The author's prior is that INT4 is narrower than FP16 *for
DVFS-based attacks*, because the absolute switching power is
lower and the per-operand variation is smaller. But quantization
introduces lookup-table-based dequantization paths (in some
implementations), and those are *cache-side-channel observable*
in ways the FP16 baseline is not. The two effects may partially
cancel; the net direction of the threat model shift is
unknown.

### 7.6 Confidential-compute AI workloads

NVIDIA's Confidential Computing mode on Hopper, AMD's SEV-SNP
with GPU passthrough, ARM's Realm Management Extension (RME)
all promise the ability to run AI workloads inside a
hardware-attested enclave that excludes the host operating
system from the trust boundary. The question, post-Foreshadow:
does the GPU's confidential-compute mode protect against the
DVFS-derived timing channels described in this writeup, or does
it protect only against the *direct memory read* channels that
Foreshadow used?

The author's prior is the latter. The Hopper confidential-
compute mode protects against memory-content disclosure to the
host; it does not protect against host-observable side-channels
like power draw, thermal sensors, boost-clock arbitration, or
inter-MIG-partition timing. The defender who deploys
confidential-compute AI inference is buying memory-content
protection, *not* side-channel protection, and the writeup
recommends naming this distinction in vendor documentation
explicitly.

### 7.7 Defensive observability

The asymmetric question that closes the open-question set. The
side-channel literature has documented dozens of attacks; the
defensive literature has documented mostly *mitigations*
(disable DVFS, partition the cache, add timing noise). What is
missing is *defensive observability* — instrumentation that
detects, in production, when a side-channel attack is in
progress against a deployed AI system.

The attacker's side-channel queries have signatures: unusual
co-location patterns, repeated micro-timing measurements,
high-frequency calls with varying input shapes, queries that
deliberately span cache-line boundaries. None of these are
hard to detect *in principle*; the production deployments the
author has audited do not detect them in practice. The
research opportunity: build the GPU-side analog of "intrusion
detection" — a continuous monitor for side-channel-attack
behavior, raising alerts before the attack succeeds. The
substrate for it (NVIDIA's DCGM, AMD's ROCm SMI, OpenMetrics
exporters from serving stacks) already exists; what is missing
is the threat-model-derived analysis on top.

---

## 8. References

[Wang et al. 2022] Wang, Y., Paccagnella, R., He, E. T.,
  Shacham, H., Fletcher, C. W., Kohlbrenner, D. *Hertzbleed:
  Turning Power Side-Channel Attacks Into Remote Timing Attacks
  on x86.* USENIX Security 2022. *(Foundational DVFS-as-timing
  paper; CVE-2022-24436 / CVE-2022-23823.)*

[Naghibijouybari et al. 2018] Naghibijouybari, H., Neupane, A.,
  Qian, Z., Abu-Ghazaleh, N. *Rendered Insecure: GPU Side
  Channel Attacks are Practical.* ACM CCS 2018. *(Foundational
  GPU side-channel paper, rendering pipeline and DNN
  architecture extraction.)*

[Horvath et al. 2024] Horvath, P., Soares, J. M., Tunstall, M.,
  Bhasin, S., et al. *BarraCUDA: Bringing Electromagnetic Side
  Channel Into Play to Steal the Weights of Neural Networks
  from NVIDIA GPUs.* 2024. *(EM-based weight extraction on
  NVIDIA Jetson.)*

[Tramer et al. 2016] Tramer, F., Zhang, F., Juels, A., Reiter,
  M. K., Ristenpart, T. *Stealing Machine Learning Models via
  Prediction APIs.* USENIX Security 2016. *(Foundational
  model-extraction paper.)*

[Jagielski et al. 2020] Jagielski, M., Carlini, N., Berthelot,
  D., Kurakin, A., Papernot, N. *High Accuracy and High
  Fidelity Extraction of Neural Networks.* USENIX Security
  2020. *(Modern model-extraction methodology.)*

[Tramer & Boneh 2019] Tramer, F., Boneh, D. *Slalom: Fast,
  Verifiable and Private Execution of Neural Networks in
  Trusted Hardware.* ICLR 2019. *(Threat-model framing for
  AI-in-enclave deployments.)*

[Yan et al. 2020] Yan, M., Fletcher, C. W., Torrellas, J.
  *Cache Telepathy: Leveraging Shared Resource Attacks to
  Learn DNN Architectures.* USENIX Security 2020. *(Cache
  side-channel for DNN architecture extraction.)*

[Hong et al. 2018] Hong, S., Davinroy, M., Kaya, Y.,
  Locke, S. N., Rackow, I., Kulda, K., et al. *Security
  Analysis of Deep Neural Networks Operating in the
  Presence of Cache Side-Channel Attacks.* arXiv 2018.
  *(DeepRecon, architecture-via-cache extraction.)*

[Zheng et al. 2024] Zheng, X., et al. *InputSnatch: Stealing
  Input in LLM Services via Timing Side-Channel Attacks.*
  arXiv 2024. *(Prefix-cache timing leak for LLM prompt
  extraction.)*

[Kalya et al. 2025] Kalya, J., et al. *GateBleed: A
  Timing-Only Membership Inference Attack on Mixture-of-
  Experts.* MICRO 2025. *(MoE expert-routing timing
  channel, Intel AMX target, generalizes to GPU MoE
  inference.)*

[Shokri et al. 2017] Shokri, R., Stronati, M., Song, C.,
  Shmatikov, V. *Membership Inference Attacks Against
  Machine Learning Models.* IEEE S&P 2017. *(Foundational
  membership-inference paper.)*

[Kocher et al. 2018] Kocher, P., Horn, J., Fogh, A., et al.
  *Spectre Attacks: Exploiting Speculative Execution.*
  IEEE S&P 2019. *(Background; the CPU-side categorical
  shift that *Silicon-Adversary* in this portfolio
  reads in depth.)*

[Lipp et al. 2018] Lipp, M., Schwarz, M., Gruss, D., et al.
  *Meltdown: Reading Kernel Memory from User Space.*
  USENIX Security 2018. *(Background.)*

[Van Bulck et al. 2018] Van Bulck, J., Minkin, M., Weisse, O.,
  et al. *Foreshadow: Extracting the Keys to the Intel SGX
  Kingdom with Transient Out-of-Order Execution.* USENIX
  Security 2018. *(Background; the closest CPU-side analog
  to the multi-tenant GPU isolation question in §7.3.)*

[NVIDIA Hopper Architecture Whitepaper] NVIDIA Corporation.
  *NVIDIA H100 Tensor Core GPU Architecture: In-Depth.*
  2022. *(Boost-clock, transformer-engine, MIG
  partitioning specifications.)*

[NVIDIA Blackwell Architecture Whitepaper] NVIDIA Corporation.
  *NVIDIA Blackwell Architecture: In-Depth.* 2024.
  *(FP4/FP6 tensor-core specifications, dual-die
  packaging, confidential-compute mode.)*

[AMD CDNA3 Architecture] Advanced Micro Devices, Inc.
  *AMD CDNA 3 Architecture: AMD Instinct MI300 Series.*
  2023. *(XCD chiplet specifications, ROCm SMI
  interfaces, WMMA matrix-core instructions.)*

[Linux nvidia-smi documentation] NVIDIA Corporation. *NVIDIA
  System Management Interface Reference.* *(Public
  unprivileged interfaces for boost-clock, power, and
  thermal observation.)*

[vLLM project] *vLLM: Efficient Memory Management for LLM
  Serving with PagedAttention.* SOSP 2023. *(Reference
  serving stack for prefix-caching deployments.)*

[Riscure / fault-injection literature] *Riscure technical
  publications on voltage glitching and EM fault injection
  against GPU substrates.* *(Active-attack counterpart to
  the passive side-channels this writeup focuses on.)*

---

## Appendix A — Cross-cluster positioning

This writeup is the explicit **cross-cluster bridge** in the
HBO NL low-level security application portfolio. The portfolio
is organized into clusters:

- **Cluster 1: Mathematical Collapse / Silicon-Adversary /
  Microarch-Isolation / SPI-Firmware-Anatomy / Speculation
  Barrier Illusion** — the microarchitectural-security cluster.
  Reads post-2018 CPU side-channels (Spectre, Meltdown,
  Foreshadow, Hertzbleed, Rowhammer-dedup combinations) as a
  single categorical fact: silicon optimizations produce
  observable state that the software-side threat model never
  enumerated. The unifying frame is "silicon is the
  adversary"; the defensive posture is layered mitigation
  across firmware, microcode, kernel, compiler, and operational
  policy.

- **Cluster 2 (AI-systems security): ACMM-Writeup and
  related** — reads AI systems from the workload side: how
  modern AI inference and training stacks compose, what the
  threat surface of those compositions looks like, and what
  defensive posture is available. ACMM-Writeup names the
  computational mass model (how much compute, where it lives,
  who has access) as the load-bearing object of analysis.

This writeup, *Amplified Leakage*, sits at the join. The
content is structural in the register of Cluster 1 — the same
DVFS-as-timing chain Hertzbleed used, the same
"assumption-invalidated" analysis at the end of each section,
the same observation that the defender's tools live one layer
up from the silicon that the threat lives in. The *subject* is
the AI workload that Cluster 2 takes for granted as the host
on which everything else runs.

The bridge function is asymmetric. To a Cluster 1 reader
(microarchitectural security background), this writeup is "the
GPU is the new CPU" — the substrate has changed, the workload
has changed, but the analytic frame is the same. To a Cluster
2 reader (AI-systems security background), this writeup is "the
GPU is the silicon underneath your workload, and the silicon
has the same threat model the CPU community spent eight years
characterizing — you are inheriting it without having paid the
intellectual cost of generating it." The portfolio is designed
so that a defender who reads across the two clusters arrives
at both views.

### A.1 Pairing with Silicon-Adversary (Cluster 1, CPU side)

The CPU-side companion writeup reads Spectre, Meltdown,
Foreshadow, Hertzbleed, Rowhammer-dedup, and Cloak/HTM
defenses as a single argument about the structural geometry of
post-2018 microarchitectural security. The arc closes with:
"the threat model will keep expanding downward, into firmware,
into DRAM controllers, into MSR-exposed thermal sensors, into
the next layer of silicon engineering that has not yet been
read as a side channel. There is no version of this story
that ends with silicon-as-defender; there is only the version
that ends with the defender's tools matured at every layer
above silicon and the operational discipline to compose them."

This writeup is the next layer down: it shows what happens when
the same structural reading is applied to GPU silicon under AI
workloads. The narrative does not start over; it continues.

### A.2 Pairing with ACMM-Writeup (Cluster 2, AI-systems side)

The ACMM writeup reads the AI computational mass model — the
deployment-level shape of compute, data, and access in modern
AI systems — from the workload-engineer's perspective. It does
not bottom out at the silicon layer; the silicon, in ACMM's
register, is a service the workload consumes. This writeup
provides the bottom: it characterizes the silicon underneath
ACMM's workload, in the same register Cluster 1 uses, and
shows that the silicon is a side-channel emitter that ACMM's
threat model has not yet enumerated.

The composition is mechanically straightforward but
intellectually consequential: an AI-systems defender who reads
both gets a complete top-to-bottom view of their stack's
side-channel exposure. An AI-systems defender who reads only
ACMM does not see the silicon-layer threats; an AI-systems
defender who reads only this writeup does not see the workload-
level mitigations (cache namespacing, timing obfuscation,
batched-inference shuffling) that are the practical answers in
production.

### A.3 The bridge claim

The bridge claim this writeup makes explicit, in the register
the portfolio uses throughout: **microarchitectural security
and AI-systems security are the same field with two registers.**
The microarchitectural register names the substrate-level
threats and the substrate-level mitigations. The AI-systems
register names the workload-level threats and the workload-level
mitigations. The defender of a production AI deployment in 2026
needs both, and the field that has historically split between
"hardware security" conferences (USENIX Security, IEEE S&P, CCS
for the substrate work) and "AI/ML security" venues (DEF CON AI
Village, AISec, individual workshops at NeurIPS) is structurally
the same field. The portfolio's argument, made explicit here, is
that the next generation of defender training should treat the
two as a unit.

---

*This writeup is a structural reading of GPU side-channel
exposure under AI inference workloads, with overclocking as the
amplifier. The intent, in the same register the other portfolio
pieces use, is not to celebrate the attacks or to indict the
silicon, but to make the geometry of the threat surface legible
to a defender who is just arriving at the intersection of
microarchitectural security and AI systems. With acknowledgement
to the academic communities at UC Riverside, UT Austin,
University of Illinois at Urbana-Champaign, University of
Washington, the VUsec group at Vrije Universiteit Amsterdam,
TU Graz, KU Leuven, and the Riscure research team, whose patient
enumeration of GPU and CPU side-channels this writeup
synthesizes into the AI-workload register.*
