---
title: "An Anatomy of Firmware Fault Injection"
subtitle: "From SPI Bus to Bootloader"
author: "Tyler (HBO NL Application Portfolio)"
date: "2026-05-16"
keywords: [SPI flash, firmware fault injection, voltage glitch, clock glitch, electromagnetic fault injection, boot ROM, UEFI, Intel Boot Guard, BIOS Guard, ChipWhisperer, hardware root of trust, anatomical security read]
companion_project: "SPIFault (Fault Campaign Description Format) — the schema side of the same research surface"
---

# An Anatomy of Firmware Fault Injection
## From SPI Bus to Bootloader

---

## Author's Note

There is a tradition in low-level security writing to take a side
— attacker or defender — and write the document from that
position. *Bootkit installation guides* take the attacker's
position; *secure-boot hardening checklists* take the defender's
position. Both registers have their place, and both register
choices distort the artifact: an attack guide will not pause to
describe a fault-mode it cannot productively exploit, and a
defense checklist will not enumerate a phenomenon it cannot
practically mitigate.

This writeup takes a third position — the **anatomical** one.
The SPI bus, the SPI flash IC, the boot ROM, the chain of
signatures that hands control from silicon to firmware to
operating system — these are *things in the world*. They have
electrical properties, protocol properties, die-level
properties, and architectural properties. Where the system is
fault-susceptible, that susceptibility is a structural feature
of the composition, not a moral failing of any one component.
A reader who wants to *attack* the system can derive their tools
from an anatomical read. A reader who wants to *defend* the
system can derive their countermeasures. A reader who wants to
do *research* — to understand a phenomenon well enough to
contribute to the published literature — needs the anatomical
read first.

The piece sits in this portfolio alongside SPIFault, which is
the *schema-side* artifact for fault-injection research: a
specification language for describing a campaign in a way other
researchers can reproduce. The present writeup is the
*content-side* companion: a dissection of one campaign-class
(SPI flash fault injection) at the level of structural detail a
schema is supposed to capture. The two pieces, read together,
are an answer to the same question — *how should fault-injection
research be communicated?* — from two complementary angles.

What follows is seven sections. §1 walks the SPI bus protocol
as an anatomical object. §2 walks the SPI flash IC. §3 walks
the boot ROM chain of signatures. §4 walks the four physical
fault-injection categories — voltage, clock, electromagnetic,
bus-level interception — as phenomena rather than as
techniques. §5 names the confluence points where the chain's
anatomy is structurally susceptible. §6 reviews the empirical
literature: what has been measured, on which silicon, by whom.
§7 lists open questions, the part the literature has not yet
closed and where new research can sit.

The intended reader is someone arriving at firmware fault
injection from one of two directions — the embedded-systems side
(wants to know what the bus actually is, electrically) or the
software-security side (wants to know where the boot chain's
trust assumptions live and what makes them fail). The writeup
tries to be useful to both without taking either's vocabulary.

---

## Abstract

This writeup is an anatomical reading of the SPI-flash fault-
injection surface. It treats the SPI bus, the SPI flash IC,
the boot ROM, and the signature chain that connects them as
structural objects whose composition admits fault states under
documented physical conditions. The contribution is a
layer-by-layer dissection of where the composition is fault-
susceptible, an account of the four physical phenomena that
produce fault states (voltage glitch, clock glitch,
electromagnetic glitch, SPI bus interception), a survey of the
empirical literature that has measured these phenomena on
deployed silicon, and a list of open questions where the
literature is incomplete. The writeup is companion to SPIFault
(the schema-side artifact for describing fault campaigns); the
two pieces are an answer to the same research-communication
problem from complementary angles.

**Keywords:** SPI flash, firmware fault injection, voltage
glitch, clock glitch, electromagnetic fault injection, boot
ROM, UEFI, Intel Boot Guard, BIOS Guard, ChipWhisperer, hardware
root of trust, anatomical security read.

---

## 1. The SPI Bus — Protocol Anatomy

### 1.1 Position in the system

The Serial Peripheral Interface (SPI) bus is the physical
channel by which a host processor reads its firmware at power-
on. On a modern x86 motherboard the host-side endpoint is the
PCH (Platform Controller Hub) SPI controller; the slave-side
endpoint is the SPI flash IC holding the UEFI image. On an
embedded ARM or RISC-V platform the host-side endpoint is the
SoC's SPI peripheral; the slave-side endpoint is, again, an
SPI flash IC.

The bus is the *first interface* the system uses. Before the
CPU has loaded a single byte of firmware, before the memory
controller has been initialized, before any cryptographic
hardware has been activated, the SPI bus has already carried
the reset vector. Whatever fault occurs on the bus during this
window changes what the CPU sees as its first instructions.

### 1.2 The four wires

```
   ┌─────────────────┐                    ┌─────────────────┐
   │                 │── MOSI ──────────▶│                 │
   │                 │◀────────── MISO ──│                 │
   │  Host (master)  │── SCLK ──────────▶│  SPI Flash IC   │
   │                 │── CS#  ──────────▶│  (slave)        │
   └─────────────────┘                    └─────────────────┘
```

| Wire   | Direction         | Function                                     |
|--------|-------------------|----------------------------------------------|
| MOSI   | host → slave      | Master Out, Slave In — commands + write data |
| MISO   | slave → host      | Master In, Slave Out — read response         |
| SCLK   | host → slave      | Serial clock; defines bit-cell boundaries    |
| CS#    | host → slave      | Chip Select, active-low; gates transactions  |

The bus is electrically simple. Four wires, single-ended
push-pull or open-drain, full-duplex (MOSI and MISO can
transport bits in the same clock cycle), master-controlled
clocking. Every property a fault-injection adversary cares
about — the clock domain, the data validity windows, the
voltage levels, the asymmetric speed between command and
response phases — is set by the bus's own protocol definition.

### 1.3 CPOL and CPHA — the four modes

SPI defines four operating modes, indexed by two bits of the
master's configuration: **CPOL** (Clock Polarity) and **CPHA**
(Clock Phase). Each combination shifts when bit-cells are
sampled relative to the clock edge.

| Mode | CPOL | CPHA | Sampling edge                                |
|------|------|------|----------------------------------------------|
| 0    | 0    | 0    | Data sampled on the rising edge of SCLK     |
| 1    | 0    | 1    | Data sampled on the falling edge of SCLK    |
| 2    | 1    | 0    | Data sampled on the falling edge of SCLK    |
| 3    | 1    | 1    | Data sampled on the rising edge of SCLK     |

A fault relevant to mode is one that *shifts the sampling
window*: a sufficiently sharp glitch on SCLK can cause the
slave to sample a bit one cell earlier or later than the
master intended, with the effect that a single command byte
can be read as a different command byte. The flash IC's
state machine consults the *sampled* byte, not the byte the
master meant to send. Mode is, in fault-injection terms, a
property of *whose interpretation wins* when the clock and
the data lines disagree.

### 1.4 Multi-slave addressing

A single SPI host can address multiple slaves via independent
CS# lines:

```
                                  ┌── CS0# ──▶ Flash IC #0
   ┌─────────────────┐            │
   │                 │── MOSI ────┼─────────▶ All slaves
   │                 │── MISO ◀───┤
   │  Host           │── SCLK ────┼─────────▶ All slaves
   │                 │── CS1# ────┼─────────▶ Flash IC #1
   │                 │            │
   │                 │── CS2# ────┴─────────▶ Flash IC #2
   └─────────────────┘
```

CS# is active-low; only one slave responds at a time. The MISO
line is, electrically, a shared bus — the selected slave drives
it, the others tri-state. A fault-injection scenario that
matters on a multi-slave bus is one in which two slaves
become simultaneously selected (CS# floats or is driven low on
two lines at once), and the MISO line is driven by two devices,
yielding electrically undefined bit values.

### 1.5 The bus as fault surface — summary

Three properties of the bus, taken together, define the
fault-injection surface at the protocol layer:

1. **Single-ended electrical signaling.** No differential
   pairs, no error-correcting line code. Every wire's voltage
   is interpreted directly as a bit; a sufficient transient
   on any wire becomes a bit flip in the slave's state machine.
2. **Master-driven clocking.** SCLK is generated by the
   host, not negotiated. An adversary with bus access who can
   modulate SCLK timing changes the slave's sampling window
   unilaterally.
3. **Asymmetric trust.** The slave does not authenticate the
   master. Any device that can drive MOSI / SCLK / CS# at the
   electrical level can issue commands to the flash IC,
   including erase commands, write-enable commands, and
   security-register read commands. The protocol's threat
   model assumes the bus is inside a physical security
   boundary.

This is the anatomy of the bus, not yet a fault scenario. The
fault scenarios live in §4. The bus's properties define what
sort of fault scenarios are possible.

---

## 2. The SPI Flash IC — Die-Level Anatomy

### 2.1 The IC as a state machine

An SPI flash IC is not a passive memory. It is an embedded
state machine — typically an 8-bit microcontroller with a
small instruction set — that exposes a SPI-protocol interface
over MOSI / MISO / SCLK / CS#, and that owns the actual NOR-
flash array on the same die.

The state machine's principal duties:

- Decode incoming command bytes (READ, FAST_READ, WREN, WRDI,
  PP, SE, BE, CE, RDID, RDSR, WRSR, ...).
- Apply chip-internal protection state (Block Protect bits,
  Write Protect pin, Write-Lock bit) to writes.
- Sequence the array's read / program / erase cycles (program
  takes ~1 ms / 256-byte page; erase takes 100–500 ms / 4 KB
  sector).
- Maintain the Status Register, the Security Register, and the
  SFDP (Serial Flash Discoverable Parameters) tables.

Every one of these duties is implemented as logic on the IC die,
executed by the embedded controller, observable only through
the SPI interface. The host has no register-level visibility
into the controller's internal state.

### 2.2 The control structures

```
SPI Flash IC, internal layout (simplified, vendor-typical)
───────────────────────────────────────────────────────────

  ┌────────────────────────────────────────────────────────┐
  │  Status Register (1 byte, sometimes 2-3 in newer parts)│
  │  ┌──────────────────────────────────────────────────┐  │
  │  │ SRWD │ BP3 │ BP2 │ BP1 │ BP0 │ WEL │ BUSY │     │  │
  │  └──────────────────────────────────────────────────┘  │
  │                                                          │
  │  - BP[3:0]  : Block Protect bits — write-protect range │
  │  - WEL      : Write Enable Latch                       │
  │  - SRWD     : Status Register Write Disable            │
  │  - BUSY     : Program/Erase in progress                │
  └────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────┐
  │  Security Register (typically 3 × 256-byte regions)    │
  │  - OTP (One-Time Programmable): factory data           │
  │  - Lock bits (per region)                              │
  │  - User-programmable; permanent once locked            │
  └────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────┐
  │  SFDP Tables (JEDEC JESD216 standard)                  │
  │  - Discoverable parameters: page size, sector size,    │
  │    command set, dual/quad capabilities, timings        │
  │  - Read-only from the host's perspective               │
  └────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────┐
  │  Array (NOR flash main storage)                        │
  │  - Erased state: all bits = 1                          │
  │  - Program: 1 → 0 (per bit, no 0 → 1 without erase)    │
  │  - Erase granularity: sector (4KB) / block (32/64KB) / │
  │    chip                                                │
  │  - Endurance: 100k erase cycles / sector (typical)     │
  └────────────────────────────────────────────────────────┘
```

The state machine consults these structures on every write
command. The Block Protect bits are the principal anti-
modification gate: a write or erase to an address inside a
protected range is silently refused, with no error returned to
the host beyond a status-register read of "not BUSY but WEL
remains set".

### 2.3 The asymmetry of program vs erase

A foundational property of NOR flash that matters for fault
injection: **a bit can be programmed (1 → 0) per page, but
cannot be unprogrammed (0 → 1) without an erase of the entire
containing sector**. This is a physical property of the floating-
gate cell: programming injects charge; erasure tunnels charge
out via a high voltage applied to the whole sector at once.

A fault-injection adversary who can program *additional* bits to
zero without erasing has a one-way write primitive: they can
turn an existing UEFI image's `0xff` padding bytes into arbitrary
machine code, but cannot turn `0xfa` into `0xff` without
permission to erase the whole sector. The asymmetry is *the*
defining property for what kind of firmware modifications are
single-fault-feasible.

### 2.4 Hidden state — OTP, lock bits, SFDP-tampering

Three regions are particularly underexamined in the public
literature:

- **OTP (One-Time Programmable) regions.** Per-IC, ~256–1024
  bytes, programmable once by anyone with bus access, then
  permanent. Common use: vendor signature, board serial, MAC
  address. A fault-injection adversary who programs the OTP
  before the legitimate manufacturer can pre-empt the board's
  identity.

- **Lock bits.** Per-region, one-shot. Setting a lock bit makes
  the corresponding region read-only or read-protected.
  Asymmetry: an adversary can set lock bits to *deny* legitimate
  firmware updates, with no physical-tampering recovery path
  short of replacing the IC.

- **SFDP tampering.** The SFDP table is read by host firmware
  to discover the chip's parameters (page size, command set,
  timing). A modified SFDP can cause the host to send commands
  the host's driver was never tested against — a fault primitive
  that lives at the *protocol* layer rather than the array
  layer.

### 2.5 The Write Protect pin — physical override

Every SPI flash IC includes a Write Protect pin (WP#), typically
active-low. When asserted, the chip refuses Status Register
writes and (depending on configuration) protects the entire
array. The pin is electrical, not protocol — it cannot be
manipulated by an adversary with only SPI bus access; it
requires physical access to the IC's pin.

The pin's existence is the IC's *physical* root of trust. The
flash's security model, as designed, assumes:
1. The motherboard routes WP# to a controlled GPIO under
   privileged firmware control.
2. The privileged firmware deasserts WP# only during a sanctioned
   update flow.
3. The hostile environment cannot bridge WP# to ground or to
   Vcc on the running board.

Each of these assumptions has been violated in published
research (§6 below). The WP# pin is the cleanest single point
in the IC's anatomy; it is also the cleanest single point that
gets bypassed by adversaries with physical access.

---

## 3. The Boot ROM Chain — Sequential Trust Handoffs

### 3.1 The chain, end to end

```
   Power-on Reset
        │
        ▼
  ┌──────────────┐
  │  Boot ROM    │  ← read-only mask ROM on the SoC die
  │  (CPU-internal)│
  └──────┬───────┘
         │
         │  fetches initial bytes via SPI controller
         ▼
  ┌──────────────┐
  │  SPI Flash   │  ← UEFI / IBV firmware image
  │  (External)  │     - Authenticated Code Modules (Intel ACMs)
  │              │     - IBV firmware (AMI, Insyde, Phoenix)
  │              │     - Vendor add-ons (OEM-specific)
  │              │     - OS Loader (winload / shim / GRUB)
  └──────┬───────┘
         │
         │  hands control to OS loader
         ▼
  ┌──────────────┐
  │  OS Kernel   │
  │  (Win / Linux)│
  └──────────────┘
```

Each arrow is a *signature handoff*. The boot ROM verifies the
first stage's signature against a key burned in eFuse. The first
stage verifies the second stage's signature against a key the
first stage trusts. And so on down the chain. The integrity of
the operating system at boot is the *product* of every
signature check along the way, in series.

### 3.2 Intel's chain — Boot Guard + BIOS Guard

On modern Intel platforms (Skylake and later) the architecture
is documented as follows:

- **Boot Guard ACM** (Authenticated Code Module): a signed
  microcode-class module loaded by the CPU's microcode during
  reset. The ACM verifies the initial IBV firmware against a
  key whose public half is in eFuse and whose private half is
  Intel's.
- **IBV Firmware**: the bulk of the UEFI image; AMI/Insyde/
  Phoenix-vendor code; loaded after ACM verification.
- **BIOS Guard ACM**: a separate ACM that enforces SPI-flash
  write policies at runtime — only signed update images can
  perform writes to certain SPI regions.
- **UEFI Variables / SMM Modules**: code paths that the OS may
  invoke through SMI handlers, also subject to BIOS Guard
  policy.

The chain is, *architecturally*, comprehensive. The reset
vector fetches into ACM territory; the ACM authenticates the
IBV; the IBV authenticates the next stage; runtime write
policy is enforced by a second ACM. Each link in the chain has
a documented signature scheme.

### 3.3 The same chain on AMD

AMD's analogous architecture is:

- **AMD-SI ROM**: the silicon root of trust, executed by the
  Platform Security Processor (PSP, an ARM Cortex-A5 core on
  the same die as the x86 cores).
- **PSP Firmware (bootloader stages)**: signed by AMD, loaded
  from a dedicated region of SPI flash.
- **AGESA / OEM Firmware**: AMD reference code plus OEM
  customization, signed by the OEM under AMD's CA.
- **x86 firmware (UEFI)**: loaded by PSP after the PSP's
  initialization completes.

The PSP is a *parallel* trust path — it runs before and
alongside the x86 cores, and its compromise reaches every
later stage by definition.

### 3.4 Microsoft Pluton — the recent generation

Pluton (announced 2020, shipping 2022+) is Microsoft's
hardware root of trust integrated into the SoC by AMD, Intel,
and Qualcomm. Architecturally it is an isolated security
processor with:

- Its own boot ROM and signature chain, distinct from x86 /
  ARM main cores.
- A firmware update channel managed by Microsoft via Windows
  Update.
- A cryptographic interface used by Windows for attested
  measurements and key storage.

Pluton's significance, anatomically, is that it relocates the
TPM from a discrete IC on the LPC/SPI bus into the same package
as the CPU — eliminating the bus-sniffing attack class
documented against discrete TPMs (§6.4 below).

### 3.5 The chain's load-bearing assumption

Every link in every variant of the chain rests on the same
property: **the previous link's measurement-of-the-next-link is
performed before the next link executes**. The order is

```
   for each link L_{n+1} in the chain:
       1. fetch L_{n+1} bytes from SPI
       2. verify L_{n+1}.signature against L_n.trust_key
       3. if verified: jump to L_{n+1}.entry_point
       4. if not verified: halt
```

This is correct, *as long as* steps 1, 2, and 3 happen in that
order without interruption. The fault-injection literature is
the systematic enumeration of conditions under which the order
can be perturbed.

---

## 4. Fault Injection Vectors — Physical Phenomena

This section is about *what physically happens* in each of the
four documented fault-injection categories. Each phenomenon is
described as a measurable physical event with measurable
effects on the silicon's state machine. The section is not a
how-to. It is a structural description of what the experimental
literature reports.

### 4.1 Voltage glitch

The premise: digital logic requires Vcc within a manufacturer-
specified range. Outside that range, individual transistors
operate outside their characterized timing margins, with the
result that combinational paths produce wrong outputs and
flip-flops sample wrong values. The fault is *transient* —
restoring Vcc restores correct operation — but the wrong values
sampled during the glitch persist as state.

```
   Vcc  ─────────╗                       ╔─────────
                 ║                       ║
                 ║  ◀── glitch width ─▶  ║
                 ║                       ║
  Vglitch ──────╚═══════════════════════╝──────────

   t              t1                     t2
```

Measurable parameters:

- **Glitch depth** (mV below nominal). On a 1.0 V Vcc core,
  depths of 200–400 mV are typical for productive faults.
- **Glitch width** (ns). 5–500 ns is the documented productive
  range, with chip-family-dependent sweet spots.
- **Trigger offset** (ns from a reference event). Typically a
  CS# falling edge, an SCLK count, or a power-on counter.

The phenomenon is well-instrumented. Public-domain platforms
(ChipWhisperer-Lite, ChipWhisperer-Husky from NewAE Technology)
generate calibrated glitches via an FET in series with the
target's power rail, with sub-nanosecond trigger precision.
Riscure's Inspector platform offers comparable instrumentation
at commercial-research price points.

The measured effect of a productive voltage glitch on a CPU
executing a signature check: the comparison instruction can
sample a stale or wrong flag bit, with the result that
`jne not_authenticated` is mispredicted as `je authenticated`,
and the next signed-image-required execution path is taken
without the verification's branch condition having been
true. This is the canonical "skip the signature check" effect,
and it is the effect Plundervolt [Murdock et al. 2020]
demonstrated against Intel SGX via software-controlled MSR
voltage scaling.

### 4.2 Clock glitch

The premise: digital logic's sampling is keyed to clock edges.
A clock edge that arrives early or late, relative to the data
the logic is supposed to sample, causes the sampling flip-flop
to capture either the previous bit cell (early edge) or no bit
at all (very late edge, missing the setup window). The fault is
again transient, but the wrong sample propagates.

Clock glitching is most productive on the *target's* clock
(the SoC core clock), not on SCLK directly. However, on the
SPI bus specifically, SCLK glitches affect the slave's
sampling of MOSI bytes — a different fault primitive, with
different observable effects (e.g., the flash IC interprets a
command byte differently than the host intended).

Measurable parameters:

- **Glitch offset** within the clock period (typically 10–80%
  of the period, with the sweet spot vendor-dependent).
- **Glitch length** (in fractions of a clock period).
- **Number of consecutive glitched cycles**.

Public-domain instrumentation: ChipWhisperer's clock-glitch
mode (FPGA-generated, phase-shifted, single-cycle precision).

### 4.3 Electromagnetic fault injection (EMFI)

The premise: a high-current pulse through a small coil placed
close to the target IC's die induces eddy currents in the
silicon that locally disturb transistor switching. The result
is a localized fault — adjacent transistors are unaffected; a
single transistor pair within the coil's footprint flips state.

EMFI is the most *spatially selective* of the four fault
classes. By moving the coil over the package, an experimenter
can map *which die region produces which fault* — e.g., the
ALU's carry flag, a specific cache way, the branch predictor's
counter. The technique is documented in the academic literature
from approximately 2012 (Schmidt and Hutter at TUGraz; Dehbaoui,
Dutertre, Robisson, and Tria at LIRMM/Mines Saint-Etienne).

Measurable parameters:

- **Coil position** (X, Y, Z over die).
- **Pulse magnitude** (typically 200–1000 V into a small coil).
- **Pulse rise time** (sub-nanosecond, dominated by the
  trigger circuit's slew rate).
- **Repetition rate** (relative to a trigger event).

Public-domain EMFI hardware is sparse but exists: the
ChipSHOUTER from NewAE, the Riscure EM-FI Transient Probe at
the commercial end.

### 4.4 SPI bus interception (man-in-the-middle)

Distinct from the three transient-fault categories above:
bus interception is a *non-transient* attack class in which the
adversary inserts a hardware probe between the host and the
flash IC, observes traffic, and optionally substitutes responses.

```
   ┌────────┐  ───MOSI──▶ ┌──────────────────┐  ───MOSI──▶ ┌───────────┐
   │  Host  │  ───SCLK──▶ │  MITM Adversary  │  ───SCLK──▶ │  Flash    │
   │        │  ───CS#───▶ │  (FPGA / Glasgow │  ───CS#───▶ │  IC       │
   │        │  ◀──MISO─── │   Interface      │  ◀──MISO─── │           │
   └────────┘             │   Explorer)       │             └───────────┘
                          └──────────────────┘
```

The phenomenon is electrical: at standard SPI clock rates
(10–50 MHz for fast read modes), an FPGA-based probe can
process every transaction in real time, optionally substituting
MISO bytes with attacker-chosen values. The premise:
*if the adversary can sit on the bus, the boot ROM's view of
the flash is whatever the adversary chooses to send back*.

Public-domain platforms: Glasgow Interface Explorer
(open-source FPGA SPI interceptor), various Lattice ICE40-
based community projects, Glitchkit-style hobbyist tooling.

### 4.5 The shape of the surface

| Phenomenon              | Granularity    | Persistence | Public instrumentation cost |
|-------------------------|-----------------|-------------|-------------------------------|
| Voltage glitch          | Whole-chip      | Transient   | $250 (ChipWhisperer-Lite)     |
| Clock glitch            | Whole-chip      | Transient   | $250 (ChipWhisperer-Lite)     |
| EMFI                    | Spatially local | Transient   | $2,000 (ChipSHOUTER)          |
| Bus interception (MITM) | Whole-protocol  | Permanent   | $80 (Glasgow IE)              |

Bus interception is structurally different: it costs the least,
requires only the attacker to be on the bus, and persists for
the duration of the bus contact. The transient categories
require precise timing but operate without the adversary
maintaining a physical position. The four categories *compose*
— a productive campaign typically uses two or three of them in
sequence (e.g., MITM the bus to identify a critical instruction
window, then EMFI to corrupt that specific instruction's flag
output).

---

## 5. Where the Anatomy Fails — Confluence Points

This section names the *structural* susceptibilities — the
places where two independently-correct properties of the
anatomy compose into a system property that is no longer
correct. The presentation is observational. Each subsection
describes a confluence the experimental literature has
demonstrated; the bibliographic anchors are in §6.

### 5.1 Time-of-check vs time-of-use across the SPI fetch boundary

The boot ROM verifies a stage's signature *after* reading the
stage's bytes from SPI. Between the read and the verification,
the bytes pass through:

1. The host's SPI controller (some PCHs cache prefetched bytes
   in an internal buffer).
2. The host's data path (the bytes are written to system DRAM
   before being hashed).
3. The hash function's input stream (the bytes are re-read
   from DRAM into the hash core's input register).
4. The signature verifier (the hash is compared against a
   decrypted-via-public-key reference).

A fault injected between steps 1 and 2, or between steps 2
and 3, can produce a hash over *different bytes* than the
bytes that subsequently execute. If the bytes that execute are
the *original signed image*, the executed image is authentic.
If the bytes that execute differ from those hashed, the chain
is broken — but the hash check still passes.

This is the TOCTOU window at the firmware level. The
literature has demonstrated it on multiple platforms with
bus-MITM in the time between hash-of-fetched-bytes and
execution-of-fetched-bytes (the "swap the flash response after
the hash" attack class).

### 5.2 Asymmetric authentication — boot ROM vs NVRAM variables

The boot ROM authenticates the initial firmware image. UEFI
firmware, once authenticated, then *itself* reads NVRAM
variables — boot configuration, secure-boot databases (PK,
KEK, DB, DBX), TPM event-log entries — that are also stored
on SPI flash but in a *different region* with *different*
write-protection settings.

The NVRAM region is, by design, writable from the running
OS (this is how the OS records boot events, updates the
secure-boot databases, etc.). The protection is *runtime*
(BIOS Guard enforces signed-update policy on writes to this
region during OS execution); it is *not* compile-time-baked.

A fault that corrupts the BIOS Guard ACM's enforcement of
NVRAM write policy reduces the system to: signed initial
firmware, unsigned NVRAM variables that the signed firmware
trusts. The unsigned NVRAM variables can then redirect the
firmware's behavior at the next reboot.

### 5.3 Single-signature trust along a multi-stage chain

The chain in §3 has multiple links, each signed independently.
A compromise of *any one signing key* breaks *all subsequent
stages*. There is no in-band cross-check: stage N+1 trusts
stage N completely; stage N+2 trusts stage N+1 completely.
The product-of-probabilities reasoning that a defender might
hope holds — "all stages must be compromised" — does not
hold; *any* stage compromise reaches every subsequent stage.

The implication for fault injection: a single productive
glitch on the *first* stage's verification opens the entire
chain. Targeted research effort concentrates on the lowest-
stage signature checks for this reason.

### 5.4 The update channel as a re-entry point

The boot chain's signatures protect the *runtime* image. They
do not protect the *update channel* through which the image
is replaced. UEFI firmware updates are delivered via:

- **Windows Update** capsule updates (UEFI capsule format,
  signed by Microsoft + the OEM).
- **OEM update utilities** (vendor-specific signed payloads).
- **fwupd** on Linux (community-maintained LVFS firmware
  update aggregator).

Each channel has its own signature scheme, its own trust
anchors, and its own update-time verification flow. The
firmware that runs at the next boot is whatever the most-
recent update committed; a confluence between an update-channel
fault and a chain-of-signatures gap produces a persistent
firmware compromise that survives reboot, OS reinstall, and
disk replacement.

The Eclypsium research group has documented multiple cases in
the field where update-channel vulnerabilities were the
practical breach vector even on Boot-Guard-protected systems.

### 5.5 The bus's physical accessibility

A property of the SPI flash IC that is rarely stated in the
public discussion of firmware security: the chip is a
physical object on the motherboard PCB, typically in an
SOIC-8 or WSON-8 package, with externally accessible pins.
Test points are commonly placed at the chip's pins for
manufacturing diagnostics. A motherboard with the lid removed
exposes the bus to anyone with a SOIC-8 clip — the cost of
which is ~$15 for the hobbyist-grade variety.

The Boot Guard / BIOS Guard architecture assumes the SPI bus
sits *inside* the physical security boundary; the hardware
makes no provision for a hostile bus. This is the cleanest
single observation about the surface — the chain's strongest
crypto guarantees are written under a physical-access threat
model the chain itself does not enforce.

---

## 6. What the Literature Has Shown

This section is a survey of the empirical literature on
firmware fault injection from approximately 2014 to 2025.
The intent is bibliographic — to name the papers, the
hardware they used, the results they reported — so a researcher
arriving at this surface has a reading list.

### 6.1 Foundational fault-attack literature

Before firmware-specific research, the broader fault-attack
literature established the framework:

- **Bar-El et al. (2006)**, *The Sorcerer's Apprentice Guide
  to Fault Attacks*. Foundational taxonomy of fault attacks on
  cryptographic implementations. Establishes voltage / clock /
  temperature / EM as the four main fault categories and the
  mathematics by which a fault becomes a key recovery.

- **Kocher, Jaffe, Jun (1999)**, *Differential Power Analysis*,
  CRYPTO 1999. Demonstrated that power consumption during
  cryptographic operations leaks key bits. Established the
  side-channel-as-research-surface paradigm that fault
  injection is a destructive cousin of.

### 6.2 Voltage glitch on commodity processors

- **Tang, Sethumadhavan, Stolfo (2017)**, *CLKSCREW:
  Exposing the Perils of Security-Oblivious Energy
  Management*, USENIX Security 2017. First major paper to
  show that *software-controlled* voltage scaling (the OS's
  own DVFS interface) could be weaponized as a fault primitive
  against ARM TrustZone. No physical probe required.

- **Murdock, Oswald, Garcia, Van Bulck, Gruss, Piessens
  (2020)**, *Plundervolt: Software-based Fault Injection
  Attacks against Intel SGX*, IEEE S&P 2020. Extended the
  CLKSCREW idea to Intel SGX via the MSR-controlled voltage
  interface. Demonstrated AES key extraction from enclaves
  via undervolting.

- **Chen, Vinothkumar, Yarom (2021)**, *VoltPillager: Hardware-
  based fault injection attacks against Intel SGX Enclaves
  using the SVID voltage scaling interface*, USENIX Security
  2021. Hardware-level extension of Plundervolt: a $30
  microcontroller inserted on the SVID (Serial Voltage
  Identification) bus between the CPU and the voltage
  regulator achieved the same SGX compromise after Intel had
  patched Plundervolt's software interface.

### 6.3 Bootloader and firmware-level fault attacks

- **Redini, Machiry, Das, et al. (2017)**, *BootStomp: On the
  Security of Bootloaders in Mobile Devices*, USENIX Security
  2017. Multi-vendor analysis of Android bootloaders;
  identified six previously-unknown vulnerabilities including
  signature-bypass paths and arbitrary memory write
  primitives via the boot ROM's untrusted-input handling.

- **Eclypsium (2019–present)**, multiple technical reports
  documenting Intel Boot Guard ACM bypasses on shipping
  hardware, including the IPMI / BMC re-flash path, the
  Direct Connect Interface (DCI) attack surface, and the
  insecure update channel cases.

- **ESET (2018)**, *LoJax: First UEFI rootkit found in the
  wild*, ESET research blog. First documented production-
  observed UEFI rootkit, used by the Sednit (APT28) actor.

- **Kaspersky (2020)**, *MosaicRegressor: UEFI rootkit
  campaign attributed to Hacking Team / Winnti tooling*.
  Demonstrated that the threat model of "in-the-wild firmware
  persistence" is no longer hypothetical.

### 6.4 TPM, SPI, and bus-sniffing attacks

- **Sparks (2006)**, *A Security Assessment of Trusted Platform
  Modules*. The original TPM Reset Attack; demonstrated that
  the discrete TPM's LPC-bus interface could be reset
  asynchronously while a measurement was in flight, allowing
  arbitrary PCR values to be loaded.

- **Wong (2021)**, *Sniffing BitLocker keys from a TPM*. A
  contemporary write-up demonstrating LPC bus sniffing of a
  Microsoft Surface Pro 3's TPM communications to recover
  BitLocker keys with sub-$100 hardware. Practical
  demonstration of why Pluton-class integrated TPMs matter.

- **Cooper Quintin / EFF (various)**, BadUSB-class research
  on USB firmware and its parallels to SPI flash
  manipulation; established the wider field of "firmware is
  the new code" as a practitioner conversation.

### 6.5 EM fault injection

- **Schmidt, Hutter (2007)**, *Optical and EM Fault Attacks on
  CRT-based RSA: Concrete Results*, Cryptologia. Early
  experimental EM fault injection on cryptographic processors.

- **Dehbaoui, Dutertre, Robisson, Tria (2012)**, *Electromagnetic
  Transient Faults Injection on a Hardware and a Software
  Implementations of AES*, FDTC 2012. Demonstrated EM faults
  on both hardware AES (FPGA) and software AES on ARM. Among
  the first reports to characterize the spatial selectivity
  of the technique on a die.

- **Riscure technical reports (various)**, applied EM fault
  injection against deployed SoC silicon for hardware-
  security evaluations. The reports are typically NDA-bound;
  Riscure's published Inspector platform documentation
  describes the technique at high level.

### 6.6 Microcode and management-engine attacks

- **Goryachy, Ermolov (2017)**, *How to Hack a Turned-Off
  Computer, or Running Unsigned Code in Intel Management
  Engine*, Black Hat Europe 2017. Demonstrated arbitrary code
  execution inside the Intel Management Engine via a USB-DCI
  attack vector. Significance: even when the x86 cores are
  powered off, the ME remains running and reachable.

- **Goryachy, Ermolov, Sklyarov (2018)**, *Intel ME: Flash File
  System Explained*. Bus-level reverse engineering of the ME's
  on-flash storage format; basis for follow-on attacks on the
  ME's runtime trust assumptions.

### 6.7 The instrumentation literature

- **O'Flynn, Chen (2014)**, *ChipWhisperer: An Open-Source
  Platform for Hardware Embedded Security Research*. The
  paper introducing the ChipWhisperer platform; established
  the open-source-instrumentation tradition that has since
  enabled most public-domain fault-injection research.

- **NewAE Technology (2014–present)**, ongoing development of
  ChipWhisperer-Lite, ChipWhisperer-Husky, and ChipSHOUTER.
  The instrument the literature has standardized on for
  reproducible work.

- **Glasgow Interface Explorer (2018–present)**, open-source
  community FPGA platform; widely used for SPI bus MITM in
  hobbyist and academic research.

### 6.8 Synthesis

The pattern across two decades of literature: each new
deployed firmware-protection mechanism has, within roughly
three to five years, been demonstrated to have a fault-
injectable path around it. CLKSCREW (2017) followed the
introduction of widely-deployed TrustZone. Plundervolt (2020)
followed the broad deployment of SGX. VoltPillager (2021)
followed Plundervolt's software-side patching by Intel. The
research-and-response cycle is structurally biased toward
discovery — physical phenomena are easier to find than to
mitigate — and the literature shows no sign of approaching a
fixed point.

---

## 7. Open Questions

This section is a research-agenda invitation. Each item is a
question the published literature has not closed, where new
empirical or theoretical work could contribute.

### 7.1 Variability across flash vendors

The literature reports glitch parameters in the form *(V, t,
trigger)* for specific (vendor, family, lot) tuples. There is
no systematic public catalogue mapping glitch parameters to
flash families across the vendor space (Macronix MX25,
Winbond W25, Infineon S25, Microchip SST26, ...). A research
project that produces such a catalogue, with confidence
intervals across lot variation, would close one of the
field's largest measurement gaps.

### 7.2 Temperature dependence of glitch success

Voltage and clock glitch success rates are temperature-
dependent — colder silicon has tighter timing margins, with
the result that smaller-magnitude glitches become productive.
The dependence is not systematically reported in the
published literature; most papers fix temperature at room and
do not vary it. A characterization study across the
commercial temperature range (-40 °C to +85 °C) would
illuminate a structurally important degree of freedom.

### 7.3 Formal models of the boot-chain trust handoff

The chain in §3 is *informally* understood as a series of
signature checks. There is no widely-adopted formal model of
the chain that admits machine-checkable proofs of properties
like "no execution path skips a signature check" or "the
hashed bytes are the executed bytes". Building such a model
on a published boot chain (Coreboot or Tianocore's reference
EDK2 would be candidate targets) and identifying which of the
documented attacks (§6.3) are invariant violations of the
model is open territory.

### 7.4 Spatial-selectivity bounds on EMFI

EMFI's spatial selectivity is known to be coil-geometry-
dependent, but the lower bound on the resolution (how small a
die region a coil-and-pulse pair can affect) is not well-
established in public data. With modern silicon at 5 nm and
below, the question becomes especially pointed: a single die
contains tens of billions of transistors; whether EMFI can
target individual functional units (an ALU, a load-store
queue, a single cache way) or only larger regions is an
empirical question with implications for what defenses are
even conceivable.

### 7.5 Observable side-effects of productive glitches

A fault that bypasses a signature check produces an executing
process that, by construction, is in a state the firmware did
not intend. Whether that state has *observable* side-effects —
in TPM PCR measurements, in performance counters, in voltage-
regulator telemetry, in the system's own SMBus traffic — is
under-characterized. If productive faults are always
detectable post-hoc with the right instrumentation, the
defensive posture changes substantially.

### 7.6 The update-channel formal verification gap

Firmware update channels (UEFI capsule, fwupd, OEM utilities)
are independently designed and independently verified, with
no shared specification across vendors. Whether a single
formal specification of the *update protocol* (independent
of the firmware image format) is feasible, and whether such a
specification would catch the empirically-observed update-
channel attacks (§5.4), is a software-engineering question as
much as a security one.

### 7.7 The relationship between transient and persistent faults

The four physical phenomena in §4 produce *transient* state
changes. Persistence is achieved by composition with a
*write* primitive — the transient glitch causes a write to
happen that would not otherwise have happened. Whether there
is a phenomenon that produces *directly* persistent fault
state — an EMFI-induced charge injection into a NOR cell, for
example — is a question the literature touches but does not
close.

---

## References

[Bar-El et al. 2006] Bar-El, H., Choukri, H., Naccache, D.,
  Tunstall, M., Whelan, C. *The Sorcerer's Apprentice Guide to
  Fault Attacks.* Proceedings of the IEEE, 94(2), 2006.

[Kocher et al. 1999] Kocher, P., Jaffe, J., Jun, B.
  *Differential Power Analysis.* CRYPTO 1999.

[Tang et al. 2017] Tang, A., Sethumadhavan, S., Stolfo, S.
  *CLKSCREW: Exposing the Perils of Security-Oblivious
  Energy Management.* USENIX Security 2017.

[Murdock et al. 2020] Murdock, K., Oswald, D., Garcia, F. D.,
  Van Bulck, J., Gruss, D., Piessens, F. *Plundervolt:
  Software-based Fault Injection Attacks against Intel SGX.*
  IEEE S&P 2020.

[Chen et al. 2021] Chen, Z., Vinothkumar, S., Yarom, Y.
  *VoltPillager: Hardware-based Fault Injection Attacks
  against Intel SGX Enclaves using the SVID Voltage Scaling
  Interface.* USENIX Security 2021.

[Redini et al. 2017] Redini, N., Machiry, A., Das, D.,
  Fratantonio, Y., Bianchi, A., Gustafson, E., Shoshitaishvili,
  Y., Kruegel, C., Vigna, G. *BootStomp: On the Security of
  Bootloaders in Mobile Devices.* USENIX Security 2017.

[ESET 2018] ESET Research. *LoJax: First UEFI rootkit found
  in the wild, courtesy of the Sednit group.* ESET WeLiveSecurity,
  September 2018.

[Kaspersky 2020] Kaspersky GReAT. *MosaicRegressor: Lurking in
  the shadows of UEFI.* Securelist, October 2020.

[Sparks 2006] Sparks, E. R. *A Security Assessment of Trusted
  Platform Modules.* Dartmouth Technical Report TR2007-597,
  2006.

[Wong 2021] Wong, H. *Extracting BitLocker keys from a TPM.*
  Personal research write-up, 2021.

[Schmidt, Hutter 2007] Schmidt, J.-M., Hutter, M. *Optical and
  EM Fault-Attacks on CRT-based RSA: Concrete Results.*
  Austrochip 2007.

[Dehbaoui et al. 2012] Dehbaoui, A., Dutertre, J.-M., Robisson,
  B., Tria, A. *Electromagnetic Transient Faults Injection on
  a Hardware and a Software Implementations of AES.* FDTC 2012.

[Goryachy, Ermolov 2017] Goryachy, M., Ermolov, M. *How to Hack
  a Turned-Off Computer, or Running Unsigned Code in Intel
  Management Engine.* Black Hat Europe 2017.

[Goryachy et al. 2018] Goryachy, M., Ermolov, M., Sklyarov, D.
  *Intel ME: Flash File System Explained.* Black Hat USA 2018.

[O'Flynn, Chen 2014] O'Flynn, C., Chen, Z. D. *ChipWhisperer:
  An Open-Source Platform for Hardware Embedded Security
  Research.* COSADE 2014.

[Eclypsium 2019–] Eclypsium. *Multiple technical reports on
  Boot Guard, BIOS Guard, BMC, and IPMI attack surfaces.*
  Industry research publications, 2019–present.

[Intel SDM] Intel Corporation. *Intel® 64 and IA-32
  Architectures Software Developer's Manual.* Volume 3,
  Chapters on Boot Guard, BIOS Guard, ACM verification flow.

[JEDEC JESD216] JEDEC Solid State Technology Association.
  *Serial Flash Discoverable Parameters (SFDP), for Serial
  NOR Flash.* JESD216 standard family.

[NewAE Tech docs] NewAE Technology Inc. *ChipWhisperer
  documentation, ChipSHOUTER documentation, Husky technical
  notes.* Open-source instrumentation references, 2014–present.

[Glasgow Interface Explorer] *Glasgow Interface Explorer
  documentation and applet catalog.* Open-source community
  project, github.com/GlasgowEmbedded, 2018–present.

[Microsoft Pluton] Microsoft Corporation. *Pluton Security
  Processor architecture overview.* Microsoft documentation
  + AMD Ryzen PRO 6000 / Intel Core Ultra technical briefs,
  2022–present.

[Trammell Hudson] Hudson, T. *Thunderspy and related Thunderbolt
  / firmware research.* Personal site, ongoing.

---

## Appendix A — Relationship to the portfolio

This writeup is the *content-side* anatomical companion to
**SPIFault**, an engineering project in this same portfolio
that proposes a YAML schema for describing fault-injection
campaigns (Fault Campaign Description Format) plus a Python
validator and simulator backend. The two pieces address the
same research-communication problem from complementary
angles:

- **SPIFault** asks: *how should a researcher describe a
  fault-injection campaign so another researcher can
  reproduce it?* It proposes a schema language and a tooling
  pipeline.

- **This writeup** asks: *what does the surface a campaign
  targets actually look like, anatomically?* It dissects the
  bus, the IC, the boot chain, the four physical fault
  categories, and the empirical literature that has
  measured them.

A researcher who has read SPIFault knows *how* to describe a
campaign. A researcher who has read this writeup knows *what
to describe*. The pair is the portfolio's contribution to the
research-communication problem in fault-injection security.

The wider portfolio cluster the writeup also relates to —
without sitting inside — is the microarchitectural triple
(*Mathematical Collapse*, *Silicon Is the Adversary*,
*No Boundary Below the Architecture*, *Speculation Barrier
Illusion*). Those four pieces dissect the CPU-side
microarchitectural fault surface; this writeup dissects the
firmware-and-flash side. The two surfaces share a substrate
(silicon) and share a structural posture (the architectural
contract is correct; the implementation produces observables
the contract did not enumerate), but they live at different
physical layers and target different defensive infrastructure.

A reader interested in the full portfolio's structural read of
hardware-level fault and side-channel surfaces can read this
writeup alongside the microarchitectural triple; the two
together cover the silicon-and-firmware substrate the OS sits
on top of, end to end.

---

*This writeup is an anatomical reading of the firmware fault-
injection surface, intended to be useful to researchers
arriving at the surface from either the embedded-systems or
the software-security side. With acknowledgement to NewAE
Technology, Riscure, the Eclypsium research group, the
academic communities at UC San Diego, KU Leuven, TU Graz, and
the Centre for Hardware Security at the University of Adelaide
whose patient enumeration of this surface the writeup
synthesizes.*
