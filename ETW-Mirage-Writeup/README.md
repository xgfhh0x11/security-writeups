---
title: "The ETW Mirage: When .NET Telemetry Is Repurposed as a Security Boundary"
subtitle: "A trust-boundary audit of CLR ETW, the two structural bypasses, and the defensive program that has to follow"
author: Tyler
date: "2026-05-14"
keywords: [ETW, .NET, CLR, EtwEventWrite, COMPlus_ETWEnabled, trust boundary, telemetry, user-mode reporting, AMSI, defensive detection]
---

# The ETW Mirage
## When .NET Telemetry Is Repurposed as a Security Boundary

---

## Abstract

Event Tracing for Windows (ETW) is the canonical telemetry channel for
the .NET runtime: assembly loads, JIT compilations, method invocations,
garbage-collection cycles, and managed exceptions are all reported
through a single CLR-side `EtwEventWrite` chain that crosses into the
kernel via `NtTraceEvent`. Endpoint-detection-and-response (EDR)
platforms, SIEMs, and managed-detection vendors increasingly consume
this stream as if it were a *security control*. It is not. ETW was
specified as a *debugging and profiling* primitive in the late 1990s
[Park & Buch 1999; Pietrek 2005]; its trust boundary lies entirely
inside user mode, on the side of the very process it claims to
observe. This writeup audits that boundary. We walk the CLR's ETW
registration path through `clr.dll`, locate the two structural
bypasses (`COMPlus_ETWEnabled=0` at configuration time and inline
patching of `ntdll!EtwEventWrite` at runtime), and show that neither
is a "bug in ETW" — both are direct consequences of *trusting
user-mode self-reporting as a security boundary*. We then survey the
four detection vectors a defender can put against the bypass class
(environment-variable monitoring, memory-integrity scanning,
statistical anomaly detection, kernel-side callback validation), and
show that each has a structural failure mode of its own. The writeup
closes with the generalization that matters for blue-team
architecture: every monitoring primitive whose execution depends on
the cooperation of the monitored entity — ETW, AMSI, user-mode API
hooks — is in the same category. The defensive program that follows
is multi-source telemetry with kernel-side validation, not a tighter
single channel.

**Keywords:** ETW, .NET, CLR, EtwEventWrite, COMPlus_ETWEnabled,
trust boundary, telemetry, user-mode reporting, AMSI, layered
detection.

---

## 0. Introduction: The Mirage

A defender opens the EDR console. The .NET process under
investigation has emitted zero `MethodLoad`, `AssemblyLoad`, or
`JITCompilationStarted` events for forty-five seconds. The console
reports the channel as healthy. The defender concludes: *the process
is idle*.

The process is, in fact, mid-way through a credential-harvesting
operation.

This is the ETW mirage. The defender saw a clean telemetry channel
where there was no channel at all. Not because the channel was
faulty, but because the channel's existence depends on the
cooperation of the very thing it monitors — and that cooperation
can be withdrawn in two structurally distinct ways, before any
event is ever generated.

The thesis of this writeup:

> *ETW was specified as a debugging and profiling primitive. It has
> been repurposed by the security industry as a behavior-monitoring
> primitive. The repurposing is structurally unsound: it places the
> trust boundary inside the monitored process, where the monitored
> process can simply opt out. Every CLR ETW "bypass" is an instance
> of that structural fact.*

The argument proceeds in seven movements:

- **§1** — what ETW actually is, architecturally, and where its
  trust boundary lies;
- **§2** — the configuration-level opt-out (`COMPlus_ETWEnabled=0`)
  and why it is the cleanest known bypass;
- **§3** — the runtime-level opt-out (inline patching of
  `EtwEventWrite`) and why it works even when the configuration
  path is locked down;
- **§4** — the hybrid layer (selective filtering, IAT hooking,
  post-creation environment spoofing) that defenders should expect
  in 2026-class operators;
- **§5** — the four classes of detection a defender can field, and
  the structural failure mode of each;
- **§6** — the generalization: ETW, AMSI, and user-mode API hooks
  are the *same architectural mistake*;
- **§7** — what a sound defensive program looks like once the
  mirage is named.

The writeup does not present any novel evasion technique. The
contribution is the trust-boundary framing, which makes the existing
techniques structurally legible and lets defenders allocate scarce
detection budget against the *category* rather than the *instance*.

---

## 1. What ETW Actually Is

Before any bypass, the architecture has to be drawn precisely. The
common diagrams in the security literature treat ETW as a black
box; the bypasses are illegible until the box is opened.

### 1.1 The CLR ETW data flow

A managed-code event — an `AssemblyLoad`, a JIT compilation, a GC
generation transition — travels through this sequence inside a
.NET process:

```
.NET application
       │
       ▼
clr.dll  (event source)
       │   AssemblyLoad / MethodLoadVerbose / GCStart_V1 / …
       ▼
clr.dll → _McGenEventWrite  (manifest-based wrapper)
       │
       ▼
ntdll.dll → EtwEventWrite     (user-mode entry point)
       │
       ▼─── syscall boundary ──────────────────────────
       │
       ▼
ntoskrnl.exe → NtTraceEvent   (system call handler)
       │
       ▼
ETW Controller (kernel)
       │
       ├─→ in-kernel buffers
       └─→ consumer sessions (Event Viewer, wevtutil, EDR agents)
```

The CLR ETW provider GUID is
`{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}` — registered at runtime
startup if and only if a configuration flag named `ETWEnabled`
resolves to non-zero (see §2).

### 1.2 Where the trust boundary lies

There are three boundaries in this diagram, and only one of them is
defensive:

| Boundary                              | What it actually defends                                |
|---------------------------------------|---------------------------------------------------------|
| `application ↔ clr.dll`               | Managed-code API surface; nothing security-relevant.    |
| `clr.dll ↔ ntdll.dll`                 | Loader / API namespace; nothing security-relevant.      |
| **`ntdll.dll ↔ kernel (syscall)`**    | The Ring-3 / Ring-0 transition. The only real boundary. |

The syscall is the only place the kernel can validate anything
about the call. Everything *above* the syscall — the CLR's choice
to call `EtwEventWrite`, `ntdll`'s choice to invoke the syscall, the
contents of the event payload — is executed by the monitored process
*in its own address space*, with its own privileges. The kernel sees
only what arrives at `NtTraceEvent`. It does not see what *did not*.

This is the architectural premise that the next two sections exploit
and that §5–§7 try to defend against.

### 1.3 The architectural premise: ETW was a debugging tool

ETW shipped in Windows 2000 [Park & Buch 1999], several years before
EDR and the modern threat model existed. Its original consumers were:

- performance counters (PerfMon);
- profilers (Visual Studio profiler, later xperf);
- system-administration tools (Event Viewer, `wevtutil`);
- the kernel logger (`logman`).

In every one of these consumers, the monitored process is *assumed
to be cooperative* — a developer profiling their own application, an
administrator collecting logs for an SLA report. Adversarial
non-cooperation is not in the threat model.

`COMPlus_ETWEnabled` exists precisely because the original threat
model did not include adversaries: it is a developer toggle to
*disable* runtime telemetry when it interferes with profiling
something else. In 2026 it is the cleanest available evasion. In
1999 it was a flag in a developer's `set` command.

The security industry has spent two decades retrofitting ETW into a
threat-detection role it was never designed for. The bypasses below
are not vulnerabilities in ETW. They are the absence of properties
ETW was never asked to provide.

---

## 2. The First Crack: `COMPlus_ETWEnabled` (Configuration-Level Opt-Out)

### 2.1 Configuration resolution order

The CLR resolves `ETWEnabled` from three sources, in decreasing
precedence:

```
1.  Environment variable:  COMPlus_ETWEnabled
2.  Registry:              HKLM\Software\Microsoft\.NETFramework
                              \ETWEnabled  (DWORD)
3.  Default:               1  (enabled)
```

The code path inside `CLRConfig::GetConfigValue`, simplified:

```c
BOOL CLRConfig::GetConfigValue(LPCWSTR name) {
    WCHAR  envVarName[256];
    LPWSTR envValue;

    swprintf(envVarName, L"COMPlus_%s", name);
    envValue = _wgetenv(envVarName);
    if (envValue != NULL)
        return _wtoi(envValue);          // env wins

    /* …registry lookup against
       HKLM\Software\Microsoft\.NETFramework\<name>… */

    return 1;                            // default: enabled
}
```

This pattern — env-then-registry-then-default — is canonical for the
CLR and is documented in `clrconfigvalues.h` in the open-source
CoreCLR repository [CoreCLR 2024].

### 2.2 What `ETWEnabled = 0` actually disables

The CLR's runtime-startup path, simplified:

```c
BOOL shouldRegisterETW = CLRConfig::GetConfigValue(L"ETWEnabled");

if (shouldRegisterETW == 0) {
    /* ETW registration entirely skipped.
       No provider is ever registered with the kernel. */
    goto skip_etw_registration;
}

_McGenEventRegister(&CLRProviderGuid,     /* runtime telemetry  */);
_McGenEventRegister(&RundownProviderGuid, /* shutdown rundown   */);
/* …additional providers… */

skip_etw_registration:
    /* CLR initialization continues without ETW.
       The runtime is fully functional. */
```

When `ETWEnabled = 0` the runtime initializes normally. Garbage
collection works. JIT compilation works. Exception handling works.
What does *not* happen:

- `_McGenEventRegister` is never called;
- The CLR provider GUID is never advertised to the kernel ETW
  subsystem;
- No event-emit callbacks are ever wired into the runtime's hot
  paths;
- `MethodLoadVerbose_V1`, `AssemblyDCStart_V1`, `ModuleLoad_V1`,
  `GCStart_V1`, `ExceptionThrown_V1` are *not emitted*, not
  filtered, not suppressed — they simply do not exist as events.

From the kernel's vantage, the process is a .NET runtime with no
registered ETW provider. This is *indistinguishable from a perfectly
legitimate developer scenario*: a profiling tool that wants ETW
disabled to reduce overhead, a benchmarking harness, a constrained
embedded host. The kernel has no way to tell the difference.

### 2.3 The clean-bypass property

This bypass has four properties that, taken together, make it the
strongest known evasion class:

1. **No memory modification.** No page is made writable. No
   instructions are patched. Memory-integrity scanners find
   nothing to flag because nothing is modified.

2. **No anomalous syscall trace.** The bypass operates by *not
   making syscalls*. There is no `NtTraceEvent` invocation to
   detect, because the provider was never registered.

3. **Configuration parity with legitimate use.** The exact same
   flag is used by the .NET team to recommend disabling ETW in
   performance-sensitive scenarios. A blanket "alert on
   `COMPlus_ETWEnabled=0`" rule fires on legitimate developer
   workstations.

4. **Configurable at three layers.** Environment, registry, or
   default — each with its own forensic visibility profile (see
   §4.3 for the spoofing trick that further hides the env layer).

### 2.4 Why this is a configuration property, not a vulnerability

This is the key reframing. `COMPlus_ETWEnabled=0` is not a bug in
.NET. It is the *documented behavior* of a configuration flag whose
purpose is exactly to disable the channel. Microsoft has not patched
it because there is nothing to patch. Removing the flag would break
legitimate developer scenarios that the flag exists to support.

The "vulnerability", if there is one, is in the *defender's mental
model*: a defender who treated ETW as a security boundary did so
without authority from the architects of ETW. The architects shipped
a `COMPlus_*` switch that disables it.

The defender's choice now is to either accept that telemetry is
optional (and adjust the detection program accordingly — see §5 and
§7) or to add an *independent* mechanism that does not depend on the
monitored process's cooperation (kernel-side callbacks, AMSI which
has its own analogous problems, or external behavioral telemetry).

---

## 3. The Second Crack: Inline Patching of `EtwEventWrite`

If a defender locks down `COMPlus_ETWEnabled` (e.g., by enforcing
the registry value and monitoring environment-variable
modifications), the attacker still has the runtime-level path.

### 3.1 `ntdll!EtwEventWrite` as the choke point

The CLR's event-emit chain routes through `ntdll!EtwEventWrite` for
every event. The function's signature:

```c
ULONG EtwEventWrite(
    REGHANDLE              RegHandle,
    PCEVENT_DESCRIPTOR     EventDescriptor,
    ULONG                  UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData
);
```

Disassembly (x86, simplified):

```
ntdll!EtwEventWrite:
    8B FF                mov     edi, edi          ; NOP / hotpatch slot
    55                   push    ebp
    8B EC                mov     ebp, esp
    B8 XX XX XX XX       mov     eax, <syscall #>
    BA XX XX XX XX       mov     edx, <handler addr>
    FF 12                call    [edx]              ; NtTraceEvent
    5D                   pop     ebp
    C2 14 00             ret     14h
```

On x86 the function uses `stdcall`-style cleanup (`ret 14h` pops
five 4-byte arguments from the stack). On x64 it uses the
fast-call convention; the caller cleans up, so a simple `ret` (`C3`)
suffices.

### 3.2 The patch

Overwriting the first instruction(s) with an immediate return
short-circuits every subsequent call:

```c
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
FARPROC pEtw    = GetProcAddress(hNtdll, "EtwEventWrite");

DWORD oldProtect;
VirtualProtect(pEtw, 4, PAGE_EXECUTE_READWRITE, &oldProtect);

#ifdef _WIN64
    memcpy(pEtw, "\xC3", 1);                /* ret               */
#else
    memcpy(pEtw, "\xC2\x14\x00", 3);        /* ret 14h           */
#endif

VirtualProtect(pEtw, 4, oldProtect, &oldProtect);
```

After the patch, the function returns immediately. The CLR-side
event chain executes — `_McGenEventWrite` populates its argument
struct, calls into `EtwEventWrite` — and the function returns
without ever reaching the `call [edx]` that would dispatch to
`NtTraceEvent`. The kernel sees nothing.

### 3.3 Why it works: below the kernel's observability horizon

The kernel does not inspect user-mode instruction memory for
modifications. It validates *what arrives at the syscall layer*. A
patched `EtwEventWrite` simply does not arrive. From the kernel's
side, the absence of an event is exactly the absence the
`ETWEnabled=0` path produces — *no provider, no event*.

```
User mode:
┌──────────────────────────────────────┐
│  ntdll.dll                            │
│  ┌──────────────────────────────────┐ │
│  │ EtwEventWrite:                   │ │
│  │   ret 14h         ← patched      │ │
│  │   <rest is unreachable>          │ │
│  └──────────────────────────────────┘ │
│  clr.dll → calls EtwEventWrite →     │
│            returns immediately       │
└──────────────────────────────────────┘
            │
            │ (no syscall is made)
            │
            ▼
Kernel mode:
┌──────────────────────────────────────┐
│  NtTraceEvent: never invoked          │
│  ETW Controller: receives no event   │
└──────────────────────────────────────┘
```

The patch sits entirely below the kernel's observability surface. A
kernel-mode component *can* be written to verify the integrity of
user-mode `ntdll` pages periodically (see §5.2), but the cost is
high, the timing window is wide, and the attacker can re-patch on
demand. Memory-integrity scanning is a defensive option, not a
defensive solution.

### 3.4 Trade-offs against the configuration bypass

| Property                  | `COMPlus_ETWEnabled=0`  | `EtwEventWrite` patch          |
|---------------------------|-------------------------|--------------------------------|
| Memory modification       | None                    | Yes (one or three bytes)        |
| Forensic artifact         | Environment variable    | Modified page in `ntdll`        |
| Detection by integrity    | Not applicable          | Periodic compare against on-disk |
| Timing of application     | Pre-CLR-init            | After process start (any time)  |
| Granularity               | All-or-nothing          | All-or-selective (cf. §4.1)     |
| Legitimacy parity         | High (documented flag)  | Low (no legitimate inline patch) |

Memory patching is the *less clean* of the two bypasses, and that
matters: defenders concentrating detection budget at the wrong end
(memory-integrity scanning, when the actual operator is using the
config bypass) get the worst of both — they pay the cost and miss
the attack.

---

## 4. The Hybrid Layer: What Operators Actually Do in 2026

The configuration and runtime bypasses are the canonical pair. Real
operators rarely use either in its textbook form. The 2026
defender's threat model is the hybrid.

### 4.1 Selective filtering: don't disable, just exclude

A blanket-off `EtwEventWrite` is visible to a careful statistical
detector (§5.3). A patched-but-selective hook is not:

```c
ULONG WINAPI HookedEtwEventWrite(
    REGHANDLE              RegHandle,
    PCEVENT_DESCRIPTOR     Desc,
    ULONG                  UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData)
{
    /* Inspect the event descriptor. The CLR provider's event IDs
       are well known; AssemblyLoad is a particularly sensitive
       event for tools like SharpHound, Rubeus, Seatbelt. */
    if (Desc->Id == AssemblyDCStart_V1) {
        LPWSTR name = ExtractAssemblyName(UserData);

        if (wcsstr(name, L"SharpHound") ||
            wcsstr(name, L"Rubeus")     ||
            wcsstr(name, L"Seatbelt")) {
            /* Pretend the event was emitted; return success. */
            return ERROR_SUCCESS;
        }
    }

    /* Let everything else through. The defender's statistical
       baseline sees a normal stream of GC / JIT / loader events. */
    return OriginalEtwEventWrite(RegHandle, Desc, UserDataCount, UserData);
}
```

The point of this design is to *preserve statistical legitimacy*.
The defender's anomaly detector counts events per second, computes
a baseline, and watches for sharp drops. A selective filter keeps
the average rate inside the normal envelope and only excises the
events that would name the offensive tools.

### 4.2 IAT hooking instead of inline patching

Inline patching modifies `ntdll`'s `.text` section. Modern
integrity-checking EDRs scan this region. The Import Address Table
(IAT) of the caller — `clr.dll` — is a softer target:

```
Before:
  clr.dll IAT[ntdll.dll → EtwEventWrite] = &ntdll!EtwEventWrite

After:
  clr.dll IAT[ntdll.dll → EtwEventWrite] = &HookedEtwEventWrite
```

The IAT entry is a pointer in the importing module's data section.
Modifying it is allowed by every loader on Windows; many legitimate
libraries (instrumentation tools, profilers, AV/EDR themselves)
rewrite IAT pointers as part of normal operation. An IAT redirect is
*harder to flag* than a `.text` patch because the page protection
state of the IAT page is normally writable already during loader
operation, and many IAT entries are written by legitimate hooks
during process initialization.

The trade-off is precision: IAT hooks only intercept calls *from
that specific module*, so an attacker hooking `clr.dll`'s IAT does
not catch direct calls to `EtwEventWrite` from other DLLs the
process may load. For the .NET case, `clr.dll` is the only emitter,
so this limitation does not bite.

### 4.3 Post-creation environment-variable spoofing

The configuration bypass (§2) suffers from a forensic problem: any
process-creation hook (`CreateProcessA/W`, ETW's
`Microsoft-Windows-Kernel-Process` channel) records the environment
block at process start. `COMPlus_ETWEnabled=0` in that block is
sometimes the only indicator the attacker left behind.

The mitigation, on the attacker's side, is to *set the variable
after process creation*:

```
EDR view (at CreateProcess):
  envblock = { …no COMPlus_ETWEnabled… }     ← passes inspection

Target process (post-creation, via injected code):
  SetEnvironmentVariableA("COMPlus_ETWEnabled", "0");
  /* Now spawn or trigger the .NET runtime, which reads the
     env-var during CLR init. */
```

The CLR is initialized lazily by the runtime; it reads the
configuration *when it initializes*, not at process creation. A
shellcode that sets the variable any time before CLR init achieves
the bypass while keeping the process-creation hook's view of the
environment clean.

The pattern generalizes to "anti-forensic environment manipulation"
— the same technique applies to `COMPlus_AMSIEnabled`,
`DOTNET_StartupHooks`, and any other CLR-init configuration the
attacker can mutate between process start and CLR init.

---

## 5. The Defender's Four Detection Vectors (and Their Failure Modes)

A blue-team architecture facing the bypass class has four
non-overlapping vectors. Each has a structural limitation that
prevents it from being the *single* answer.

### 5.1 Environment-variable monitoring

**Mechanism.** Hook `SetEnvironmentVariableA/W` and
`NtSetInformationProcess`; record every `COMPlus_*` modification.
Optionally enforce a registry-pinned default of `ETWEnabled=1`.

**Failure mode.** Process-creation environment blocks can carry the
variable *without* a runtime `SetEnvironmentVariableA` call — the
parent process can simply spawn with a custom env block. The
post-creation spoofing trick (§4.3) defeats it from the other
direction. And, fundamentally, the variable being set is *not the
attack*; the attack is the bypass. The variable is a forensic
artifact, present in some attack flows and absent in others.

### 5.2 Memory-integrity scanning

**Mechanism.** Periodically read user-mode `ntdll` pages, compare
against an on-disk reference, alert on any modification of
`EtwEventWrite`'s prologue.

**Failure mode.** Periodic means there is a window between scans
during which the attacker can patch, fire the .NET workload, and
restore. The window is bounded by scanner cadence; faster cadence
costs CPU. The defender is paying a continuous cost to close a
window that the attacker can adapt to in seconds. Worse, the scan
is itself observable — an attacker who can detect the scanner
(timing-based or hook-based) can restore the byte just before each
scan and re-patch right after.

### 5.3 Statistical anomaly detection

**Mechanism.** Baseline each .NET process's expected ETW event
rate; alert when a process emits zero or anomalously few events
relative to its peers and history.

**Failure mode.** Selective filtering (§4.1) preserves the
baseline. The detector fires on the all-or-nothing operator and
misses the precise one. And the false-positive rate on legitimate
"low ETW" scenarios (constrained runtime, benchmarking harness,
explicit performance config) is non-trivial; a tuning that catches
the all-off operator without flooding the analyst with legitimate
disables is hard to achieve without per-tenant calibration.

### 5.4 Kernel-side provider-registration callbacks

**Mechanism.** Register a kernel-mode callback that fires whenever
an ETW provider is registered, and audit which providers are
registered for each .NET process. The CLR provider GUID
(`{e13c0d23-…}`) should be present for every running .NET
runtime.

**Failure mode.** This is the strongest of the four — the kernel
sees `ETWEnabled=0` as the absence of a provider registration —
but it has its own problems. It is high cost (a kernel callback
per provider event across the entire system), it requires a signed
kernel driver, and it only detects the *configuration* class of
bypass; an attacker who registers the provider and then patches
`EtwEventWrite` passes this check. The kernel-callback detector is
necessary but not sufficient.

### 5.5 The architectural reading

No single one of the four is sound. Each one closes a window the
others don't. The defensive program has to deploy *all four*, accept
the layered cost, and treat the union of their alerts as a
*candidate set* requiring analyst review — not as an oracle.

The architectural reason for this state of affairs is the one
stated in §1: ETW's trust boundary is on the wrong side of the
process. No detector that lives only inside the monitored process
can be the answer. The only sound primitives are the ones that
live outside it (kernel callbacks, external behavioral telemetry,
hardware-rooted attestation in the limit), and those primitives
have their own costs and their own — different — failure modes.

---

## 6. The Generalization: ETW Is Not the Only Mirage

The trust-boundary failure described above is *not specific to
ETW*. It is a category. Every monitoring primitive whose execution
depends on the cooperation of the monitored entity lives in the
same category:

| Primitive                          | Boundary                          | Bypass class                                   |
|------------------------------------|-----------------------------------|------------------------------------------------|
| ETW                                | user-mode in the monitored process | `COMPlus_ETWEnabled=0`; `EtwEventWrite` patch  |
| AMSI                               | user-mode in the monitored process | `AmsiScanBuffer` patch; provider DLL hijack    |
| User-mode API hooks (EDR)          | user-mode in the monitored process | Hook removal; direct syscall; unhook from `ntdll.dll` on disk |
| `SetThreadContext` notifications   | user-mode subsystem               | Suspended-process hollow; manual mapping       |
| .NET assembly load logging         | CLR, user-mode                    | `Assembly.Load(byte[])` from memory; loader hooks |

The shared property: in each case, the entity that emits the
telemetry is *the same entity the telemetry is meant to monitor*.
The entity has the privilege to modify the telemetry. The kernel
either does not validate the telemetry's emission, or validates only
that the emission *that arrived* is well-formed — never that the
emissions which *did not arrive* should have.

This is sometimes phrased as "user-mode telemetry is not a security
control". The phrasing is correct but soft. The precise claim is:
*a control whose execution can be removed by the monitored entity
is not a security boundary*. It is a debugging convenience. The
fact that real attackers exploit it daily is the operational
confirmation; the architectural reading is the prior.

### 6.1 What makes a real security boundary

The contrast helps. The Ring-3 / Ring-0 transition *is* a security
boundary, because:

- the kernel side does not run in the user process's privilege;
- modifications to the kernel side require Ring-0, which is
  exactly the privilege the boundary is meant to defend;
- the kernel can validate inputs at the syscall layer
  irrespective of what user-mode did.

The ETW emit path is the inverse on all three counts. The CLR runs
in the same process. Modifications to `clr.dll`, `ntdll.dll`, or
the configuration require nothing beyond the user-mode process's
own privileges. The kernel cannot validate emissions; it only
processes what arrives.

That is why the bypasses exist, and that is why patching them
individually does not move the architecture.

---

## 7. The Sound Defensive Program

Once the mirage is named, the defensive program rewrites itself.
The compressed shape:

1. **Stop trusting any single user-mode telemetry source as a
   security boundary.** Treat ETW, AMSI, and user-mode hook
   outputs as *signal*, not as *control*. A process emitting these
   signals is *probably* benign; a process not emitting them is
   *not necessarily* malicious, but it is *unobserved*, which is a
   distinct epistemic state from "observed and clean".

2. **Field independent telemetry sources.** Network telemetry, file
   I/O telemetry from a kernel-mode driver, process-creation
   telemetry from PsSet… kernel callbacks, registry telemetry,
   thread-creation events — each lives in a different trust
   boundary. The intersection of their reports is harder to
   bypass than the union of any one.

3. **Use the kernel-side primitives that exist.** Kernel ETW
   sessions (consumed by a kernel-mode driver) cannot be modified
   by user-mode patching. ProcessAccess, ThreadCreate, ImageLoad,
   and RegistryCallback notifications are kernel-side and survive
   user-mode tampering. They have their own costs (driver
   signing, kernel ABI risk) but they are the only options that
   live in the right boundary.

4. **Baseline statistically, not absolutely.** A given process's
   ETW emission rate is informative if you have the baseline. The
   selective-filter operator (§4.1) can defeat a binary "0 events =
   bad" rule; a rolling-window distribution model with anomaly
   detection across multiple features (event count, event-type
   diversity, peer comparison) is harder to fool.

5. **Treat configuration as part of the threat surface.**
   `COMPlus_ETWEnabled` is a configuration value with a security
   consequence. So is `COMPlus_AMSIEnabled`. So are
   `DOTNET_StartupHooks`, `LD_PRELOAD` analogues, `_NT_DEBUGGER`
   variables. A defender's configuration-management program
   should enforce policy on these and detect drift.

6. **Acknowledge the boundary in the threat narrative.** When a
   detection-program owner cannot truthfully say "this process
   would have emitted X events if it were doing Y", the program
   should not pretend otherwise. Documenting the gap is the first
   defensive step; *closing* it is the next several.

The architectural reading the writeup has built toward is that
points 1–6 are not a wish-list of improvements; they are the
*minimum* required posture once the mirage is named. Defenders who
stop at point 1 buy little; defenders who reach point 6 have
internalized the boundary.

---

## 8. Conclusion

Five compressed claims:

1. **ETW was designed as a debugging primitive.** The trust
   boundary it provides was never intended to be a security
   boundary. Two decades of repurposing have papered over this,
   but the architectural fact remains.

2. **There are two structural bypasses.** `COMPlus_ETWEnabled=0`
   disables registration at configuration time; an inline patch of
   `ntdll!EtwEventWrite` disables emission at runtime. Each is a
   direct consequence of the trust boundary lying inside the
   monitored process.

3. **The bypasses are not vulnerabilities in ETW.** They are
   features of ETW that defenders have repurposed away from. The
   "fix" is not to patch ETW; the fix is to stop trusting ETW as a
   security boundary.

4. **No single detection vector closes the bypass class.**
   Environment monitoring, memory-integrity scanning, statistical
   anomaly detection, and kernel-side callbacks each close a
   distinct window and leave the others open. The defensive
   program has to deploy all four and treat their union as a
   candidate set.

5. **The category is wider than ETW.** AMSI, user-mode API hooks,
   and any monitoring primitive whose execution can be removed by
   the monitored entity are in the same category. The sound
   defensive posture is multi-source telemetry with kernel-side
   validation, not a tighter single channel.

The defender's first move, when reading a CVE advisory that names
an ETW or AMSI bypass, should be: *which trust boundary did this
break, and was it ever a trust boundary?* If the answer is "no", the
CVE is a re-publication of an architectural fact. The fact does not
get more or less true by being numbered.

> *A debugging channel that defenders treat as a security control
> is not a control. It is a mirage with a CVE.*

---

## References

[1] Park, M., Buch, J. *Event Tracing in Windows.* Microsoft Systems
    Journal, vol. 14, 1999. (Original ETW design intent.)

[2] Pietrek, M. *Improve Debugging and Performance Tuning with ETW.*
    MSDN Magazine, April 2005.

[3] Microsoft Corporation. *Event Tracing for Windows.* Windows
    Driver Documentation, 2024. https://learn.microsoft.com

[4] Chester, A. ("XPN"). *Hiding your .NET — ETW.*
    XPN Security blog, 2020. https://blog.xpnsec.com/hiding-your-dotnet-etw/

[5] Chester, A. ("XPN"). *Hiding your .NET — COMPlus_ETWEnabled.*
    XPN Security blog, 2021.
    https://blog.xpnsec.com/hiding-your-dotnet-complus-etwenabled/

[6] CoreCLR project. *clrconfigvalues.h.* dotnet/runtime GitHub
    repository, accessed 2026.
    https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/clrconfigvalues.h

[7] Russinovich, M., Solomon, D., Ionescu, A., Yosifovich, P.,
    Cohen, S. *Windows Internals, 7th Edition, Part 1 & 2.*
    Microsoft Press, 2017/2022. (Authoritative reference for the
    ETW kernel architecture, including `NtTraceEvent` and the
    in-kernel event dispatcher.)

[8] Microsoft Corporation. *Event Tracing API Reference:
    EtwEventWrite.* Windows API Documentation, 2024.

[9] MITRE Corporation. *ATT&CK Technique T1562.006 — Impair
    Defenses: Indicator Blocking.* MITRE ATT&CK Framework, 2024.

[10] MITRE Corporation. *ATT&CK Technique T1112 — Modify Registry.*
     (Used by the registry path of `ETWEnabled`.)

[11] Microsoft Security Response Center. *Microsoft Defender for
     Endpoint AMSI integration.* Public documentation, 2023.
     (Comparative analogue for the same trust-boundary class.)

[12] Hosseini, S. et al. *AMSI Bypass: A Survey.* (Survey of the
     same architectural failure mode applied to AMSI.) 2023.

[13] Microsoft Corporation. *Detecting and Preventing PowerShell
     Downgrade Attacks.* Threat Intelligence Center, 2017. (Early
     public acknowledgement of the user-mode trust-boundary problem
     in adjacent telemetry channels.)

[14] National Security Agency. *Hardening .NET on Microsoft Windows.*
     Technical Report, 2023.

[15] Cabrera, A. *Catching .NET ETW evasion using kernel-mode
     callbacks.* Threat-research blog post, 2022. (One of the
     concrete kernel-side detection prototypes referenced in §5.4.)

---

## Appendix A — Where this writeup fits in this collection

This writeup is one of three "trust-boundary autopsies" in the
collection. The three argue, at three different layers, that
defenders routinely treat as security controls things that were
never designed to be security controls — and that the bypasses
follow structurally rather than incidentally.

- [[Speculation Barrier Illusion]] — `lfence` proves a property
  under the ISA-level model; reading it as a microarchitectural
  guarantee is a category error.
- [[Mathematical Collapse]] — six instances of the same trust-vs.-
  silicon mismatch across the abstraction stack.
- **This writeup** — ETW proves a "telemetry was emitted" property
  if and only if the monitored process cooperates; reading it as
  a security control is the same category error one layer up.

Read together, the three are intended to demonstrate that the same
architectural diagnostic transfers across microarchitecture, formal
verification, and security telemetry — and that the defensive
response (multi-source, kernel-side validation, layered
observation) is the same in all three.

The writeup is also the theoretical companion to two engineering
artefacts in this collection:

- [[KSIF]] — *defensive*, kernel-state semantic-integrity
  framework. The kernel-side primitive §7 calls for, in code.
- [[Kernel-Mode Deception Framework]] (KDF) — the observability
  asymmetry of §6 turned inside out: a defender's *deception*
  layer that exploits the same trust-boundary that attackers do.

---

*Written under the constraint that the defender's first move,
faced with a new attack on a telemetry channel, is to ask which
trust boundary the channel was ever supposed to defend.*
