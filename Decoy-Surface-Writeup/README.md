---
title: "The Decoy Surface"
subtitle: "Anatomy of Hypervisor-Mediated Kernel Deception"
author: "Tyler (HBO NL Application Portfolio)"
date: "2026-05-17"
keywords: [hypervisor-mediated deception, SSDT, APC injection, decoy device object, kernel rootkit anatomy, kernel honeypot, IRP dispatcher, handle table, manual export resolver, PatchGuard, HVCI, VBS, vulnerable driver blocklist, kernel deception]
companion_writeup: "KDF (Kernel-Mode Deception Framework) — the engineering counterpart"
---

# The Decoy Surface
## Anatomy of Hypervisor-Mediated Kernel Deception

---

## Author's Note

Kernel-mode decoys live at the intersection of two literatures
that rarely cite each other. On one side is the rootkit-persistence
canon: SSDT hooking, IRP dispatcher subversion, manual PE export
walking inside ring 0, APC-queued shellcode delivery. On the other
side is the defensive deception canon: honeypots, honeytokens,
honeyclients, hypervisor-introspection-based decoys, NIST's
deception-as-design-pattern guidance. The two literatures use
different vocabularies, publish in different venues, and frame
their object of study with opposite valence. They are, structurally,
describing the same artifact.

The primitives are identical. A fake device object that an unknown
probe interrogates. An SSDT-routed IOCTL handler that returns
plausible decoy data. A hypervisor-level network listener gated on
a magic trigger, so legitimate traffic flows through unaffected.
An APC queued onto a system-context thread that runs late-bound
resolved code at the next alertable transition. A manual export
walker inside kernel space that rebuilds `ntoskrnl` exports without
calling the documented API. These primitives appear in offensive
campaigns (LoJax, MosaicRegressor, ProjectSauron, the Sednit /
APT28 toolset) and in defensive systems (Honeyd-family kernel
honeypots, hypervisor-introspection-based deception fabrics,
NIST SP 800-160 vol. 2 deception design patterns). The components
are the same; what differs is the disposition of the surrounding
infrastructure — telemetry collection vs. payload delivery,
classification vs. execution, observation vs. action.

This writeup takes a third position. The components are things in
the world. They have protocol, kernel-object, scheduler, and
hypervisor-layer properties. Where the composition is susceptible —
where SSDT writes still resolve at all on a kernel where PatchGuard
should have caught them; where a fake `DEVICE_OBJECT` linked into a
handle table is indistinguishable from a real one to consumers of
`NtQueryObject`; where a queued K-mode APC runs in the target
thread's own stack frame and attributes its work to that thread —
that susceptibility is a structural feature of the composition,
not a moral property of any one component.

The piece that follows reads the substrate. It does not coach an
attacker; it does not equip a defender. It names parts, traces
how they compose, and points at the literature in which each part
was first observed in the wild.

---

## Abstract

This writeup is a structural reading of the kernel-mode decoy
surface as it exists on contemporary Windows systems augmented with
a Type-1 hypervisor (Hyper-V family, VT-x / SVM). It treats the
composition of a hypervisor-mediated network listener, an SSDT hook
routing `NtDeviceIoControlFile` to a fake handler, a fake
`DEVICE_OBJECT` reachable through a sentinel handle value, a
kernel-mode APC carrying late-bound resolved code, and a manual
PE export walker resolving `ntoskrnl.exe` from inside ring 0, as a
single decoy surface — not a chain of independent techniques but a
layered substrate whose susceptibility properties are emergent from
the composition.

The contribution is the unifying anatomical frame plus a layered
map of where the surface sits relative to the IRP dispatcher, the
SSDT, the per-process handle table, and the per-thread APC queue —
and how the hypervisor layer beneath them changes what is
observable from inside the guest. Each technical section closes
with a paragraph naming the assumption that, in the literature, has
been observed to fail and the abstraction at which observation
became newly possible (or newly impossible).

**Keywords:** hypervisor-mediated deception, SSDT, APC injection,
decoy device object, kernel rootkit anatomy, kernel honeypot,
IRP dispatcher, handle table, manual export resolver, PatchGuard,
HVCI.

---

## 1. The Position — Where the Decoy Surface Sits

### 1.1 The layered substrate

The decoy surface that this writeup analyzes is not a single
component. It is a stack of components, each of which provides one
property that the assembled surface depends on. The components are:

1. The **IRP dispatcher**, at the driver layer, which routes
   `IRP_MJ_DEVICE_CONTROL` requests through a driver's
   `MajorFunction[]` table.

2. The **SSDT** (System Service Descriptor Table), at the system
   service dispatch layer, which maps syscall numbers to entry
   points inside `ntoskrnl.exe`.

3. The **handle table**, at the per-process layer, which translates
   process-local `HANDLE` values into kernel object pointers via
   the `EPROCESS.ObjectTable` indirection.

4. The **APC queue**, at the per-thread layer, which holds
   asynchronous procedure-call records that fire when the target
   thread next reaches an alertable wait or a kernel routine that
   drains kernel-mode APCs.

5. Underneath all four, the **hypervisor layer** (VT-x root mode,
   SVM host mode), which observes guest-mode transitions
   (`VMEXIT`s) and which, where present, can mediate network I/O
   and memory access without the guest OS's kernel being a
   participant in the observation.

The decoy surface is the composition of these. Removing any one
layer changes the surface's properties qualitatively. A decoy
device object without an SSDT hook is reachable only through the
normal IRP dispatch path and therefore visible to any tool that
enumerates devices. An SSDT hook without a fake device object
routes real syscalls to a stub that has no meaningful surface to
present. An APC without a resolver chain runs into the wrong
function address as soon as the kernel reloads with a different
KASLR offset. A hypervisor-mediated listener without an in-guest
handler has nothing to deliver received triggers to.

### 1.2 The "hypervisor-mediated" qualifier

The qualifier is precise. It does not mean the decoy lives entirely
in the hypervisor; for current Type-1 hypervisors that is not yet a
production posture for either offense or defense, except in
research systems (Bitdefender HVI, Lares, and the academic
introspection literature stemming from Garfinkel & Rosenblum 2003).
It means the hypervisor is the substrate on which a subset of the
surface's behavior is implemented:

- The **network listener** can run as a virtual-switch extension or
  a hypervisor module, so that packet matching against a magic
  trigger happens *below* the guest's network stack.

- The **VMEXIT discipline** can mask the existence of certain
  in-guest operations from the guest's own telemetry, because
  `CPUID`, `RDTSC`, and certain MSR accesses are intercepted at
  ring -1 and resolved without the guest kernel running.

- The **EPT (Extended Page Tables)** layer can re-map the physical
  memory backing a decoy device object so that introspection from
  inside the guest sees one view and the hypervisor-side tooling
  sees another.

The literature has observed all three in research deployments
(Drakvuf for instance, Lengyel et al. 2014) and in offensive
research (Bluepill-era hypervisor rootkits documented by Rutkowska
2006, and subsequent academic descendants).

### 1.3 Diagram of the layered surface

```
        +----------------------------------------------------+
 user   |  application probing \\?\GLOBALROOT\Device\...     |
 mode   +----------------------------------------------------+
                              |
                              | DeviceIoControl(handle, IOCTL, ...)
                              v
        +----------------------------------------------------+
 ring 0 |  ntdll syscall stub  ->  syscall  ->  ntoskrnl      |
        |  SSDT[NtDeviceIoControlFile]                        |
        |       |                                             |
        |       +-- (hooked) -->  MyIoctlHandler              |
        |                              |                      |
        |                              v                      |
        |  HandleTable[0xDEAD1337] -> FakeDeviceObject        |
        |                              |                      |
        |                              v                      |
        |  FakeDeviceObject.DriverObject.MajorFunction[]      |
        |       |                                             |
        |       +--> StubIRPHandler (returns synthetic data)  |
        |                                                     |
        |  KAPC queued on system thread                       |
        |       |                                             |
        |       +--> KernelRoutine -> late-bound NormalRoutine|
        +----------------------------------------------------+
                              |
                              | VMEXIT (CPUID, MSR, EPT violation)
                              v
        +----------------------------------------------------+
 ring-1 |  VT-x root / SVM host                               |
        |  network listener (vSwitch ext) + EPT remap         |
        +----------------------------------------------------+
```

### 1.4 Structural fact made visible

The decoy surface is not located at any single ring. It is the
*composition relation* between ring 0 objects (device object,
SSDT entry, APC), ring 3 consumers (the probe), and a ring -1
substrate (the hypervisor's introspection and packet-listening
plane). The literature's habit of describing each of these layers
in isolation — "SSDT hooking", "APC injection", "VM introspection" —
obscures the fact that the susceptibility of interest is a property
of the composition, not of any single technique. Removing the
hypervisor leaves an SSDT-only surface that PatchGuard will
ultimately catch; removing the SSDT hook leaves a hypervisor that
sees packets but has no in-guest handler; removing the fake device
leaves a handler with nothing plausible to dispatch on. The
substrate is the relation, not the parts.

---

## 2. The Magic-Triggered Network Listener

### 2.1 The trigger primitive

A magic-triggered network listener is a packet sniffer combined
with a content-gating predicate. Packets that fail the predicate
are passed through to the normal network stack and never produce
any side effect inside the listener; packets that satisfy the
predicate activate the listener's handler. The structural property
of interest is that the listener produces **no observable signal**
on the host until the predicate fires. Until activation, the
component is functionally identical to a pass-through bridge.

The predicate is a layered composition over packet content. The
literature on covert C2 channels (Pasternak et al. 2016, the
DNS-based-C2 surveys, the Domain Generation Algorithm taxonomies)
has documented variations on this composition; the structural
shape is consistent:

| Layer            | What the predicate inspects                          |
|------------------|------------------------------------------------------|
| IP / Port        | Source subnet, destination port (e.g., 4444, 31337)  |
| TCP flags        | Specific flag combinations (e.g., SYN+PSH+URG)       |
| Payload header   | Fixed magic bytes at known offset                    |
| Payload body     | Encrypted blob keyed on a session ID                 |
| Payload checksum | Integrity field over the decrypted body              |
| Timing           | Inter-arrival pattern consistent with a heartbeat    |
| Session          | Per-client session identifier carried in payload     |

The Boolean conjunction of these layers produces a predicate whose
false-positive rate against background internet traffic is, in
practice, vanishingly low. The structural reason is composition:
the entropy of "right port AND right flags AND right header AND
correctly-decrypts-under-session-key AND checksum matches" is the
sum of the per-layer entropies, and even modest per-layer entropies
yield a predicate with $2^{40}$ or more bits of effective false-
positive resistance.

### 2.2 A representative composition

The literature's typical payload format, recovered consistently
across the rootkit-campaign reports (LoJax's C2, MosaicRegressor's
beacon format, the documented Sednit / Sofacy variants), is:

```
+----------+----------+----------+------------------+----------+
| Header   | Session  | OpCode   | Encrypted body   | Checksum |
| 4 bytes  | 8 bytes  | 2 bytes  | variable         | 1 byte   |
+----------+----------+----------+------------------+----------+
```

The header is a fixed ASCII tag (e.g., `"LDR1"`) that gates the
remainder. The session ID doubles as a per-message XOR key — a
common stream-cipher-on-a-budget construction documented in
malware-reversing literature for two decades (Sikorski & Honig
2012, *Practical Malware Analysis*, the chapter on encoding
schemes). The opcode field selects between handler variants
(trigger IOCTL dispatch, queue memory injection, schedule delayed
trigger, emit response packet). The checksum is the byte sum of
the decrypted body modulo 256.

### 2.3 Where the listener sits

The two structural positions for the listener are:

1. **In-guest kernel driver**, hooking the NDIS chain or a
   `WFP` (Windows Filtering Platform) callout. The listener
   observes every packet but is observable in turn: the driver
   image is loaded, its image is signed (or its loading required
   test-signing or an HVCI bypass), and `fltmc` / `wfpcli`
   enumeration will surface it.

2. **In the hypervisor**, as a virtual-switch extension or a
   hypervisor-side packet-tap module. The listener observes every
   packet that crosses the virtual NIC but is **not** observable
   from inside the guest, because the guest's view of its network
   stack is unchanged by the listener's existence. The literature
   on this configuration is sparse outside research deployments;
   Bitdefender HVI is a production instance, and Drakvuf is the
   reference academic introspection platform.

The "hypervisor-mediated" framing means position (2). The reason
the framing matters is that EDR telemetry, AV scanning, and
in-guest forensic tooling all observe at position (1) or above.
A listener at position (2) is invisible to the entire in-guest
telemetry stack, not because it evades anything but because its
events do not propagate into the guest's address space.

### 2.4 Assumption invalidated

The standard threat model for network-based command-and-control
assumes that *some* host-resident telemetry component can observe
packet arrival, packet content, and the dispatch from packet to
in-host action. Magic-triggered listeners at the hypervisor layer
falsify the first conjunct: the packet does not need to arrive at
the host telemetry plane at all, because the trigger predicate is
evaluated at ring -1 and the host-side action is delivered as a
side-channel (an EPT remap, an injected APC, an MSR-mediated VMCALL)
rather than as visible packet payload. The literature has observed
this design pattern in both academic introspection systems (Drakvuf,
Bitdefender HVI) and rootkit campaigns of the post-2018 generation
(MosaicRegressor's UEFI-resident loader, which uses a comparable
substrate at the firmware layer rather than the hypervisor layer).
The asymmetry between in-guest telemetry and below-guest event
plane is the structural fact the surface depends on.

---

## 3. The Fake Device Object

### 3.1 Composition of `MyFakeDeviceObject`

The Windows kernel object that the decoy surface presents to a
probing handle is a structure derived from `DEVICE_OBJECT`. The
relevant fields, from the public Windows Internals documentation
(Russinovich, Solomon, Ionescu, *Windows Internals* 7th ed.
Part 2, chapter 8) and the WDK headers, are:

```c
typedef struct _FAKE_DEVICE_OBJECT {
    DEVICE_OBJECT     Header;          // canonical DEVICE_OBJECT
    PDRIVER_OBJECT    DriverObject;    // back-pointer; populated
    UNICODE_STRING    DeviceName;      // \Device\LoaderComm
    WCHAR             NameBuffer[64];  // backing storage for name
    ULONG             Signature;       // sentinel for self-id
    /* DeviceExtension is the carrier for state */
} FAKE_DEVICE_OBJECT;
```

The structural properties of interest:

- The `Header` is laid out exactly as the kernel I/O manager
  expects. Consumers that walk a device object through
  `IoGetDeviceObjectPointer`, `ObReferenceObjectByHandle`, or
  `NtQueryObject(ObjectNameInformation)` see a well-formed object.

- The `DriverObject` back-pointer is populated with a real or
  synthesized `DRIVER_OBJECT` whose `MajorFunction[]` array is
  populated with stub handlers — at minimum
  `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_DEVICE_CONTROL`,
  `IRP_MJ_CLEANUP`. The stubs return `STATUS_SUCCESS` for create
  and cleanup, and dispatch on `IoControlCode` for device-control.

- The `DeviceName` field carries a plausible device path. The
  literature's pattern is to choose a name that looks similar to a
  legitimate vendor driver (a comparable example is the way
  rootkit campaigns have historically named themselves to imitate
  AV vendors; Kaspersky's *ProjectSauron* report 2016 documents
  this convention).

### 3.2 The handle-table semantic

A handle in Windows is a process-local index into
`EPROCESS.ObjectTable`, which is itself a multi-level table whose
leaves hold `HANDLE_TABLE_ENTRY` records. Each entry carries an
object pointer and an access mask. The Windows Internals 7th ed.
treatment is the canonical reference.

The decoy surface's structural manipulation is to install an entry
at a *specific sentinel handle value* (e.g., `0xDEAD1337`) whose
object pointer references `FAKE_DEVICE_OBJECT` and whose granted
access mask is `0x1FFFFF` (full access). Consumers that present
the sentinel handle to any kernel API that takes a handle —
`NtDeviceIoControlFile`, `NtQueryObject`, `NtClose` — see a
well-formed object reachable through the documented dispatch
path.

The literature has observed handle-table manipulation of this
shape in two distinct contexts:

- **Rootkit persistence**, where the goal is to expose a
  command-and-control surface inside a process without the surface
  appearing in standard handle enumeration (the Uroburos /
  Turla family, documented by G Data 2014, used a comparable
  primitive at the device-object layer).

- **Defensive deception**, where the goal is to expose a decoy
  surface that a probing process will interact with under the
  assumption that the surface is real (the academic literature on
  kernel honeypots — Provos's Honeyd extensions to kernel-resident
  decoys, Spitzner's chapters on high-interaction honeypots —
  describes this primitive in a defender-positive framing).

### 3.3 SSDT routing of `NtDeviceIoControlFile`

The SSDT is the table of syscall handlers in `ntoskrnl.exe`. On
x86-64 Windows, syscall dispatch goes:

```
user-mode application
   |
   v
ntdll!NtDeviceIoControlFile  (syscall stub, places syscall # in EAX)
   |
   v  syscall instruction
KiSystemCall64  (ntoskrnl entry point)
   |
   v
KeServiceDescriptorTable->ServiceTableBase[syscall_index]
   |
   v
ntoskrnl!NtDeviceIoControlFile  (legitimate handler)
```

The structural intervention the decoy surface performs is to
overwrite the SSDT entry at the `NtDeviceIoControlFile` index with
the address of `MyIoctlHandler`. The overwrite requires:

```c
// Disable WP bit (Write Protect) in CR0 so SSDT (read-only by
// default) becomes writable.
KIRQL irql = KeRaiseIrqlToDpcLevel();
ULONG_PTR cr0 = __readcr0();
__writecr0(cr0 & ~0x10000);

InterlockedExchange64(
    &SSDT[SSDT_INDEX_NtDeviceIoControlFile],
    (LONG64)MyIoctlHandler
);

__writecr0(cr0);
KeLowerIrql(irql);
```

This pattern is the canonical SSDT hook documented in rootkit
literature since the early 2000s (Hoglund & Butler, *Rootkits:
Subverting the Windows Kernel*, 2005). The structural facts about
it on contemporary Windows are:

- **PatchGuard** (Kernel Patch Protection, KPP), introduced in
  Windows x64 in 2005, detects SSDT modifications by periodically
  sampling the table against a snapshot taken at boot. The
  detection latency is on the order of minutes; the response is a
  bugcheck (`CRITICAL_STRUCTURE_CORRUPTION`, `0x109`).

- **HVCI** (Hypervisor-protected Code Integrity), available on
  systems with VBS (Virtualization-Based Security) enabled,
  enforces that kernel pages marked executable are read-only and
  signed, which makes the SSDT effectively immutable from inside
  the guest.

- **The Vulnerable Driver Blocklist**, maintained by Microsoft and
  shipped via Windows Update since 2022, lists drivers known to
  enable PatchGuard bypass or HVCI bypass and prevents their
  loading on systems with the policy applied.

The technique therefore requires either a pre-PatchGuard kernel
(historical Windows 7 and earlier, or 32-bit Windows where
PatchGuard does not apply), a system with HVCI disabled (research
labs, virtualization test environments), or the use of a
vulnerable signed driver from the period before the blocklist
caught it. The literature on the latter — Eclypsium's ongoing
"Living off the Land Drivers" reports, the
loldrivers.io project — catalogues several hundred such drivers.

### 3.4 Assumption invalidated

The standard model of handle-based access to kernel objects assumes
that the kernel object reachable through a handle was instantiated
by a recognized driver image that the I/O manager loaded, that the
driver image was signed, and that enumeration tools
(`!devobj` in WinDbg, `WinObj` from Sysinternals, drive enumerators
in EDR products) will see the same set of objects that the kernel
sees. The fake device object falsifies the first conjunct without
falsifying the others: the object is well-formed, it is reachable
through a real (if synthesized) `DRIVER_OBJECT`, and it appears in
enumeration if the enumeration walks the object directory. What it
*lacks* is the provenance — there is no driver image on disk, no
load event in the Plug-and-Play telemetry, no signature chain. The
substrate has the structural property that **the runtime
representation of an object and its provenance are decoupled**, and
the decoy surface depends entirely on that decoupling.

---

## 4. The IOCTL Surface as Decoy Channel

### 4.1 The handler anatomy

The IOCTL handler `MyIoctlHandler` is the function that the SSDT
hook routes `NtDeviceIoControlFile` calls into when the target
handle matches the sentinel. Its anatomy is constrained by the
contract that the I/O manager and its caller share:

```c
NTSTATUS MyIoctlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    PVOID  inputBuffer  = Irp->AssociatedIrp.SystemBuffer;
    PVOID  outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG  ioCtl        = irpSp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_SUCCESS;

    switch (ioCtl) {
    case IOCTL_DECOY_PROBE:
        // structured-but-synthetic response
        RtlCopyMemory(outputBuffer,
                      "{\"driver\":\"LoaderComm.sys\","
                      "\"status\":\"OK\","
                      "\"version\":\"1.0\"}", 47);
        Irp->IoStatus.Information = 47;
        break;

    case IOCTL_DECOY_DISPATCH:
        if (DispatchPredicate(inputBuffer, irpSp->Parameters.
                              DeviceIoControl.InputBufferLength)) {
            QueueLateBoundAPC();   // see Section 5
        } else {
            status = STATUS_ACCESS_DENIED;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
```

### 4.2 Protocol v1.0 — the in-IOCTL handshake

Layered above the IOCTL is a small handshake protocol whose
purpose is to make the surface's responses well-formed enough to
pass plausible-fakeness criteria. The literature's typical shape:

```
Request:
+----------+----------+----------+--------------+
| "LDR1"   | session  | opcode   | encrypted    |
| 4 bytes  | 8 bytes  | 2 bytes  | variable     |
+----------+----------+----------+--------------+

Response:
+----------+----------+----------+--------------+
| "ACKR"   | session  | status   | log entry    |
| 4 bytes  | 8 bytes  | 2 bytes  | variable     |
+----------+----------+----------+--------------+
```

The opcode field selects between handler variants:

| Opcode  | Handler                                          |
|---------|--------------------------------------------------|
| 0x1001  | Trigger IOCTL dispatch path                      |
| 0x1002  | Queue late-bound APC for memory operation        |
| 0x1003  | Schedule delayed trigger via timer DPC           |
| 0x1004  | Return synthetic telemetry to caller             |

The status field on the response uses values chosen to be plausible
under the protocol's published semantics:

| Status  | Meaning (synthetic)                              |
|---------|--------------------------------------------------|
| 0x2000  | DispatchSuccess                                  |
| 0x2001  | AccessDenied                                     |
| 0x2002  | InvalidSession                                   |
| 0x2003  | ChecksumFailure                                  |

### 4.3 The measurable property: plausible-but-synthetic data

The decoy channel's structural property of interest is that it
**accepts well-formed IOCTL requests and returns structured
synthetic data**, so that a probe can be observed and classified
without reaching real kernel state. The literature on high-
interaction honeypots (Spitzner 2002, Provos & Holz 2007, *Virtual
Honeypots*) develops the concept under the name *fingerprintable
fidelity*: the decoy's behavior must be high-fidelity along the
dimensions a probe inspects, and is permitted to be arbitrarily
synthetic along dimensions the probe does not inspect.

The structural challenge of "what dimensions does the probe
inspect" is open. NIST SP 800-160 vol. 2 (Ross et al. 2021,
*Developing Cyber-Resilient Systems*) names it as the *deception
authenticity problem* and lists it among open research questions
for deception-as-a-design-pattern. The academic literature on
honeyfile authenticity (Bowen et al. 2009, *Baiting Inside
Attackers Using Decoy Documents*; Voris et al. 2013,
*Lost in Translation*) develops measures for the file-content
case; the kernel-object analog is less developed.

### 4.4 Assumption invalidated

The standard threat model for IOCTL handlers assumes that an
IOCTL's return data, if the call succeeds, originates from the
device the call was directed at. The decoy surface falsifies this:
the data is synthesized by a handler whose code path never touches
the named device, and the named device may not exist outside the
handle-table entry. The structural fact made visible is that **the
relationship between a successful syscall return and a real-world
device state is, in Windows, mediated entirely by the dispatch
chain**, and the dispatch chain is itself a runtime object whose
integrity is a separate question from the syscall's. The
literature has used this fact constructively (kernel honeypots
deliberately synthesize device state to study probe behavior) and
destructively (rootkit campaigns synthesize device state to deliver
payloads under the cover of a legitimate-looking IOCTL).

---

## 5. APC Injection as Code-Delivery Primitive

### 5.1 The APC primitive

An APC (Asynchronous Procedure Call) is a Windows kernel object
that carries a callback to be executed in the context of a target
thread. The mechanism is documented in the WDK and treated
canonically in Windows Internals 7th ed. Part 1, chapter 8. The
relevant facts:

- Every thread has two APC queues, one for kernel-mode APCs and
  one for user-mode APCs.

- A user-mode APC fires when the target thread reaches an
  alertable wait (`SleepEx(_, TRUE)`, `WaitForSingleObjectEx`,
  `MsgWaitForMultipleObjectsEx`).

- A kernel-mode APC fires at the next kernel routine that drains
  the K-APC queue, which on a running system happens routinely
  during scheduler transitions and during I/O completion.

- APCs are delivered at `APC_LEVEL` IRQL (1), below
  `DISPATCH_LEVEL` (2), so they may take page faults and may
  call most kernel routines.

The structural property of interest is that the APC's callback
runs **on the target thread**, with the target thread's stack,
inside the target thread's process context. From the kernel's
accounting standpoint, work done by the callback is attributed to
the target thread.

### 5.2 The kernel-mode APC code path

The canonical sequence for queuing a K-mode APC, as documented in
WDK and in the rootkit literature (Hoglund & Butler 2005;
Blunden 2012, *The Rootkit Arsenal*; ireland-russinovich's
sysinternals blog series):

```c
PKAPC apc = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'Kapc');

KeInitializeApc(
    apc,
    targetThread,                 // PKTHREAD
    OriginalApcEnvironment,       // KAPC_ENVIRONMENT
    (PKKERNEL_ROUTINE)ApcKernelRoutine,
    (PKRUNDOWN_ROUTINE)ApcRundown,
    (PKNORMAL_ROUTINE)NormalRoutine, // late-bound, see Section 6
    KernelMode,
    NULL                          // NormalContext
);

KeInsertQueueApc(apc, NULL, NULL, 0);
```

Each parameter has a structural role:

- `ApcKernelRoutine` runs first, at `APC_LEVEL`, before the
  normal routine. It is permitted to mutate the APC record — in
  particular, it may set `*NormalRoutine = NULL` to convert a
  normal APC into a "special" APC that has no user-mode follow-up.

- `ApcRundown` runs if the target thread terminates before the
  APC fires. Its job is to release the APC's resources.

- `NormalRoutine` is the callback that does the work. It runs at
  `PASSIVE_LEVEL` (IRQL 0) in the target thread's context.

### 5.3 The disassembled `ApcRundown` and `ShellcodeEntry`

The literature has documented the disassembly pattern in
captured rootkit samples. The Windows Internals canonical shape
matches; representative fragments:

```
ApcRundown:
    sub    rsp, 28h               ; shadow space
    mov    rcx, rcx               ; rcx = APC pointer
    mov    edx, 7063614Bh         ; tag 'pcaK' (little-endian)
    call   cs:__imp_ExFreePoolWithTag
    add    rsp, 28h
    ret
```

The pool tag `'pcaK'` (`0x7063614B`) is the conventional
allocation tag for APC objects in many rootkit samples and in
defensive driver examples alike. Tag values are 4-byte ASCII
identifiers and are visible to `!poolfind` in WinDbg.

The `KernelRoutine` (here called `ShellcodeEntry` in the source
material) follows the Windows x64 calling convention:

```
ShellcodeEntry:
    push   rbx
    sub    rsp, 20h               ; 32-byte home space
    mov    rbx, rcx               ; preserve APC ptr
    test   rdx, rdx               ; NormalRoutine ptr non-null?
    jz     skip_disable
    and    qword ptr [rdx], 0     ; *NormalRoutine = NULL
                                   ; -> "special" APC; no user
                                   ;    mode tail
skip_disable:
    ; ... late-bound NormalRoutine called via Section 6 resolver
    test   rbx, rbx
    jz     epi
    mov    edx, 7063614Bh         ; 'pcaK'
    mov    rcx, rbx
    call   __imp_ExFreePoolWithTag
epi:
    add    rsp, 20h
    pop    rbx
    ret
```

The structural reading: the `KernelRoutine` nullifies the
`NormalRoutine` pointer, which converts the APC into a special
kernel APC with no user-mode portion; it then performs the
intended work; it then frees the `KAPC` allocation with the
`'pcaK'` tag.

### 5.4 Why APC injection works architecturally

The literature has converged on a structural account that does
not depend on the disposition (offense or defense) of the
implementation:

- **Thread attribution.** Work done in an APC's normal routine is
  attributed to the target thread by the scheduler's accounting,
  by ETW events keyed on thread ID, and by stack-walk-based
  telemetry.

- **No code-injection signature.** The APC's `NormalRoutine` is
  a function pointer; it does not require writing executable code
  into the target's address space, only writing a pointer to an
  already-executable address.

- **Alertable wait scheduling.** Many system threads spend most
  of their lifetime in alertable waits (the I/O completion thread
  pool, the worker thread pool), so a queued APC will fire
  quickly without any further intervention.

The technique appears in both literatures:

- **Rootkit campaigns:** the Sednit / APT28 toolset
  (ESET 2016, *En Route with Sednit*), the Hacking Team RCS
  driver components (Galperin et al. 2014), and the Turla
  family (Kaspersky 2014).

- **Defensive systems and academia:** kernel-resident honeypot
  research (e.g., the Sebek family at the Honeynet Project),
  hypervisor-introspection systems that need to inject probes
  into guest threads (Drakvuf, Lengyel et al. 2014), and the
  legitimate kernel subsystems that the APC mechanism was
  designed for in the first place — I/O completion routines,
  thread termination notifications, asynchronous file system
  operations.

### 5.5 Assumption invalidated

The standard model of thread-attributed work in Windows assumes
that the work on a thread's stack reflects the thread's owning
process's intended execution. APC injection falsifies this
locally: work runs on the thread, is attributed to the thread,
and yet originates from a kernel actor that the thread's owning
process did not invite. The literature has observed that this is
not a defect; it is the API working as designed (the I/O manager
and the file system rely on the same mechanism). The structural
fact made visible is that **thread attribution and provenance of
work are decoupled by design**, and the APC queue is the
mechanism of the decoupling.

---

## 6. The Dynamic Resolver Chain

### 6.1 Why late binding is necessary

Two structural facts about contemporary Windows kernels force any
ring-0 code that intends to call kernel routines by name to resolve
those names at runtime rather than at link time:

1. **KASLR (Kernel Address Space Layout Randomization).** Since
   Windows Vista, the kernel's image base is randomized per boot.
   The offset is per-boot stable, but no two boots of the same
   kernel image present the same base.

2. **Version-specific export changes.** The set of exports from
   `ntoskrnl.exe` and the offsets of those exports change across
   Windows builds. An image compiled against one build's offsets
   will not link against another's.

The literature has consistently observed that both legitimate
third-party drivers and rootkit drivers handle this with a
runtime resolver. The mechanism is identical; only the use case
differs.

### 6.2 Kernel base resolution

Two API paths are documented and observed:

```c
// Path A: AuxKlib (documented WDK)
AUX_MODULE_EXTENDED_INFO info;
ULONG bufferSize = 0;
AuxKlibInitialize();
AuxKlibQueryModuleInformation(&bufferSize,
                              sizeof(AUX_MODULE_EXTENDED_INFO),
                              NULL);
// bufferSize now holds required size; allocate and re-query.
PAUX_MODULE_EXTENDED_INFO modules = ExAllocatePool2(
    POOL_FLAG_NON_PAGED, bufferSize, 'bKmN');
AuxKlibQueryModuleInformation(&bufferSize,
                              sizeof(AUX_MODULE_EXTENDED_INFO),
                              modules);
// modules[0].BasicInfo.ImageBase is the ntoskrnl base, by
// convention; the first entry is always the kernel.

// Path B: undocumented Zw / NtQuerySystemInformation
NtQuerySystemInformation(SystemModuleInformation, buf, len, &ret);
// buf is an RTL_PROCESS_MODULES; the first entry's ImageBase is
// likewise the ntoskrnl base.
```

The structural property of interest: both paths converge on the
same datum, the `ImageBase` of the first loaded module. Path A is
documented and supported; path B is widely used but not part of the
documented API.

### 6.3 Kernel routine resolution

Given the kernel base, two paths exist for resolving a routine
by name:

```c
// Documented path: MmGetSystemRoutineAddress
UNICODE_STRING name;
RtlInitUnicodeString(&name, L"KeInitializeApc");
PVOID addr = MmGetSystemRoutineAddress(&name);
```

The documented routine has the limitation that it only resolves
exports of `ntoskrnl.exe` and `hal.dll`. The literature has
observed that drivers needing exports from other kernel modules,
or wanting to avoid the recorded use of `MmGetSystemRoutineAddress`
in driver telemetry, walk the PE export table manually:

```c
// Manual path: walk the PE export directory of ntoskrnl
PVOID ResolveExport(PVOID base, PCSTR name) {
    PIMAGE_DOS_HEADER     dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS     nt  = (PIMAGE_NT_HEADERS)
                                  ((PUCHAR)base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)
        ((PUCHAR)base + nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG names    = (PULONG)((PUCHAR)base + exp->AddressOfNames);
    PUSHORT ords    = (PUSHORT)((PUCHAR)base + exp->AddressOfNameOrdinals);
    PULONG funcs    = (PULONG)((PUCHAR)base + exp->AddressOfFunctions);
    for (ULONG i = 0; i < exp->NumberOfNames; i++) {
        PCSTR exportName = (PCSTR)((PUCHAR)base + names[i]);
        if (strcmp(exportName, name) == 0) {
            return (PUCHAR)base + funcs[ords[i]];
        }
    }
    return NULL;
}
```

This routine is identical in shape to the user-mode `GetProcAddress`
re-implementation in malware loaders documented since the early
2000s (Sikorski & Honig 2012, *Practical Malware Analysis*,
chapter 19). The structural fact: PE export resolution is a
deterministic walk over a published layout, and the walk can be
performed by any code that has read access to the image.

### 6.4 The composition: late-bound APC

Combined with Section 5, the resolver chain produces a late-bound
APC: the `NormalRoutine` field of the `KAPC` record holds an
address resolved at runtime against the running kernel's
`ntoskrnl.exe` export table. The same `KAPC` initialization code
will work across Windows builds, against different kernel images,
because the routine addresses are bound after the relevant images
have loaded.

A typical resolver-state structure:

```c
typedef struct _API_RESOLVED {
    PVOID  KeInitializeApc;
    PVOID  KeInsertQueueApc;
    PVOID  PsLookupProcessByProcessId;
    PVOID  MmMapLockedPagesSpecifyCache;
    PVOID  MmGetSystemRoutineAddressIATSlot;
} API_RESOLVED;

BOOLEAN InitializeApiResolver(API_RESOLVED* api) {
    PVOID ntBase = ResolveKernelBase();
    if (!ntBase) return FALSE;
    api->KeInitializeApc            = ResolveOrFallback(
        ntBase, L"KeInitializeApc", "KeInitializeApc");
    api->KeInsertQueueApc           = ResolveOrFallback(
        ntBase, L"KeInsertQueueApc", "KeInsertQueueApc");
    api->PsLookupProcessByProcessId = ResolveOrFallback(
        ntBase, L"PsLookupProcessByProcessId",
        "PsLookupProcessByProcessId");
    api->MmMapLockedPagesSpecifyCache = ResolveOrFallback(
        ntBase, L"MmMapLockedPagesSpecifyCache",
        "MmMapLockedPagesSpecifyCache");
    // Minimum viable: KeInitializeApc + KeInsertQueueApc resolved.
    return api->KeInitializeApc != NULL
        && api->KeInsertQueueApc != NULL;
}
```

`ResolveOrFallback` first tries `MmGetSystemRoutineAddress`; if
that returns `NULL`, it falls back to the manual export walker.
The "minimum viable" criterion — only the two APC routines must
resolve — reflects the surface's design: if APC injection is
unavailable the surface degenerates to the IOCTL handler alone.

### 6.5 Assumption invalidated

The standard model of statically-linked kernel code assumes that
function addresses are determined at link time and persist across
boots. KASLR and per-build export shifts falsify this assumption
*by design*. The structural consequence is that any kernel code
that needs to call by name must include a resolver, and the
resolver is a recognizable composition (kernel-base lookup +
export-table walk) that appears identically in legitimate drivers
(when calling routines not exported through `MmGetSystemRoutineAddress`)
and in rootkit drivers. The literature has observed that
detection-by-resolver-shape produces high false-positive rates
against legitimate kernel components, which is one reason
defensive telemetry tends to instrument the *behavioural* outputs
(SSDT modifications, suspicious APC queue patterns) rather than
the resolver itself.

---

## 7. What the Literature Has Shown

### 7.1 Rootkit campaigns observed in the wild

The decoy-surface primitives that this writeup has anatomised
appear, in various compositions, across the public corpus of
published rootkit-campaign analyses. The sample below is
illustrative rather than exhaustive.

- **LoJax** (ESET 2018, *LoJax: First UEFI rootkit in the wild,
  courtesy of the Sednit group*). The first publicly-documented
  UEFI-resident rootkit; demonstrates the susceptibility of the
  pre-OS layer to component substitution. The primitive set
  observed includes a kernel-mode dropper installed from the SPI
  flash that uses dynamic resolution against `ntoskrnl` (the
  resolver chain anatomised in Section 6).

- **MosaicRegressor** (Kaspersky 2020, *MosaicRegressor: Lurking
  in the Shadows of UEFI*). UEFI-resident malware that loads a
  Windows-side component via the Intel Management Engine surface.
  The Windows-side component uses an in-driver dispatch table
  comparable to the fake-device-object pattern of Section 3.

- **ProjectSauron / Strider** (Kaspersky and Symantec 2016,
  *The ProjectSauron APT* and *Remsec: A clandestine attacker*).
  Modular APT framework with multiple kernel-resident modules;
  documented to use SSDT-region hooks on some target systems and
  APC-based injection into target processes.

- **Sednit / APT28 / Sofacy toolset** (ESET 2016, *En Route with
  Sednit*; F-Secure 2015, *Sofacy II*). Kernel-resident component
  family used over multiple campaigns; documented to use APC
  injection (Section 5 primitive) and manual export resolution
  (Section 6 primitive).

- **Turla / Uroburos** (G Data 2014, *Uroburos: Highly complex
  espionage software*; Kaspersky 2014, *The Epic Turla*). The
  Uroburos driver implements a hidden device-object surface with
  encrypted virtual filesystem (a structural relative of the
  fake-device-object pattern), demonstrating that the same
  primitive set has been deployed for at least a decade.

- **Equation Group / GrayFish** (Kaspersky 2015, *Equation Group:
  Questions and Answers*). Documented to use hardware-near
  persistence (firmware-resident modules) and kernel-resident
  payload delivery via APC-equivalent primitives on multiple
  operating-system versions.

### 7.2 Defensive deception literature

The same primitive set appears in the defensive honeypot canon,
under a different vocabulary and with the opposite framing of the
surrounding infrastructure.

- **Spitzner (2002), *Honeypots: Tracking Hackers*** (Addison-
  Wesley). The foundational text. Develops the taxonomy of
  low-interaction vs. high-interaction honeypots and names the
  structural property — *deliberate vulnerability with
  comprehensive observability* — that is the structural inverse
  of the rootkit's *deliberate observability gap*.

- **Provos (2004), *A Virtual Honeypot Framework*** (USENIX
  Security 13). The Honeyd system. The relevant structural
  contribution is that honeypot fidelity is layered: each
  protocol layer can be modelled to a different fidelity, and
  the choice is a function of what probes are expected to
  inspect.

- **Provos & Holz (2007), *Virtual Honeypots: From Botnet
  Tracking to Intrusion Detection*** (Addison-Wesley). The
  follow-up monograph; develops kernel-level deception as a
  design pattern, including the use of fake device objects on
  Unix (the `/dev` analog) and the equivalent surface on
  Windows.

- **Bowen, Hershkop, Keromytis, Stolfo (2009), *Baiting Inside
  Attackers Using Decoy Documents*** (SecureComm). Develops the
  *decoy authenticity* problem at the document level; the formal
  framework adapts to the kernel-object case but has not, in the
  public literature, been so adapted.

- **Lengyel, Maresca, Payne, Webster, Vogl, Kiayias (2014),
  *Scalability, fidelity and stealth in the DRAKVUF dynamic
  malware analysis system*** (ACSAC). The reference academic
  system for hypervisor-mediated introspection of Windows
  guests. The DRAKVUF architecture implements observation-via-
  VMCALL at exactly the position this writeup names the
  hypervisor-mediated qualifier for.

- **NIST SP 800-160 vol. 2 (Ross, Pillitteri, Graubart, Bodeau,
  McQuaid 2021), *Developing Cyber-Resilient Systems: A Systems
  Security Engineering Approach*** (NIST). Names deception as
  one of the fourteen techniques contributing to cyber
  resilience, alongside concealment and obfuscation; explicitly
  models the decoy-surface authenticity problem as an open one.

### 7.3 Industry research on kernel observability

- **Microsoft Driver Block List / Vulnerable Driver Blocklist**
  (Microsoft Learn, *Microsoft recommended driver block rules*).
  The list of drivers Microsoft considers vulnerable enough to
  enable kernel-attacker primitives that the OS otherwise
  prevents. The list grew substantially after the introduction
  of HVCI and is shipped with Windows Update.

- **Eclypsium reports (2020-2024)**. Ongoing series of firmware-
  and kernel-driver vulnerability analyses, including the
  *Screwed Drivers* series and subsequent "Living off the Land
  Drivers" follow-ups. Documents the population of signed
  drivers with kernel-attacker primitives.

- **PatchGuard and HVCI specifications** (Microsoft Docs,
  *Device Guard and Credential Guard*, *Hypervisor-protected
  Code Integrity*). The contemporary in-OS countermeasures to
  the SSDT-modification primitive; the technique requires
  either pre-PG kernel or HVCI disabled.

- **Russinovich, Solomon, Ionescu (2017), *Windows Internals*
  7th ed., Parts 1 and 2** (Microsoft Press). The canonical
  reference for the kernel data structures named throughout this
  writeup: `EPROCESS`, `ETHREAD`, `KAPC`, `DEVICE_OBJECT`,
  `DRIVER_OBJECT`, the SSDT, the handle table, the IRP
  dispatcher.

- **Hoglund & Butler (2005), *Rootkits: Subverting the Windows
  Kernel*** (Addison-Wesley). The foundational text on SSDT
  hooking, IRP dispatcher subversion, and kernel-resident
  rootkit primitives. Written before PatchGuard's introduction;
  documents the primitives in their unencumbered form.

- **Blunden (2012), *The Rootkit Arsenal*, 2nd ed.** (Jones &
  Bartlett). The post-PatchGuard treatment; covers the
  primitive set including APC injection, manual export walking,
  and the resolver pattern of Section 6.

### 7.4 Earlier hypervisor-rootkit research

- **Rutkowska (2006), *Subverting Vista Kernel for Fun and
  Profit / Blue Pill*** (Black Hat USA). The hypervisor-rootkit
  proof-of-concept that named the structural possibility this
  writeup's hypervisor-mediation framing depends on.

- **Garfinkel & Rosenblum (2003), *A Virtual Machine
  Introspection Based Architecture for Intrusion Detection***
  (NDSS). The foundational paper on VM introspection as a
  security architecture. Establishes the structural distinction
  between in-guest and below-guest observation.

- **King & Chen (2006), *SubVirt: Implementing malware with
  virtual machines*** (IEEE S&P). The contemporary academic
  treatment of hypervisor-based offense; in dialogue with
  Rutkowska 2006.

### 7.5 The symmetry, explicitly

Across the corpus surveyed above, the technical primitives are
the same set:

| Primitive                                | Offensive corpus    | Defensive corpus      |
|------------------------------------------|---------------------|-----------------------|
| Magic-triggered packet listener          | LoJax, Sednit C2    | Honeyd, Drakvuf       |
| Fake device object in handle table       | Turla, ProjectSauron| High-int. honeypots   |
| SSDT hook of NtDeviceIoControlFile       | Hoglund/Butler 2005 | Pre-PG kernel research|
| Kernel-mode APC for code delivery        | Sednit, Hacking Team| Drakvuf injection     |
| Manual PE export walker in kernel        | MosaicRegressor     | Documented driver use |
| Hypervisor-mediated observation          | Bluepill descendants| Drakvuf, HVI          |

The structural reading: there is no offensive-only or defensive-
only technique on this surface. The surface itself is morally
inert. Disposition is determined by surrounding infrastructure —
where the listener reports to, what the IOCTL handler returns,
who reads the APC's observed work — not by the primitives.

---

## 8. Open Questions

The decoy surface as anatomised in this writeup leaves several
structurally interesting questions open, both for offensive
research (rootkit-evolution forecasting) and defensive research
(deception-fabric design). The list below is illustrative.

### 8.1 Formal models for decoy authenticity

NIST SP 800-160 vol. 2 names the *deception authenticity problem*:
under what formal model can the fidelity of a synthetic kernel
object be made measurable? The document-level case (Bowen et al.
2009) has a partial answer based on stylometric and structural
features of natural-language content. The kernel-object analog
has no equivalent: there is no published metric for "how
plausible is this fake `DEVICE_OBJECT` to a probe with a given
inspection budget?". The literature treats fidelity as
qualitative and probe-specific.

### 8.2 Hypervisor-level observability gap

If telemetry is collected entirely at the in-guest layer — by
ETW, by EDR drivers, by AV scanners — then events that happen
strictly at the hypervisor layer (VMCALL-mediated communication
between a hypervisor-side listener and an in-guest decoy) are
not visible to the telemetry stack. The structural question:
what is the smallest set of in-guest invariants whose violation
would witness hypervisor-mediated activity? The introspection
literature (Garfinkel 2003, Lengyel 2014) approaches this from
the defender's vantage; the offensive literature (Rutkowska 2006
and descendants) approaches it from the contrary vantage. A
unified structural treatment is not, in the public corpus,
present.

### 8.3 PatchGuard / HVCI interaction model

The SSDT-modification primitive at the center of this writeup
is, on contemporary Windows with HVCI enabled, infeasible from
inside the guest. The technique requires either pre-PatchGuard
kernel (Windows 7 and earlier, 32-bit Windows), HVCI disabled
(research lab, virtualization test environments), or a vulnerable
signed driver predating the blocklist. The structural question:
**what does the decoy surface look like when ported to an HVCI-
enforced kernel?** Candidate substitutions — using hypervisor-
mediated EPT remapping to introduce the decoy at ring -1, using
documented filter drivers (`Fltmgr`) instead of SSDT hooks, using
Windows Filtering Platform callouts for the network listener —
each preserve some of the surface's properties and lose others.
A complete porting analysis is open.

### 8.4 ARM TrustZone and equivalent decoy primitives

The Windows-on-ARM kernel and the broader ARM TrustZone ecosystem
have analogues for many of the components anatomised here:
SMC-mediated calls instead of `INT 2E` syscalls, the Secure
Monitor and the TEE as the equivalent of ring -1, the Trusted
Application surface as the equivalent of `DEVICE_OBJECT`. The
structural question: which of the decoy-surface properties
transfer to that substrate, and which are specific to x86-64
Windows? The literature has scattered points (Lipp et al. 2017,
*ARMageddon* and related cache-side-channel work on ARM;
Cerdeira et al. 2020, *SoK: Understanding the Prevailing
Security Vulnerabilities in TrustZone-assisted TEE Systems*) but
no unified treatment of decoy surfaces in that substrate.

### 8.5 Performance overhead of hypervisor-mediated observation

A hypervisor-mediated network listener that runs the trigger
predicate on every packet adds latency to every packet. The
structural question: what is the achievable overhead budget for
a production-deployable hypervisor-mediated observation plane,
and how does that budget scale with predicate complexity? The
performance literature on production hypervisor introspection
(Bitdefender HVI deployment notes, Drakvuf benchmarks) suggests
that small predicates on switched-virtual-network traffic are
feasible at line rate, but the trade-off curve is not, in the
public literature, fully characterized.

### 8.6 Late-binding resolver fingerprintability

The resolver chain (Section 6) is a recognizable composition:
kernel-base lookup via documented or undocumented API, followed
by PE export-directory walk, followed by a small table of
function pointers populated by name. The structural question:
how distinguishable is this composition from legitimate driver
behaviour? Legitimate drivers that use exports not surfaced
through `MmGetSystemRoutineAddress` exhibit the same shape. The
question is whether *behavioural* signatures (e.g., the *combined*
pattern of resolver + SSDT-region write + APC enqueue) yield a
low-false-positive detector. The published telemetry literature
suggests yes; the analysis has not been done in the open.

### 8.7 Composition with confidential-VM substrates

The Confidential-VM substrate (SEV-SNP, Intel TDX) excludes the
hypervisor from the guest's TCB. The structural question: does
this exclusion eliminate the hypervisor-mediated listener
primitive, since the hypervisor can no longer read guest memory?
The answer is partial: SEV-SNP and TDX protect *guest memory
contents* but not *guest I/O*, and a network listener that
inspects packet content post-decapsulation but pre-delivery still
operates on cleartext at the virtual-NIC boundary. A complete
analysis depends on the network-encryption posture of the
specific deployment and on whether IOMMU-protected virtual
devices are in use.

---

## References

1. Spitzner, L. (2002). *Honeypots: Tracking Hackers*.
   Addison-Wesley.

2. Provos, N. (2004). *A Virtual Honeypot Framework*. USENIX
   Security Symposium 13.

3. Provos, N., & Holz, T. (2007). *Virtual Honeypots: From
   Botnet Tracking to Intrusion Detection*. Addison-Wesley.

4. Hoglund, G., & Butler, J. (2005). *Rootkits: Subverting the
   Windows Kernel*. Addison-Wesley.

5. Blunden, B. (2012). *The Rootkit Arsenal*, 2nd ed. Jones &
   Bartlett.

6. Russinovich, M., Solomon, D., & Ionescu, A. (2017). *Windows
   Internals*, 7th ed., Parts 1 and 2. Microsoft Press.

7. Sikorski, M., & Honig, A. (2012). *Practical Malware
   Analysis: The Hands-On Guide to Dissecting Malicious
   Software*. No Starch Press.

8. Garfinkel, T., & Rosenblum, M. (2003). *A Virtual Machine
   Introspection Based Architecture for Intrusion Detection*.
   NDSS.

9. King, S. T., & Chen, P. M. (2006). *SubVirt: Implementing
   Malware with Virtual Machines*. IEEE Symposium on Security
   and Privacy.

10. Rutkowska, J. (2006). *Subverting Vista Kernel for Fun and
    Profit*. Black Hat USA.

11. Lengyel, T. K., Maresca, S., Payne, B. D., Webster, G. D.,
    Vogl, S., & Kiayias, A. (2014). *Scalability, Fidelity and
    Stealth in the DRAKVUF Dynamic Malware Analysis System*.
    ACSAC.

12. ESET (2018). *LoJax: First UEFI rootkit found in the wild,
    courtesy of the Sednit group*. ESET Research White Paper.

13. Kaspersky (2020). *MosaicRegressor: Lurking in the Shadows
    of UEFI*. Securelist.

14. Kaspersky (2016). *The ProjectSauron APT*. Securelist.

15. Symantec (2016). *Remsec: A clandestine attacker*.
    Symantec Security Response.

16. ESET (2016). *En Route with Sednit*, parts 1-3. ESET
    Research White Papers.

17. G Data (2014). *Uroburos: Highly Complex Espionage Software
    with Russian Roots*. G Data SecurityLabs.

18. Kaspersky (2014). *The Epic Turla Operation*. Securelist.

19. Kaspersky (2015). *Equation Group: Questions and Answers*.
    Securelist.

20. Bowen, B. M., Hershkop, S., Keromytis, A. D., & Stolfo, S. J.
    (2009). *Baiting Inside Attackers Using Decoy Documents*.
    SecureComm.

21. Voris, J., Boggs, N., & Stolfo, S. J. (2013). *Lost in
    Translation: Improving Decoy Documents via Automated
    Translation*. IEEE Security and Privacy Workshops.

22. Ross, R., Pillitteri, V., Graubart, R., Bodeau, D., &
    McQuaid, R. (2021). *NIST SP 800-160 vol. 2: Developing
    Cyber-Resilient Systems*. NIST.

23. Microsoft (ongoing). *Microsoft recommended driver block
    rules*. Microsoft Learn / Windows Defender Application
    Control documentation.

24. Microsoft (ongoing). *Hypervisor-protected Code Integrity
    (HVCI)*. Microsoft Docs.

25. Eclypsium (2019). *Screwed Drivers: Signed, Sealed,
    Delivered*. Eclypsium Research.

26. Eclypsium (2020-2024). *Living off the Land Drivers* series.
    Eclypsium Research.

27. Cerdeira, D., Santos, N., Fonseca, P., & Pinto, S. (2020).
    *SoK: Understanding the Prevailing Security Vulnerabilities
    in TrustZone-assisted TEE Systems*. IEEE Symposium on
    Security and Privacy.

28. Galperin, E., Marquis-Boire, M., & Scott-Railton, J. (2014).
    *Police Story: Hacking Team's Government Surveillance
    Malware*. Citizen Lab.

---

## Appendix A — Relationship to the Portfolio

This writeup is the anatomical-research counterpart to the
**KDF (Kernel-Mode Deception Framework)** engineering project
already in the portfolio. KDF is the engineering side: it
implements a subset of the primitives anatomised here as a
defensive deception fabric, with the surrounding infrastructure
oriented toward telemetry capture and probe classification. This
writeup is the research side: it reads the substrate without
committing to either disposition.

The relationship to the other cluster siblings:

- **Microarch-Isolation TEE chapter.** Names the hypervisor as
  the observation substrate underneath confidential-VM and TEE
  workloads. The decoy surface anatomised here uses the same
  layer for a different purpose: introspection-as-deception
  rather than introspection-as-attestation. Section 8.7 of this
  writeup names the open question of how the two substrates
  compose.

- **SPI-Firmware-Anatomy.** Names the pre-OS layer where LoJax-
  family rootkits resident. This writeup's hypervisor-mediated
  qualifier sits one layer up from SPI; together they form a
  ladder of below-OS substrates that decoy surfaces can be
  hosted on.

- **Confidential-VM.** Names the substrate that, where deployed,
  excludes the hypervisor from the guest's TCB and therefore
  qualitatively changes what the hypervisor-mediated listener
  can observe. The decoy surface as anatomised here assumes a
  non-confidential VM substrate; the open question of porting to
  confidential VMs is named in Section 8.7.

- **Speculation Barrier Illusion** and **Silicon Is the
  Adversary**. Name the substrate at which the decoy surface's
  observability properties ultimately bottom out: even a
  hypervisor-mediated listener observing at ring -1 is observable
  through microarchitectural side-channels in principle. The
  decoy surface does not eliminate observation; it relocates
  observation to a layer most production telemetry stacks do not
  reach.

- **Interrupt-Injection-CC.** Names the primitive of using
  interrupt delivery as a covert channel from hypervisor to
  guest. The decoy surface's hypervisor-mediated communication
  with the in-guest IOCTL handler can use interrupt injection as
  one of several signalling channels; the two writeups thus
  describe complementary parts of the same surface.

- **Secure-Boot-Anatomy** and **BitLocker-Anatomy**. Name the
  boot-time integrity substrate that, if violated, permits the
  installation of a kernel-resident decoy surface in the first
  place. The decoy surface assumes that a kernel-mode component
  can be loaded; the secure-boot anatomy names what that
  loading depends on.

- **Rowhammer-Decade** and **GPU-Side-Channel-AI**. Name
  primitive sets at different substrates (DRAM, GPU memory);
  the decoy surface anatomised here is a CPU/hypervisor-substrate
  parallel. The portfolio's structural argument is that decoy
  surfaces, side channels, and integrity-substrate analyses are
  three facets of the same low-level-security object.

- **Mathematical Collapse** and **BFS 2019**. Name the
  mathematical and physical-process substrates underneath the
  software stack. The decoy surface is the most software-
  flavored writeup in the cluster; it sits at the top of the
  ladder the other writeups descend.

The portfolio's coherence is that each writeup names one
substrate, anatomises one decoy or attack surface on that
substrate, and points at the substrates above and below it. This
writeup is the kernel-and-hypervisor rung.

---
