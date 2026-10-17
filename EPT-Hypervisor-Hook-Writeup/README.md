---
author: Utku Erol
title: "Ring -1 Memory Control: EPT-Based Hooking via Intel VT-x"
date: 2026-05-17
tags: [hypervisor, intel-vtx, ept, vmcs, vmexit, stealth-hook, kernel-rootkit, ring-minus-one]
cluster: kernel-memory-model
related:
  - DMA-IOMMU-Writeup
  - LBR-Hijacking-VMExit-Writeup
---

## Author's Note

The standard mental model of privilege separation is a vertical stack: user-mode at Ring 3, kernel at Ring 0. The OS is the arbiter of memory — it decides what processes can see and execute. This model is correct within its scope.

The scope ends at the hypervisor layer.

Intel VT-x introduces a hardware execution mode below Ring 0 — non-root mode for guests, root mode for the hypervisor. From root mode, the hypervisor controls Extended Page Tables: the second-level address translation that maps guest physical addresses to host physical addresses. An OS running inside a VM believes it controls memory. The hypervisor decides what that memory actually is, and whether it can be executed at all.

This writeup builds an EPT-based hooking framework from first principles: VMXON, VMCS configuration, EPT table construction, EPT violation handling, and GUEST_RIP redirection. The goal is to demonstrate that interception at the hypervisor layer is architecturally distinct from and undetectable by any mechanism available at Ring 0. The guest OS cannot observe that it is being monitored — not because detection is difficult, but because the monitoring operates in a different execution domain entirely.

---

## Abstract

Extended Page Tables (EPT) are Intel VT-x's mechanism for nested address translation: a second page table hierarchy, controlled exclusively by the hypervisor, that translates guest physical addresses (GPA) to host physical addresses (HPA). A guest OS manages its own virtual-to-physical translation (VA → GPA), unaware that a second translation step (GPA → HPA) is being applied by the hypervisor underneath.

By clearing the Execute permission bit on a target page's EPT entry, the hypervisor causes any execution attempt on that page to generate an EPT violation VM-Exit, transferring control to the hypervisor's exit handler with the guest's full CPU state visible. From there, `GUEST_RIP` can be redirected to arbitrary shellcode — intercepting a syscall, logging its arguments, modifying its behavior, or replacing it entirely — before resuming the guest via `VMRESUME`.

This writeup covers the complete implementation: CPU VT-x initialization (VMXON, CR4.VMXE, feature control MSR), VMCS construction with host and guest state fields, 4-level EPT table construction with identity mapping, EPTP encoding and VMCS registration, VM-Exit handler with EPT violation routing, and a syscall argument logger shellcode that captures RAX, RCX, RDX, R8, R9 into shared memory. The technique requires no kernel patches, no SSDT modifications, no inline hooks, and leaves no artifacts observable by the guest OS.

---

## §1 — Address Translation: Three Levels

On a system running without a hypervisor, memory access follows one translation:

```
Guest VA ──[ CR3 + page tables ]──▶ Physical Address ──▶ DRAM
```

On a VT-x system with EPT enabled, there are two:

```
Guest VA ──[ CR3 + guest page tables ]──▶ Guest Physical Address (GPA)
                                                         │
                                         [ EPT (hypervisor page tables) ]
                                                         │
                                                   Host Physical Address (HPA)
                                                         │
                                                        DRAM
```

The guest OS manages only the first translation — VA → GPA. It has no visibility into the second. From the guest's perspective, its physical addresses are real. From the hypervisor's perspective, those physical addresses are virtual — another layer of indirection that the hypervisor controls.

The EPT table is the hypervisor's CR3. It is not stored in any register visible to the guest. It is referenced via the EPTP field in the VMCS, a structure whose existence is not accessible to the guest OS.

This architectural separation is the foundation of EPT-based hooking: the guest cannot detect a hook because the hook exists in a data structure the guest cannot read, modified by code the guest cannot execute, triggered by a hardware mechanism the guest cannot intercept.

---

## §2 — VT-x Hardware Initialization

Before any VM can run, the CPU must be placed in VMX root mode. This is a hardware state transition, not just a software configuration.

### 2.1 VT-x Feature Check

```c
int cpuInfo[4] = {0};
__cpuid(cpuInfo, 1);
// ECX bit 5 = VMX support
if (!(cpuInfo[2] & (1 << 5))) {
    return STATUS_NOT_SUPPORTED;
}
```

### 2.2 IA32_FEATURE_CONTROL MSR (0x3A)

This MSR determines whether VMX is permitted outside SMX (trusted launch). The BIOS typically sets it and locks it with bit 0. The relevant check:

| Bit | Meaning |
|---|---|
| 0 | Lock bit — if set, MSR is read-only |
| 1 | VMX enable inside SMX |
| 2 | VMX enable outside SMX (required for our use) |

If bit 0 is set and bit 2 is clear, VMX is disabled at the firmware level. Most systems with virtualization enabled in BIOS will have bits 0 and 2 set.

### 2.3 CR4.VMXE

The CR4 register's VMXE bit (bit 13) must be set before VMXON:

```c
__writecr4(__readcr4() | (1ULL << 13));   // CR4.VMXE = 1
```

### 2.4 VMXON Region

A 4KB-aligned page, initialized with the VMX revision ID from `MSR_IA32_VMX_BASIC (0x480)`, is required:

```c
PHYSICAL_ADDRESS maxAddr = { .QuadPart = MAXLONGLONG };
PVOID vmxonRegion = MmAllocateContiguousMemory(0x1000, maxAddr);
RtlZeroMemory(vmxonRegion, 0x1000);

ULONGLONG vmxBasic = __readmsr(0x480);
*(ULONG*)vmxonRegion = (ULONG)(vmxBasic & 0xFFFFFFFF);  // revision ID in [31:0]

PHYSICAL_ADDRESS vmxonPhys = MmGetPhysicalAddress(vmxonRegion);
__vmx_on(&vmxonPhys.QuadPart);
```

After `VMXON`, the CPU is in VMX root mode. No guest exists yet — only the hypervisor infrastructure.

---

## §3 — VMCS: The Guest/Host State Container

The Virtual Machine Control Structure is a CPU-managed data structure that stores all state needed to run a guest and return to the hypervisor on VM-Exit. It is accessed exclusively through `VMREAD` and `VMWRITE` instructions — no direct pointer access.

Three operations initialize a VMCS:
1. `VMCLEAR` — reset to a clean state
2. `VMPTRLD` — load as the current VMCS
3. `VMWRITE` — configure all fields

### 3.1 Host State Fields

The host state is where the CPU returns after a VM-Exit. All host segment registers, control registers, and the host RIP (the VM-Exit handler entry point) must be set:

```c
__vmx_vmwrite(0x6C00, __readcr0());     // HOST_CR0
__vmx_vmwrite(0x6C04, __readcr3());     // HOST_CR3
__vmx_vmwrite(0x6C08, __readcr4());     // HOST_CR4
__vmx_vmwrite(0x6C16, (ULONG64)HandleVMExit);  // HOST_RIP — exit handler entry
__vmx_vmwrite(0x6C14, GetHostRsp());    // HOST_RSP — hypervisor stack
```

### 3.2 Guest State Fields

The guest state represents the CPU context the guest will execute with. For a Type-2 hypervisor (running on top of an existing OS), this captures the current CPU state and runs the existing OS as a guest:

```c
__vmx_vmwrite(0x6800, __readcr0());     // GUEST_CR0
__vmx_vmwrite(0x6802, __readcr3());     // GUEST_CR3
__vmx_vmwrite(0x6804, __readcr4());     // GUEST_CR4
__vmx_vmwrite(0x681E, GuestRip);        // GUEST_RIP — where guest resumes
__vmx_vmwrite(0x6820, GuestRsp);        // GUEST_RSP
```

### 3.3 Control Fields

Pin-based and CPU-based VM-execution controls determine what events cause VM-Exits:

```c
// CPU_BASED_VM_EXEC_CONTROL: enable secondary controls
__vmx_vmwrite(0x4002, AdjustMsr(0x482, CPU_BASED | ACTIVATE_SECONDARY));

// SECONDARY_CPU_EXEC_CTRL: enable EPT
__vmx_vmwrite(0x401E, AdjustMsr(0x48B, ENABLE_EPT));
```

Without `ENABLE_EPT` in the secondary controls, EPT is inactive and there is no second-level translation. Every EPT violation and hook depends on this bit being set.

---

## §4 — EPT Table Construction

The EPT hierarchy mirrors the standard x64 page table structure with an additional dimension: it translates GPA (what the guest thinks is physical) to HPA (the actual host physical address).

```
EPTP → PML4 → PDPT → PD → PT → Host Physical Page
        [9]    [9]    [9]  [9]       [12 offset bits]
```

Each entry in the table carries permission bits:

| Bit | Permission | Effect if cleared |
|---|---|---|
| 0 | Read | EPT violation on guest read |
| 1 | Write | EPT violation on guest write |
| 2 | Execute | EPT violation on guest execute ← hook trigger |

### 4.1 Identity Mapping

For the hypervisor to be transparent to the guest, the EPT maps each GPA to the same HPA — identity mapping:

```c
for (ULONG64 i = 0; i < PAGE_COUNT; i++) {
    eptPt[i] = (i * PAGE_SIZE) | 0x7;   // R=1, W=1, X=1, mapped identity
}
```

All pages start as fully accessible. The hook is installed by selectively clearing the X bit on target pages.

### 4.2 EPTP Encoding

The EPTP is a 64-bit value written to the VMCS `EPT_POINTER` field (`0x201A`). Its format (Intel SDM Vol. 3C §29.6):

| Bits | Field | Value |
|---|---|---|
| 2:0 | Memory type | 6 = Write-Back |
| 5:3 | Page-walk length − 1 | 3 → 4-level paging |
| 11:6 | Reserved | 0 |
| 51:12 | PML4 physical address | aligned to 4KB |
| 63:52 | Reserved | 0 |

```c
ULONG64 eptp = eptPml4Phys.QuadPart;
eptp |= 6;          // memory type: write-back
eptp |= (3 << 3);   // page-walk length: 4 levels (3+1)

__vmx_vmwrite(0x201A, eptp);   // VMCS_EPT_POINTER
```

EPTP is the hypervisor's equivalent of CR3 — it roots the second-level translation hierarchy. If this value is wrong, every guest memory access will generate an EPT fault and the system will triple-fault. Alignment and encoding must be exact.

---

## §5 — Installing the Hook: X-Bit Removal

Installing an EPT hook on a target address is one operation: clear the Execute bit in that address's PT entry.

```c
VOID EptSetExecuteHook(ULONG64 targetGpa) {
    ULONG64 ptIndex  = (targetGpa >> 12) & 0x1FF;
    ULONG64 pdIndex  = (targetGpa >> 21) & 0x1FF;
    ULONG64 pdptIndex = (targetGpa >> 30) & 0x1FF;
    ULONG64 pml4Index = (targetGpa >> 39) & 0x1FF;

    PULONG64 pt = GetPtForAddress(pml4Index, pdptIndex, pdIndex);
    pt[ptIndex] &= ~(1ULL << 2);   // clear X bit
}
```

After this modification, any attempt by the guest to execute code at `targetGpa` will cause an EPT violation VM-Exit. The guest did not change. The guest's page tables did not change. The hook is invisible to the guest because it lives in the EPT, which only the hypervisor can read.

---

## §6 — VM-Exit Handler: Intercepting and Redirecting

When the guest attempts to execute a hooked page, the CPU:
1. Stops executing the guest
2. Saves guest state to the VMCS
3. Loads host state from the VMCS
4. Jumps to `HOST_RIP` — the exit handler

The exit handler reads `EXIT_REASON` to determine why the exit occurred:

```c
VOID HandleVMExit(VOID) {
    ULONG64 exitReason = 0;
    __vmx_vmread(0x4402, &exitReason);

    if ((exitReason & 0xFFFF) == 0x30) {   // 0x30 = EPT Violation
        ULONG64 guestRip = 0;
        __vmx_vmread(0x681E, &guestRip);    // GUEST_RIP: what the guest tried to execute

        DbgPrint("[EPT Hook] Execution trapped at GPA: 0x%llx\n", guestRip);

        if (guestRip == TargetSyscallAddress) {
            // Redirect to shellcode
            PVOID shellcode = GetSyscallLoggerShellcode();
            __vmx_vmwrite(0x681E, (ULONG64)shellcode);
        }
    }

    __vmx_vmresume();   // return to guest (with modified RIP if redirected)
}
```

The handler reads `GUEST_RIP` — the instruction the guest was about to execute. If it matches the hooked syscall address, `GUEST_RIP` is overwritten with the shellcode address. On `VMRESUME`, the guest continues — but executing the shellcode instead of the original code.

The exit reason `0x30` (EPT violation) is distinct from CPUID exits, I/O exits, MSR exits, and interrupt exits. A minimal hypervisor that only monitors a single syscall can handle only this exit reason and forward all others unchanged.

---

## §7 — Syscall Argument Logger Shellcode

The shellcode placed at the redirected RIP captures the syscall context — which syscall was called and with what arguments — before jumping to the original handler.

On Windows x64, the syscall calling convention passes:
- `RAX` — syscall number
- `RCX` — first argument
- `RDX` — second argument
- `R8`  — third argument
- `R9`  — fourth argument

The shellcode writes these into a shared memory region readable by the hypervisor:

```asm
; Syscall argument logger — assembled shellcode
; Shared memory at guest kernel VA 0xFFFF800012345000

mov  [0xFFFF800012345000], rax   ; syscall ID
mov  [0xFFFF800012345008], rcx   ; arg 1
mov  [0xFFFF800012345010], rdx   ; arg 2
mov  [0xFFFF800012345018], r8    ; arg 3
mov  [0xFFFF800012345020], r9    ; arg 4
mov  [0xFFFF800012345028], rip   ; return address (original syscall entry)

jmp  [OriginalSyscallAddress]    ; continue to real handler
```

The hypervisor's host code periodically reads the shared memory region to retrieve logged syscall invocations. Neither the guest OS nor any security software running inside the guest can observe this — the shared memory page is allocated and mapped by the hypervisor, and the logging occurs during a VM-Exit when the guest is suspended.

---

## §8 — The Stealth Argument

Standard kernel hooks operate within the guest's execution context and are detectable by:
- SSDT scanning (looking for modified function pointers in the System Service Descriptor Table)
- Inline hook detection (looking for `JMP` or `INT3` at the start of NTAPI functions)
- PatchGuard (Microsoft's kernel integrity monitor, which periodically verifies critical structures)
- Driver scanning (looking for unknown loaded modules in the kernel driver list)

EPT hooks are undetectable by all of these mechanisms for a structural reason: they do not exist in the guest's address space. The SSDT is unmodified. No function has a `JMP` at its entry point. PatchGuard's code integrity checks scan the guest's page tables and find all pages intact. The EPT — the table that controls what those pages actually contain — is not accessible to any code running at Ring 0 or below.

The detection surface for EPT hooks is limited to:
1. **Timing anomalies** — VM-Exits add latency. RDTSC measurements inside a VM will reveal hypervisor presence if compared against bare-metal baselines.
2. **Hypervisor presence flags** — CPUID leaf 0x40000000 can expose hypervisor vendor strings. A hypervisor that does not clear these will be detected.
3. **Physical vs virtual RDTSC** — A guest's TSC can be offset from the host's. Hardware-level tools can sometimes detect this.

None of these reveal the specific hook location or what is being intercepted. They reveal only that a hypervisor is present — which may be expected in cloud or virtualized environments.

---

## §9 — The Three-Level Address Control Hierarchy

This writeup, combined with the DMA/IOMMU writeup, completes a picture of physical memory control across three hardware layers:

```
Level 1 — CPU MMU (CR3 / page tables)
  Controls: VA → PA for CPU instruction execution
  Owner: Operating system (Ring 0)
  Failure mode: User-mode code reads kernel memory if page tables misconfigured

Level 2 — IOMMU (DMA remapping)
  Controls: device PA → real PA for DMA operations
  Owner: OS / firmware (BIOS/UEFI)
  Failure mode: PCIe devices read arbitrary RAM if IOMMU disabled

Level 3 — EPT (Extended Page Tables)
  Controls: GPA → HPA for all guest memory operations
  Owner: Hypervisor (Ring -1)
  Failure mode: Hypervisor can redirect any guest memory access invisibly
```

Each level is invisible to the level above it. The OS cannot inspect IOMMU remapping tables directly. A guest OS cannot inspect EPT tables at all. A process cannot inspect the OS's page tables without kernel privileges.

Security claims made at one level hold only within that level's enforcement domain. An EPT-based hook violates every security assumption made by the guest OS — not by breaking any of the OS's mechanisms, but by operating outside the scope of those mechanisms entirely.

---

## §10 — Related Writeups

**`DMA-IOMMU-Writeup`** — IOMMU is Level 2 of the three-tier control hierarchy described in §9. EPT is Level 3. Both demonstrate that the OS's memory isolation model is complete only within the CPU's execution domain, and both show attack surfaces that operate below that domain. The IOMMU writeup attacks from the hardware bus direction; this writeup attacks from the hypervisor layer.

**`LBR-Hijacking-VMExit-Writeup`** — LBR hijacking also manipulates VM-Exit handling, but at the branch history record layer rather than the memory translation layer. Both writeups share the structural insight that the VM-Exit mechanism is a general-purpose interception point: any event configured to cause a VM-Exit transfers execution to the hypervisor with the guest's full CPU state, making it a surveillance and manipulation primitive for any observable guest behavior.

The overarching claim: **privilege level is not a security boundary on a hypervisor-capable system unless the hypervisor is trusted.** Ring 0 is trusted by Ring 3. Ring -1 is trusted by Ring 0. The only layer without a layer below it is the hardware itself — and even hardware is subject to firmware-level manipulation (UEFI, SMM), which runs at an even lower privilege level than the hypervisor.

---

*Research context: educational walkthrough of Intel VT-x EPT-based interception mechanics. Implementation demonstrated on Type-2 hypervisor skeleton. All techniques require VMXON access (Ring 0 entry point) and BIOS-level VT-x enablement.*
