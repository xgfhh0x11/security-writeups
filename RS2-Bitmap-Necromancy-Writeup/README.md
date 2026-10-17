---
author: Utku Erol
title: "Grave Robbery: UAF Heap Reuse and the RS2 Bitmap Necromancy Technique"
date: 2026-05-17
tags: [windows-kernel, uaf, gdi, desktop-heap, win32k, pvscan0, heap-grooming, lpe]
cluster: kernel-memory-model
related:
  - GDI-Bitmap-Abuse-Writeup
  - Double-Fetch-Race-Writeup
---

## Author's Note

Windows 10 RS2 (Creators Update, 2017) patched the most direct path to `pvScan0` corruption in the classic GDI Bitmap Abuse technique by adding bounds checks that restricted GDI read/write operations to desktop heap addresses. The patch was geometrically correct: it closed the specific overwrite path.

What the patch did not address was the desktop heap's allocation reuse behavior. The kernel's session pool allocates GUI objects in predictable slot patterns. When a window is created and destroyed, its `tagCLS.lpszMenuName` allocation is freed — but the slot returns to the free list at the same address. If a bitmap is allocated into that slot before another GUI object claims it, the bitmap inherits a `pvScan0` pointer that points into a region the attacker already knows about.

This is Use-After-Free through heap recycling, not through dangling pointer dereference. The dead object's body is not re-accessed — a new object is allocated *in the same grave*. The new object's internal pointer lands in the former occupant's territory. This is the technique named Bitmap Necromancy: raising a useful primitive from the address space of a dead object.

---

## Abstract

RS2 Bitmap Necromancy achieves the same arbitrary kernel read/write primitive as classic GDI Bitmap Abuse (Manager/Worker `pvScan0` redirect via `Set/GetBitmapBits`) but bypasses RS2's bounds-checking patch by constructing the `pvScan0` corruption through desktop heap reuse rather than direct overwrite.

The chain: create a window with a large controlled `lpszMenuName` buffer (0x8F0 bytes) to claim a predictable session pool slot; leak the kernel address of that allocation via the desktop heap delta (`ulClientDelta = kernel_heap_base − user_heap_base`); repeat create/destroy cycles until the kernel assigns the same address to `lpszMenuName` twice consecutively, confirming deterministic slot reuse; destroy the window to free the slot; immediately allocate a bitmap sized to fill the same slot (0x701 × 2 × 1bpp); the bitmap's `SURFOBJ.pvScan0` ends up at `freed_lpszMenuName_base + 0x50` — a predictable kernel address within the formerly controlled allocation.

The resulting `pvScan0` value points into kernel-accessible memory at a known offset, restoring the arbitrary R/W primitive without any direct `pvScan0` overwrite. Two `lpszMenuName` address leak methods are demonstrated: TEB-based desktop heap traversal and runtime `user32!HmValidateHandle` discovery via `IsMenu()` bytescan.

---

## §1 — The RS2 Patch and What It Left Open

Classic GDI Bitmap Abuse required an existing kernel write primitive to overwrite `SURFOBJ.pvScan0` with an arbitrary kernel address. After that overwrite, `SetBitmapBits` and `GetBitmapBits` became arbitrary kernel R/W.

Windows 10 RS2 added a check in the GDI subsystem's bitmap read/write paths: if `pvScan0` points outside the desktop heap's committed range, the operation is rejected. The kernel bounds the R/W against the desktop heap's address range. A `pvScan0` pointing at `HalDispatchTable` would no longer produce a write — it would fail the bounds check.

The patch's scope: it prevents *using* a corrupted `pvScan0` to access memory outside the desktop heap. It does not prevent:
1. Leaking the desktop heap's base address
2. Constructing a `pvScan0` that points within the desktop heap but at a location the attacker controls
3. Using desktop heap reuse to place a bitmap where a controlled allocation previously lived

RS2 Necromancy targets item 3. The `pvScan0` it constructs passes the RS2 bounds check because it does point into the desktop heap — specifically, into the slot where the attacker's controlled `lpszMenuName` buffer once lived.

---

## §2 — The Desktop Heap: Shared Ground Between User and Kernel

The Windows desktop heap is a memory region allocated for each window station (e.g., `WinSta0\Default`) and shared between user-mode and kernel-mode. GUI objects — windows (`tagWND`), classes (`tagCLS`), menus, bitmaps — are stored here. The same physical memory is mapped at different virtual addresses in user and kernel mode, creating an address delta:

```
ulClientDelta = kernel_heap_base − user_heap_base
```

For any GUI object:
```
KernelAddress = UserModeAddress + ulClientDelta
UserModeAddress = KernelAddress − ulClientDelta
```

This delta is constant within a session, making kernel-to-user address translation deterministic once the delta is known. The delta leaks `pvScan0` locations, `tagCLS` pointers, and `tagWND` pointers — all derivable from user-mode-readable desktop heap memory without any kernel vulnerability.

### Key Desktop Heap Structures

`tagWND` (kernel window object, accessible at `UserAddress + ulClientDelta`):
- `+0x00` — `THRDESKHEAD` (contains `pSelf`, the kernel pointer to this `tagWND`)
- `+0x20` — internal heap base pointer (used to derive `ulClientDelta`)
- `+0xA8` — `pcls` → pointer to `tagCLS` (RS2+)

`tagCLS` (window class object):
- `+0x90` — `lpszMenuName` → pointer to the class's menu name string in session pool

The `lpszMenuName` allocation is in the session paged pool, sized to the string passed at `RegisterClass` time. With a controlled 0x8F0-byte buffer, this becomes a predictable 4KB-adjacent allocation — the target for UAF reuse.

---

## §3 — Leaking `ulClientDelta` and the Target Address

Two methods exist to leak the desktop heap delta.

### Method 1: TEB Direct Traversal

```c
// TEB layout (partial)
TEB + 0x800 → Win32ClientInfo
TEB + 0x828 → pointer to user-mode desktop heap base
*(TEB + 0x828) + 0x28 → kernel desktop heap base

ulClientDelta = kernel_heap_base − user_heap_base
```

In PowerShell:

```powershell
$TEBBase = NtQueryInformationThread → TebBaseAddress
$TEB_UserKernelDesktopHeap = Marshal::ReadInt64($TEBBase + 0x828)
$TEB_KernelDesktopHeap     = Marshal::ReadInt64($TEB_UserKernelDesktopHeap + 0x28)
$ulClientDelta = $TEB_KernelDesktopHeap - $TEB_UserKernelDesktopHeap
```

With `ulClientDelta` known, any user-mode desktop heap address translates to the corresponding kernel address.

### Method 2: `HmValidateHandle` Runtime Discovery

`user32!HmValidateHandle` is an undocumented internal function that translates a GUI handle (`HWND`, `HBITMAP`, `HMENU`) to the user-mode desktop heap pointer for that object. It is called internally by `IsMenu()`:

```asm
USER32!IsMenu:
  mov     dl, 2                    ; TYPE_MENU = 2
  call    USER32!HmValidateHandle  ; returns user-mode tagWND/tagMENU pointer
  test    rax, rax
  setne   cl
```

`HmValidateHandle` is not exported, but its address can be derived at runtime: scan `IsMenu()` bytewise for the `0xE8` call opcode, read the 4-byte relative displacement, compute the target address. This bypasses ASLR because the relative offset from `IsMenu` to `HmValidateHandle` is fixed within a module version, and the module is already mapped.

```powershell
for ($i = 0; $i -lt 50; $i++) {
    if ([Marshal]::ReadByte($lpIsMenu + $i) -eq 0xE8) {
        $offset = [Marshal]::ReadInt32($lpIsMenu + $i + 1)
        $lpHMValidateHandle = $lpIsMenu + $i + 5 + $offset
        break
    }
}
$HMValidateHandle = [Marshal]::GetDelegateForFunctionPointer(
    $lpHMValidateHandle,
    [HMValidateHandle])
```

Invoking it directly:

```powershell
$lpUserDesktopHeapWindow = $HMValidateHandle.Invoke($WindowHandle, 1)  # TYPE_WINDOW = 1
$ulClientDelta = [Marshal]::ReadInt64($lpUserDesktopHeapWindow + 0x20) - $lpUserDesktopHeapWindow
```

Method 2 is faster (no heap scan) and more robust across build numbers.

---

## §4 — The UAF Reuse Detection Loop

The core of the technique is detecting when the kernel reuses the same session pool slot for consecutive `lpszMenuName` allocations. The loop:

```powershell
$KernelArray = @()
for ($i = 0; $i -lt 20; $i++) {
    $TestWindowHandle = Create-WindowObject      # RegisterClass + CreateWindowEx
    $KernelArray += Leak-lpszMenuName -WindowHandle $TestWindowHandle

    if ($KernelArray.Length -gt 1) {
        if ($KernelArray[$i] -eq $KernelArray[$i-1]) {
            # Same kernel address assigned twice = deterministic slot reuse confirmed
            Destroy-WindowObject -Handle $TestWindowHandle   # free the slot

            # Immediately allocate a bitmap into the freed slot
            $BitmapHandle = [HmValidateHandleBitmap]::CreateBitmap(0x701, 2, 1, 8, $Buffer)
            break
        }
    }

    Destroy-WindowObject -Handle $TestWindowHandle   # destroy without reuse
}
```

Each iteration:
1. Creates a window with `lpszMenuName = "A" × 0x8F0`
2. Leaks the kernel address of `tagCLS.lpszMenuName`
3. Destroys the window

When the same kernel address appears on consecutive iterations, the session pool is confirmed to be recycling that slot deterministically. At that point:
- The window is destroyed one final time, freeing the slot
- A bitmap of the correct size is immediately allocated (`CreateBitmap(0x701, 2, 1, 8, ...)`)
- The kernel session pool places the new bitmap's `SURFOBJ` into the freed slot

The bitmap's `pvScan0` field ends up at `lpszMenuName_base + 0x50` — a predictable offset into the formerly controlled buffer, within the desktop heap range, passing RS2's bounds check.

---

## §5 — Why This Slot Reuse Is Predictable

The session pool uses a segregated free list organized by allocation size. The `lpszMenuName` buffer (0x8F0 bytes → allocated in the 4KB pool bucket) and the `SURFOBJ` for a `0x701 × 2 × 1bpp` bitmap (also ~4KB) land in the same pool bucket.

When `lpszMenuName` is freed by `DestroyWindow`/`UnregisterClass`, the slot returns to the head of the same-size free list. The immediately following `CreateBitmap` call, requesting a similarly sized allocation, consumes the same list head. This is deterministic on non-ASLR pool systems and probabilistic but high-success on ASLR pool systems due to low fragmentation in session pool small-size buckets.

The reuse detection loop is the empirical confirmation of this: if the same address is assigned to two consecutive `lpszMenuName` allocations (with destroy/recreate between them), the slot is cycling through the free list head deterministically. The loop terminates on confirmation, ensuring the subsequent bitmap allocation is not a gamble.

---

## §6 — From Slot Reuse to Arbitrary R/W Primitive

After the bitmap occupies the freed slot:

```powershell
$HashTable = @{
    BitmapHandle    = $BitmapHandle
    BitmapKernelObj = $KernelArray[$i]            # former lpszMenuName base
    BitmappvScan0   = $KernelArray[$i] + 0x50     # pvScan0 within that allocation
}
```

The bitmap's `pvScan0` is at `KernelArray[$i] + 0x50`. This is a kernel address within the desktop heap, pointing into the region where the attacker's 0x8F0-byte controlled string previously lived. Since the desktop heap is shared user/kernel:

```
UserModeAddress = (KernelArray[$i] + 0x50) - ulClientDelta
```

The attacker can write to this user-mode address, changing what `pvScan0` "sees" when `GetBitmapBits` dereferences it. The write goes through the user-mode mapping of the desktop heap, but the kernel's `pvScan0` read goes through the kernel mapping of the same physical memory. Same bytes, different virtual addresses, both accessible.

From this point, the Manager/Worker pattern from `GDI-Bitmap-Abuse-Writeup` applies identically: redirect `pvScan0` to a target kernel address, use `GetBitmapBits`/`SetBitmapBits` to read/write. The token steal proceeds as in the classic technique.

---

## §7 — Structural Comparison: Abuse vs. Necromancy

| Dimension | GDI Bitmap Abuse | RS2 Bitmap Necromancy |
|---|---|---|
| Target Windows version | 7, 8, 8.1, 10 pre-RS2 | Windows 10 RS2+ |
| `pvScan0` corruption path | Direct kernel write to `SURFOBJ.pvScan0` | UAF heap reuse: bitmap occupies freed slot |
| RS2 bounds check | Fails — `pvScan0` points outside desktop heap | Passes — `pvScan0` within desktop heap |
| Prerequisite | Any kernel write primitive | Desktop heap address leak (ulClientDelta) |
| Stability | Medium (pool layout dependent) | Medium-high (deterministic slot detection) |
| Final primitive | Arbitrary kernel R/W via GDI APIs | Same |

The two techniques share the final stage entirely. The difference is entirely in how `pvScan0` is constructed to point at attacker-controlled memory. Abuse writes the pointer. Necromancy maneuvers the heap so the pointer is already in the right place when the bitmap is allocated.

---

## §8 — The `ulClientDelta` Side Channel

The delta between kernel and user-mode desktop heap addresses is readable from user-mode without any vulnerability. `TEB + 0x828` is a documented offset in the Thread Environment Block, pointing to the process's user-mode desktop heap mapping. This mapping is readable. `*(user_heap + 0x28)` gives the kernel base — also readable, because it lives in the user-mode mapping of the same shared memory.

The existence of this side channel is structural: the desktop heap was designed to be partly user-accessible to avoid syscall overhead for common GUI operations. The delta is not secret — it is a consequence of the shared mapping. The information it provides (kernel address of any GUI object whose user-mode address is known) is the foundation of most desktop heap exploitation techniques from ~2010 onward.

What changed in RS2 was not the delta's accessibility but the enforcement around its use. RS2 made `pvScan0` dangerous to use if it pointed outside the desktop heap. But the delta still reveals which kernel addresses are *within* the desktop heap, and heap grooming moves the target into that range.

---

## §9 — Related Writeups

**`GDI-Bitmap-Abuse-Writeup`** — Direct predecessor technique. This writeup exists entirely because of the RS2 patch that closed the direct `pvScan0` overwrite path. Reading the two writeups together illustrates the mitigation/escalation cycle: each defense constrains the attack surface, but the constraint itself creates a new surface (here: the implication that anything within the desktop heap is a permitted `pvScan0` value). The RS2 fix was correct within its stated goal; the bypass exploits an assumption the fix made about the desktop heap's trustworthiness.

**`Double-Fetch-Race-Writeup`** — Both techniques exploit temporal gaps in the kernel's object lifecycle. Double-fetch exploits the gap between check and use within a single syscall. Necromancy exploits the gap between `DestroyWindow` (object freed) and the next allocation that claims the slot (window of reuse opportunity). In both cases, the attack occupies a time window that the kernel's security model does not protect.

The underlying claim: **a mitigation that bounds an operation to a specific memory region is only as strong as the assumption that the attacker cannot place controlled content in that region.** RS2's bounds check is logically correct. Necromancy satisfies the bounds check by placing a bitmap — an object the attacker also controls — exactly where the bounds check expects legitimate data to live.

---

*Research context: educational analysis of desktop heap exploitation and UAF-based GDI technique development applicable to Windows 10 RS2. Demonstrated in PowerShell PoC for readability. The technique applies to systems prior to Windows 10 RS3 and related kernel pool hardening improvements.*
