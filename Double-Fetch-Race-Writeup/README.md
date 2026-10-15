---
title: "The Promise That Expires: Double-Fetch Race Conditions in the Windows Kernel"
date: 2026-05-17
tags: [windows-kernel, race-condition, toctou, win32k, bochspwn, lpe, timing-attack]
cluster: kernel-temporal-safety
related:
  - DMA-IOMMU-Writeup
  - Qualcomm-Kgsl-SignExt-Writeup
---

## Author's Note

Kernel security validation works on a model of promises: if a value passes a check, it is assumed to stay checked. This writeup examines what happens when that assumption is wrong — not because the check logic is broken, but because the value being checked can change between the moment it is validated and the moment it is used.

The double-fetch race condition is one of the clearest illustrations of a mismatch between a security model and its hardware substrate. The model says "value X was checked at time T." The hardware says "value X lives in memory you do not own, and memory can change." On a single CPU, this mismatch is hard to exploit. On a modern multi-core system, it becomes nearly deterministic.

The Bochspwn research (Jurczyk & Coldwind, Google 2013) found 27 instances of this exact pattern in a single Windows kernel subsystem — all variants of what was probably one macro. From a single detection methodology, over 50 unique CVE fixes emerged. This writeup dissects why the pattern is so persistent, how exploitation works at the hardware level, and why the fix is so simple in hindsight.

---

## Abstract

A double-fetch race condition occurs when a kernel handler reads a user-mode value twice within a single syscall: once for a safety check (bounds, pointer validation) and once to actually use the value. Because the value lives in user-mode memory that the attacker controls, it can be changed between the two fetches. If the race is won, the kernel's safety check becomes a lie: the check saw a safe value, but the use sees an attacker-controlled value.

On multi-core hardware, exploitation is parallel rather than probabilistic — a second thread on a different core spins flipping the value, and the race is won the moment the kernel's two reads straddle a flip. With memory latency amplification techniques (page-boundary alignment, cache-disabled pages, TLB flush), the window between fetches can be stretched from ~2 cycles to ~2400 cycles, inflating win rates from near-zero on single-core to ~10 million per second on six physical cores.

CVE-2013-1254 (family of 27 win32k.sys handlers) demonstrates the read-primitive case. CVE-2013-1278 (`NtApphelpCacheControl`) demonstrates the write-what-where case, with a full privilege escalation chain through `HalDispatchTable` function pointer hijacking. Bochspwn, the full-system emulator with memory access instrumentation, shows how the pattern is mechanically detectable. The defense is one rule: read user-mode data once, copy it to kernel-owned storage, operate on the copy.

---

## §1 — The Temporal Gap in Kernel Validation

Every kernel syscall that touches user-mode data faces the same structural problem: it cannot trust that memory. The standard response is to validate: probe the pointer, check the bounds, copy the value. But "validate" only means "was valid at the moment I checked." It says nothing about what the value is *now*.

Consider the minimal vulnerable pattern:

```c
PDWORD user_ptr = /* controlled by caller */;
UCHAR  LocalBuffer[256];

if (*user_ptr > sizeof(LocalBuffer)) {    // fetch #1: safety check
    return STATUS_INVALID_PARAMETER;
}
RtlCopyMemory(LocalBuffer, user_ptr, *user_ptr);  // fetch #2: use
```

The check at fetch #1 guarantees nothing about fetch #2. Between the two reads, the kernel has no lock on user memory, no copy-on-access semantic, no temporal snapshot. Any thread sharing the same virtual address space can write to `*user_ptr` in that interval.

The "interval" sounds small — it is a handful of instructions. But instructions take time in cycles, and cycles on a modern CPU map to deterministic windows. If an attacker can execute a write operation to the target address faster than the window closes, the check passes and the malicious value is used. This is not a theoretical concern: on a six-core machine it happens millions of times per second.

---

## §2 — Two Structural Variants

### Variant A: Post-Sanitization Double Fetch

The check and the use are explicit, in sequence, over the same dereference:

```c
if (*lpInputPtr > sizeof(LocalBuffer))     // fetch #1 — explicit check
    return STATUS_INVALID_PARAMETER;
RtlCopyMemory(LocalBuffer, lpInputPtr, *lpInputPtr);  // fetch #2 — raced
```

The race target is the value under `*lpInputPtr`. Fetch #1 sees it as safe (≤256). Between #1 and #2, the attacker writes a large value. Fetch #2 drives a stack buffer overflow.

### Variant B: Implicit-Assumption Double Fetch

No explicit sanitization — the code assumes allocation size and copy length stay equal across two reads of the same user pointer:

```c
PUCHAR LocalBuffer = ExAllocatePool(PagedPool, *BufferSize);  // fetch #1
if (LocalBuffer != NULL) {
    RtlCopyMemory(LocalBuffer, BufferPtr, *BufferSize);        // fetch #2
}
```

If `*BufferSize` changes between the two reads, `alloc(N1)` + `copy(N2)` with `N2 > N1` causes a kernel pool overflow. There is no explicit check to defeat — the race desynchronizes two values that the code assumes are identical.

---

## §3 — The ASM Signature: Bochspwn's Fingerprint

The canonical form at the assembly level is two `mov` instructions reading the same user-mode address within a single syscall, separated by a conditional branch but nothing else:

```asm
; win32k!SfnINOUTNCCALCSIZE — Bochspwn output format
cmp   [ecx+CALLBACK_OUTPUT.pOutput], MmUserProbeAddress  ; fetch #1
jnb   short invalid_ptr
mov   eax, [ecx+CALLBACK_OUTPUT.pOutput]                 ; fetch #2
...
rep   movsd                                               ; use fetch #2
```

Same base register (`ecx`), same offset (`CALLBACK_OUTPUT.pOutput`), three instructions apart. The time window between fetch #1 and fetch #2 is exactly the `jnb` branch — one conditional jump — approximately 2-4 cycles under cache-warm conditions. This is the window the attacker must hit.

The patched version promotes the user pointer to a kernel-local copy before the first use:

```asm
mov   esi, [ebp+CallbackOutputPtr]
lea   edi, [ebp+CALLBACK_OUTPUT]
movsd                               ; struct copy to kernel stack
movsd                               ; (12 bytes total)
movsd
...
mov   ecx, [ebp-CALLBACK_OUTPUT.pOutput]  ; operate on local copy
```

User memory is touched exactly once. After that, all operations run on the kernel stack copy. No race is possible.

---

## §4 — Hardware Topology of the Race

The race win probability is not a fixed constant — it depends directly on the hardware model.

### Single-Core: Scheduler-Dependent

On a single CPU, true parallelism does not exist. The attacker's flip thread can only execute during context switches. A race win requires the scheduler to preempt the vulnerable syscall at precisely the 2-instruction window between the two fetches.

Measured win rate on a single-core VM (CVE-2013-1254): **~1 win per 110 seconds**.

### Multi-Core: Parallel and Near-Deterministic

On multi-core hardware, the race thread on Core 0 executes the vulnerable syscall while the flip thread on Core 1 spins continuously writing to the target address:

```
Core 0 (race thread)                   Core 1 (flip thread)
────────────────────                   ────────────────────
push [BufferSize]                ┐
call ExAllocatePool              │ ←── xor [BufferSize], 0x80000000
test eax, eax                   │     jmp $-10          (spinning)
jz   bail_out                   │
push [BufferSize]               ─┘
call RtlCopyMemory
```

Core 1 does not need to time its write precisely — it writes continuously. The race is won whenever Core 0's two reads straddle a flip. With a 2-4 cycle window and Core 1 spinning at ~10^9 flips/second, wins are essentially guaranteed on every syscall invocation.

Measured win rate: **~16 wins per second on 4 logical CPUs** (~1750× speedup over single-core).

---

## §5 — Time-Window Amplification

The 2-cycle default window is tight for a flip thread. Three techniques stretch it by increasing memory access latency on the race side, making the window physically longer without changing any kernel code.

### Technique 1: Page Boundary Placement

Place the 4-byte target value at the boundary of two pages — 2 bytes in page N, 2 bytes in page N+1:

```
   page N                    page N+1
   ┌────────────────────┐    ┌─────────────────────┐
   │ ... ........ FF FE │    │ 00 00 ............. │
   └────────────────────┘    └─────────────────────┘
                       ▲▲    ▲▲
                       └┴────┴┘
                       4-byte raced value
```

A `mov eax, [ecx]` across a page boundary forces two separate address translations, two TLB lookups, two cache lookups, and two physical fetches. Measured latency:

```
Normal (same page, cached):          ~1.85 cycles
Cache-line boundary (cached):        ~4    cycles
Page boundary (cached):              ~25   cycles    ← 13× slowdown
```

Thirteen times slower for one aligned allocation.

### Technique 2: Non-Cached Memory (`PAGE_NOCACHE`)

```c
void *p = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE | PAGE_NOCACHE);
```

Removes the page from the CPU cache hierarchy entirely. Every read goes directly to DRAM. Measured:

```
Normal (aligned, cached):            ~1.85 cycles
Non-cached, aligned:                 ~250  cycles    ← 135× slowdown
Non-cached + page boundary:          ~500  cycles    ← 270× slowdown
```

`PAGE_WRITECOMBINE` achieves similar latency — designed for GPU framebuffer access, it bypasses caching entirely. Combining both techniques stacks the slowdowns multiplicatively.

### Technique 3: TLB Flush (`EmptyWorkingSet`)

Before each race attempt, evict the target page from the TLB:

```c
EmptyWorkingSet(GetCurrentProcess());
```

After a TLB miss, the CPU must perform a full 4-level page table walk to retranslate the virtual address:

```
PML4E[i47..i39] → PDPTE[i38..i30] → PDE[i29..i21] → PTE[i20..i12] → PA + offset
```

Each level is a memory fetch. With non-cached pages:

```
Non-cached + page boundary + TLB flushed:   ~2400 cycles    ← ~1300× slowdown
```

The amplification is beneficial only when the window gain exceeds the attempt-cost overhead. The condition:

```
e/t > w/x
```

where `e` = cycles gained from flush, `t` = flush syscall cost, `w` = base window, `x` = attempt cycle cost. If the flush overhead dominates, skip it.

---

## §6 — Thread Assignment Topology

Win rate also depends on how race and flip threads are assigned to logical CPUs.

**Hyperthreaded systems:** Optimal configuration pairs one race thread with one flip thread on the same physical core's two HT logical threads. Shared L1/L2 cache between HT siblings means cache-warm reads — the flip thread's writes are visible to the race thread with minimum latency. Result: ~3×10^7 wins/second per pair.

**Non-HT physical cores:** Separate physical cores share no cache. Here, non-cached memory wins over cached, because the slowdown on the race thread is what produces the window — not cache sharing. The flip thread can write faster than the race thread reads, and the window is the entire memory access latency. Six physical cores with non-cached page-boundary configuration: **~10^7 wins/second**.

The boundary-page hybrid further optimizes: place the first fetch on a `NO_CACHE` page (slow read), the second fetch on a cached page (fast). Race thread slows on fetch #1; flip thread writes to the cached address fast. The asymmetry maximizes the desync window between the two fetches.

---

## §7 — CVE-2013-1254: Family of 27, Read Primitive

The `CALLBACK_OUTPUT` structure passed by user-mode code to win32k callback handlers contains a `pOutput` pointer. In 27 distinct handlers, this pointer was read twice — once for bounds validation and once for use:

```c
typedef struct _CALLBACK_OUTPUT {
    NTSTATUS st;
    DWORD    cbOutput;
    PVOID    pOutput;    // ← raced across 27 handlers
} CALLBACK_OUTPUT;
```

Handlers confirmed double-fetching `pOutput`:

```
CalcOutputStringSize       SfnINOUTLPSCROLLINFO
ClientGetListboxString     SfnINOUTLPUAHMEASUREMENUITEM
ClientGetMessageMPH        SfnINOUTLPWINDOWPOS
CopyOutputString           SfnINOUTNEXTMENU
SfnINOUTDRAG               SfnOUTLPCOMBOBOXINFO
SfnINOUTLPMEASUREITEM      SfnOUTLPRECT
fnHkINDWORD                SfnOUTLPSCROLLBARINFO
fnHkINLPCBTCREATESTRUCT    xxxClientCopyDDEIn1
fnHkINLPMOUSEHOOKSTRUCTEX  xxxClientCopyDDEOut1
... (27 total)
```

The uniformity suggests a shared macro — the same code generation pattern emitted in 27 call sites, each inheriting the bug. The primitive is a kernel address space **read**: racing `pOutput` to a kernel address causes `memcpy(kernel_dst, attacker_kernel_ptr, N)`, leaking kernel memory into the callback output buffer.

### Exploitation Chain: PS/2 Keyboard Sniffer

The read primitive targets `i8042prt.sys`'s device extension, where the keyboard interrupt handler stores the two most recent keycodes:

```c
// i8042prt.sys interrupt handler (disassembly):
lea  eax, [esi + 0x14A]    // esi = DeviceExtension
mov  [esi + 0x14B], cl     // shift previous scancode
mov  [eax], cl              // store current scancode
```

`DeviceExtension + 0x14A` holds live keypress data, constantly overwritten. Locating the device extension:

```
SIDT → IDT base
↓
Walk IDT entries for ServiceRoutine pointer nearest i8042prt.sys image base
↓
Irql == SynchronizeIrql → keyboard interrupt
↓
KINTERRUPT.DeviceObject.DeviceExtension = target address
```

With the read primitive aimed at this offset, keystroke data is exfiltrated at ~28 reads/second. No kernel write required — the primitive leaks admin keystrokes including passwords, enabling indirect privilege escalation.

---

## §8 — CVE-2013-1278: Write-What-Where via NtApphelpCacheControl

A second double-fetch in `NtApphelpCacheControl` targets the *destination* pointer rather than a source:

```asm
; ApphelpCacheLookupEntry — vulnerable
mov   ecx, [edi+18h]          ; fetch #1: destination pointer
...
push  4
push  eax
push  ecx
call  ProbeForWrite            ; validates ecx is user-mode
...
push  [edi+18h]                ; fetch #2: same pointer, raced
call  memcpy                   ; 0x1c8 bytes written here
```

`ProbeForWrite` expands the time window substantially compared to a simple branch — the entire function call runs between fetch #1 and fetch #2, making the race trivial on any multi-core system. Measured: ~1 win per 5 seconds on Windows 7 SP1 x86.

### Exploitation Chain: HalDispatchTable Overwrite

The `memcpy` writes 0x1c8 (456) bytes. Pointing it at `HalDispatchTable+4` writes a kernel function pointer, but also corrupts 452 adjacent bytes, causing a BSOD before the exploit completes. The solution is *damage absorption* via a Private Namespace object:

```
Private Namespace Object layout:
┌───────────────────────────────────────────┐
│ Object header                             │
│ LIST_ENTRY  ← overwrite lands here        │
│ Variable-length user data (≥0x1c4 bytes)  │
└───────────────────────────────────────────┘
```

The 0x1c8-byte write is aimed 1 byte before the `LIST_ENTRY` field. The first 4 bytes of the write land at a predictable location (`0x00034782` from spray), setting `LIST_ENTRY.Flink`/`Blink` to attacker-controlled values. The remaining 0x1c4 bytes are absorbed by the user-data region of the namespace object, which is "don't-care" to the kernel.

Full chain:

```
1. Spray user-mode range 0x03000000–0x03FFFFFF with crafted LIST_ENTRY values
   → Flink and Blink both point to HalDispatchTable+4

2. Trigger NtApphelpCacheControl, win the race
   → memcpy writes 0x00034782 into LIST_ENTRY at the spray address

3. ClosePrivateNamespace → LIST_ENTRY unlink operation:
       *(victim->Flink + offsetof(Blink)) = victim->Blink
   Both Flink and Blink are attacker-controlled
   → *(HalDispatchTable+4) = shellcode_ptr

4. NtQueryIntervalProfile → calls *(HalDispatchTable+4) → shellcode
5. Token swap: process->Token = SYSTEM process Token
6. Restore HalDispatchTable to prevent BSOD
```

The same list-unlink primitive used in heap exploitation is here achieved through a write-what-where race condition — without any heap vulnerability.

---

## §9 — Bochspwn: Detection by Instrumentation

Bochspwn instruments Bochs, a full-system x86 emulator, to intercept every linear memory access executed in kernel mode (CPL=0) against user-mode virtual addresses, within syscall boundaries.

```
Architecture:
────────────────────────────────────────────────────
Guest OS (Windows 7/8 32/64-bit)
   inside
Bochs x86-64 emulator + custom instrumentation plugin
   on
Host (Linux/Windows)
────────────────────────────────────────────────────

Instrumentation hooks:
  BX_INSTR_BEFORE_EXECUTION  → SYSENTER/SYSCALL → mark syscall boundary
  BX_INSTR_LIN_ACCESS        → triggered on every linear memory access
    filter: CPL==0 && VA < user_probe_address && kind==READ && size∈{2,4,8}
    → record in per-thread, per-syscall access cache
```

Thread identity includes `(PID, TID, CreationTimestamp)` to survive OS handle recycling. The cache flushes on every `SYSENTER`, eliminating false positives from cross-syscall reads of the same address.

Detection algorithm:

```python
on_memory_access(thread, va, size, kind):
    if kind != READ or size not in {2,4,8}: return
    if cpl != 0 or not user_mode_va(va):   return
    cache = per_thread[thread].current_syscall
    for prior in cache:
        if prior.va == va and prior.size == size:
            emit_candidate(thread, va, prior.pc, current.pc)
    cache.append(current_access)

on_sysenter(thread):
    per_thread[thread].current_syscall.clear()
```

Performance overhead: ~8× slowdown vs vanilla Bochs boot time. Memory overhead: 13–136 GB disk per test run depending on Windows version. The throughput:

```
Instructions executed:                 ~2 × 10^10
Syscall events:                        ~8 × 10^5
Linear memory accesses:                ~10^10
Passing initial filter:                ~3 × 10^7  (0.3%)
```

From one session against Windows 7/8 across five disclosure batches: 50+ unique CVE fixes, 32 EoP vulnerabilities in MS13-016/MS13-017 alone.

---

## §10 — The Formal Argument: What the Check Actually Proves

The kernel's validation model implicitly assumes temporal stability:

> *If value X satisfies constraint C at time T₁, and the kernel uses value X at time T₂ > T₁, then X satisfies C at T₂.*

This assumption is valid if and only if X is immutable between T₁ and T₂, or if the kernel holds a lock that prevents external mutation. For user-mode memory, neither condition holds. The kernel does not lock user pages during a syscall — doing so would be prohibitively expensive and would prevent concurrent user-mode execution.

The formal statement of the vulnerability:

```
∀ kernel handler H with:
  fetch₁(user_ptr) → value v₁                (read for check)
  check(v₁) = PASS
  fetch₂(user_ptr) → value v₂                (read for use)

If H does not hold an exclusive lock on user_ptr between fetch₁ and fetch₂:
  ∃ attacker thread A: A can write v₂ ≠ v₁ to *user_ptr in the interval
  → check(v₁) = PASS but use(v₂) with v₂ ∉ safe domain

check(v₁) is sound only for v₁. It proves nothing about v₂.
```

The fix eliminates the problem by eliminating the distinction between v₁ and v₂:

```c
// Single fetch, kernel local, operate on copy
SIZE_T local_sz;
ProbeForRead(user_ptr, sizeof(SIZE_T), 1);
local_sz = *user_ptr;                     // one read — v₁ and v₂ become identical

if (local_sz > MAX) return ERROR;
memcpy(buf, user_ptr_data, local_sz);     // local_sz cannot be raced
```

The correction is one discipline rule. The 50+ CVE batch proves that knowing the rule and consistently applying it across a large codebase under time pressure are separate problems. Bochspwn solves the second problem by making violations mechanically detectable.

---

## §11 — Portfolio Relationships

**`DMA-IOMMU-Writeup`** — DMA/IOMMU examines a spatial isolation failure: the kernel's virtual address space protection does not extend to the hardware bus. Double-fetch examines a *temporal* isolation failure: the kernel's validation snapshot does not extend across time. Both are cases where a protection invariant is stated at one scope and relied upon at a larger scope.

**`Qualcomm-Kgsl-SignExt-Writeup`** — The kgsl writeup examines arithmetic applied to a value fetched from user-mode (via `ioctl` parameter), producing an OOB physical address due to sign extension. The double-fetch writeup examines a value fetched from user-mode memory being used after it has been mutated. The common pattern: values originating in user-mode are temporally and spatially unsafe without explicit promotion to kernel-owned storage.

The broader claim this writeup makes: **kernel security checks prove properties of values at points in time, not properties of values across time intervals.** A check-then-use sequence in kernel code is only safe if the value is immutable or controlled between the two operations. On multi-core hardware with shared user-mode memory, immutability is the developer's responsibility — the hardware guarantees nothing.

---

*Research context: analysis of Jurczyk & Coldwind, "Identifying and Exploiting Windows Kernel Race Conditions via Memory Access Patterns" (Google, 2013) and the CVE-2013-1254/1278 vulnerability family. All techniques described require kernel-mode execution context or multi-threaded user-mode code targeting a vulnerable Windows kernel. Demonstrated on historical patch-applicable systems.*
