---
title: "Counterfeit Object-Oriented Programming: Weaponizing CET's Own Trust Model"
author: Utku
date: 2026
tags: [CET, COOP, vtable, IBT, ENDBR64, shadow-stack, Windows, control-flow, exploit]
license: CC BY 4.0
---

> **Author's Note:** CET is a genuinely smart mitigation. It closes the door on every ROP/JOP chain that exploits code fragments not at valid entry points. But closing that door forces attackers through the front entrance — which turns out to be wide open if you're willing to only ever use it legitimately. COOP is what happens when you understand *why* a mitigation works, not just *that* it works.

---

## Abstract

Intel's Control-flow Enforcement Technology (CET) solves the ROP/JOP problem by operating at two levels: Shadow Stack protects return addresses, and IBT restricts indirect branches to ENDBR64-marked landing pads. Together they enforce that execution only flows through *intended code paths*. Counterfeit Object-Oriented Programming (COOP) demonstrates that this enforcement is necessary but not sufficient — it says nothing about the *semantic sequence* of those paths. By abusing C++ virtual dispatch to chain legitimate ENDBR64-marked function entry points through a counterfeit vtable, COOP builds a complete execution primitive (argument loading → invocation → collection) that CET cannot distinguish from normal OOP code. This writeup traces the full mechanism: from how CET's trust model works, to why it operates at the wrong abstraction level, to the Looper/ArgLoaders/Invoker/Collector pattern, to the WinDbg trace where `ntdll!LdrpDispatchUserCallTarget` itself delivers the final branch to `WinExec`.

---

## §1 CET's Threat Model

CET targets a specific class of exploit: the attacker has an arbitrary write or a stack smash, can redirect control flow, but cannot inject new code (W^X / DEP prevents that). Classical ROP/JOP harvests small code *fragments* — not full functions — and chains them. The gadget `pop rdi ; ret` at `libc+0x2a3f5` is useful precisely because it isn't a function entry point; it's a mid-function sequence that CET has no obligation to mark.

CET's two-pronged answer:

| Component | Mechanism | What it protects |
|---|---|---|
| Shadow Stack | CPU-maintained parallel stack; `ret` compared against SS copy | Return address integrity |
| IBT (Indirect Branch Tracking) | `jmp reg` / `call reg` must land on `ENDBR64` | Indirect branch targets |

The implicit bet: *if every valid branch target is a function prologue, and every function prologue starts with ENDBR64, then you can only go where the compiler decided you can go.*

This is correct. The problem is that "where the compiler decided you can go" is a much larger set than "the execution sequence the developer intended."

---

## §2 Shadow Stack — Guarding `ret` Only

Shadow Stack is per-thread. On a `call`, the CPU writes the return address to both the normal stack (RSP) and the shadow stack (SSP, in a write-protected page). On `ret`, it compares both. If they diverge → `#CP` (Control Protection Fault).

```asm
; What CET does on call:
;   [rsp]    ← return address
;   [ssp]    ← return address (shadow copy, CPU-maintained, read-only to user)

; What CET does on ret:
;   cmp [rsp], [ssp]
;   jne #CP_FAULT
;   pop rip
;   inc ssp
```

For a classic stack overflow that overwrites a saved return address: `[rsp]` is corrupted, `[ssp]` is still the original. The comparison fails. ROP is dead — at least the `ret`-chaining variant.

COOP's key structural insight is that it **never uses `ret` to transfer control between chain elements**. Every transition is an indirect `call` or `jmp`. Shadow Stack doesn't apply.

---

## §3 IBT and the ENDBR64 Contract

`ENDBR64` is a 4-byte NOP-equivalent instruction (`F3 0F 1E FA`) that a CET-unaware processor executes without effect. On a CET-enabled CPU, IBT tracks a "WAIT_FOR_ENDBR" state:

- After any indirect branch (`jmp reg`, `call reg`, `jmp [mem]`, `call [mem]`): CPU enters WAIT_FOR_ENDBR
- Next instruction must be `ENDBR64`; if anything else is fetched in that state → `#CP`

A CET-compiled binary looks like this:

```asm
0x140001000: f3 0f 1e fa    ENDBR64        ; ← IBT landing pad
0x140001004: 55             push rbp
0x140001005: 48 89 e5       mov rbp, rsp
```

Any mid-function gadget — `pop rdi ; ret` at `0x140001150` — lacks ENDBR64. An indirect branch to it faults immediately.

The compiler automatically inserts ENDBR64 at every function entry point and every indirect-branch-reachable label. This means every function in a CET-compiled binary is a valid COOP gadget. The attack surface grew from "a handful of gadgets" to "every exported API entry point."

---

## §4 The Abstraction Gap

CET enforces control flow at the granularity of **individual indirect branches**. It answers one question per branch: "is this destination marked?" It has no concept of a *sequence of branches* or the semantic intent of a call chain.

The invariant CET maintains: ∀ indirect branch → target has ENDBR64.

The invariant COOP violates: the semantic meaning of a sequence of virtual calls.

CET was designed to prevent code-reuse *at the instruction level*. COOP operates *at the object dispatch level* — a full abstraction level higher. The gap between these two levels is where COOP lives.

Concretely:

```
CET checks:  branch → [ENDBR64?] → allow/fault
COOP builds: vtable[0] → arg_loader1 → vtable[1] → arg_loader2 → vtable[2] → invoker
```

CET validates each arrow. It says nothing about the chain they form.

---

## §5 C++ Virtual Dispatch as the Attack Substrate

COOP is called *object-oriented* programming because it exploits the one control flow mechanism that was already indirect and that compilers generate pervasively: virtual function dispatch.

```cpp
class Animal { virtual void speak(); };
// ...
Animal *a = new Dog();
a->speak();  // compiled to:
//   mov rax, [rcx]      ; load vtable pointer from object
//   call qword ptr [rax] ; indirect call through vtable[0]
```

This is precisely an indirect call. CET validates that `vtable[0]` points to an ENDBR64-marked address. If it does, execution proceeds. CET has no opinion about *which* vtable `[rcx]` points to.

The exploit primitive: corrupt the vtable pointer in a heap object (via overflow, UAF, type confusion — any write primitive works). Replace `[rcx]` with a pointer to a *counterfeit vtable* whose entries are addresses of legitimate, ENDBR64-marked functions. CET validates each dispatch. The entire chain executes.

---

## §6 The Counterfeit Vtable as an Instruction Stream

The fake vtable is, conceptually, a program. Its entries are "instructions" — not machine instructions, but semantic operations executed by calling into real functions in the process image.

```
fake_vtable[0] = &arg_loader1   ; RCX ← "calc.exe"
fake_vtable[1] = &arg_loader2   ; RDX ← SW_SHOWNORMAL (1)
fake_vtable[2] = &invoker       ; jmp [WinExec_ptr]
fake_vtable[3] = &collector     ; RBX ← RAX; jmp Looper
```

The virtual call sequence (`obj->func1()`, `obj->func2()`, ...) is the "fetch-execute" cycle that drives this program. The object's vtable index — which you control by choosing which virtual method to call and how many times — is the program counter.

The Looper is the mechanism that advances the index, typically by incrementing RSI across the vtable entries and calling through each one in sequence.

---

## §7 Looper / ArgLoaders / Invoker / Collector

These are the four functional roles that any COOP chain needs. They map directly onto the stages of a normal function call.

### Looper

Advances the chain. Keeps virtual dispatch running across multiple vtable entries.

```asm
; Structural role: "fetch-execute cycle"
mov rax, [rsi]       ; rsi points into fake_vtable
call rax             ; IBT check → ENDBR64 → pass
add rsi, 8           ; advance vtable index
jmp Looper
```

### Argument Loaders

Move attacker-controlled values into calling convention registers. Each loader is a real function that has a sequence like `mov rcx, <constant>` near its entry point.

For `WinExec(LPCSTR lpCmdLine, UINT uCmdShow)` on x64 Windows:

```asm
; ArgLoader1: prepare RCX
mov rcx, offset szCalcExe    ; "calc.exe" string address
ret                           ; Shadow Stack OK: this was a real call

; ArgLoader2: prepare RDX
mov rdx, 1                    ; SW_SHOWNORMAL
ret
```

### Invoker

Calls the real target API. The indirect call to an API entry point is exactly what CET was designed to allow.

```asm
; Invoker: call WinExec
mov rax, [WinExec_ptr]       ; resolve from IAT
jmp rax                       ; IBT: WinExec begins with ENDBR64 → pass
```

### Collector

Captures the return value in a non-volatile register and requeues it for the next stage.

```asm
; Collector: save return value
mov rbx, rax                 ; preserve WinExec's UINT return
jmp Looper                    ; feed next vtable entry
```

The full pipeline for `WinExec("calc.exe", 1)`:

```
RIP hijack → fake_vtable → Looper → ArgLoader1 (RCX) → ArgLoader2 (RDX) → Invoker → Collector
```

`calc.exe` spawns. CET raised zero exceptions.

---

## §8 WinDbg Evidence: The Dispatcher as Accomplice

The WinDbg trace from the PoC shows `ntdll!LdrpDispatchUserCallTarget` as the instruction that legitimizes the branch:

```asm
ntdll!LdrpDispatchUserCallTarget:
...
00007ffb`ecbdc65b 48 ff e0    jmp rax      ; rax = KERNEL32!WinExec
```

`LdrpDispatchUserCallTarget` is Windows' own CET trampoline. It is the security enforcement point — it performs the IBT check and then executes the branch. In the COOP scenario, this function *is* the final delivery mechanism. The mitigation designed to stop the exploit is the thing that executes it.

After the branch:

```asm
KERNEL32!WinExec:
00007ffb`ec0f6140 f3 0f 1e fa  ENDBR64    ; ← IBT landing pad, CET satisfied
00007ffb`ec0f6144 48 8b c4     mov rax, rsp
```

Shadow Stack is satisfied because every `ret` in the chain returns to the actual caller (the Looper or the vtable dispatch mechanism). IBT is satisfied because every branch target begins with ENDBR64. Both invariants hold. Calculator opens.

---

## §9 File I/O Exfiltration Chain

WinExec is the textbook demonstration, but the same pattern scales to a full exfiltration workflow using only Windows API entry points. Each API function begins with ENDBR64. Each is a valid COOP invoker target.

```
; Stage sequence:

ArgLoader (RCX="C:\secret.txt", RDX=GENERIC_READ, R8=OPEN_EXISTING)
    → Invoker: CreateFileA
    → Collector: RBX = file handle

ArgLoader (RCX=RBX[handle], RDX=buffer, R8=0x1000)
    → Invoker: ReadFile
    → Collector: RBX = bytes_read

ArgLoader (RCX=socket_handle, RDX=buffer, R8=bytes_read)
    → Invoker: WriteFile (to socket)
    → Collector: chain terminates or loops
```

The data section needs to carry the API function pointers (resolvable via `GetProcAddress`, itself another valid ENDBR64 target) and the string literals. Everything in this chain is a CET-compliant indirect call to a real Windows API.

---

## §10 The 8-Stage Advanced Chain

A complete implant lifecycle assembled from CET-compliant call sequences:

| Stage | API calls | Purpose |
|---|---|---|
| 1 — Init/Evasion | `IsDebuggerPresent`, `EnumProcessModules`, `GetModuleBaseNameA` | Anti-debug, anti-analysis tool detection (Wireshark, ProcMon, IDA, x64dbg) |
| 2 — Process Enum | `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next` | Find explorer.exe / winlogon.exe by name scan |
| 3 — Memory Alloc | `VirtualAlloc` (MEM_COMMIT\|MEM_RESERVE, PAGE_EXECUTE_READWRITE) | Staging buffer for payload |
| 4 — File Ops | `CreateFileA`, `ReadFile`, `CloseHandle` | Read SAM or any target file into staging buffer |
| 5 — Injection | `OpenProcess` (PROCESS_ALL_ACCESS), `WriteProcessMemory` | Write payload into target process |
| 6 — Execution | `CreateProcessA`, `WaitForSingleObject` | Execute payload, synchronize |
| 7 — Cleanup+Persist | `VirtualFree`, `RegOpenKeyExA`, `RegSetValueExA` | Free staging buffer; write HKCU\...\Run for persistence |
| 8 — Finalize | State check, `ExitProcess` | Verify chain success and exit cleanly |

Every `call rax` in every stage dispatches through `LdrpDispatchUserCallTarget`. Every target starts with ENDBR64. CET approves every single branch.

---

## §11 What COOP Doesn't Bypass (and What Actually Stops It)

COOP requires a write primitive to corrupt the vtable pointer — it isn't a standalone vulnerability. It's an exploitation *technique*, not an exploit. To reach the counterfeit vtable, you need:

1. A memory write vulnerability (heap overflow, UAF, type confusion)
2. A heap address leak (to know where to place `fake_vtable`)
3. A C++ object with a virtual function you can trigger post-corruption

What actually restricts COOP:
- **CFG (Control Flow Guard)**: Windows' software CFG maintains a bitmap of valid indirect call targets. If `arg_loader1` isn't in the CFG bitmap, the call faults at the software level before CET even checks. CFG and CET are complementary — CFG narrows the set of valid targets further.
- **ASLR + heap hardening**: Makes fake vtable placement harder without a leak.
- **Safe unlinking / heap metadata integrity**: Prevents the write primitive needed to corrupt the vtable in the first place.

CET plus CFG together close most of the COOP surface. CET alone does not.

---

## §12 Related Writeups

- **GDI Bitmap Abuse / RS2 Bitmap Necromancy** (`../GDI-Bitmap-Abuse-Writeup`, `../RS2-Bitmap-Necromancy-Writeup`): COOP needs a write primitive and a controlled heap address. The Manager/Worker bitmap technique provides arbitrary kernel R/W — the exact primitive COOP would need in a kernel COOP scenario. RS2 Necromancy shows UAF → controlled heap slot, which is the setup step for any vtable corruption.

- **EPT Hypervisor Hook** (`../EPT-Hypervisor-Hook-Writeup`): EPT-level hooking operates below CET entirely — EPT violations happen in Ring -1 before the ENDBR64 check runs. Hypervisor-level code injection sidesteps the entire CET model, making it the strongest counter to IBT enforcement.

- **Double-Fetch Race** (`../Double-Fetch-Race-Writeup`): Temporal gaps produce write primitives. A TOCTOU that corrupts a vtable pointer is the exact prerequisite COOP needs to get started.

- **DMA/IOMMU Abuse** (`../DMA-IOMMU-Writeup`): IOMMU bypass yields physical memory write capability. Writing through physical addresses bypasses the virtual address space where CET and CFG operate — a COOP chain built from DMA-corrupted vtables would pass all software-layer checks.
