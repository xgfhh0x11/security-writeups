---
title: "CVE-2022-37969: How CLFS's Integrity Loop Destroyed Its Own Metadata"
author: Utku
date: 2026
tags: [CVE-2022-37969, CLFS, Windows, kernel, OOB-write, privilege-escalation, metadata-corruption]
license: CC BY 4.0
---

> **Author's Note:** The best kernel bugs aren't the ones where someone forgot a bounds check. They're the ones where the code that's supposed to *protect* integrity is the exact code that *destroys* it. CVE-2022-37969 is that kind of bug. The signature verification loop in CLFS writes sector signatures back into the block header — and at sector index 14, the write lands directly on the `SignaturesOffset` metadata field. The integrity mechanism poisons itself.

---

## Abstract

Windows Common Log File System (`CLFS.sys`) is a kernel-mode logging subsystem used by the OS, NTFS, SQL Server, and others. Its Base Log File (BLF) format carries a `SignaturesOffset` field at offset `0x6C` inside the Base Block header. The `ClfsEncodeBlockPrivate()` function writes each sector's 2-byte signature into an array starting at offset `0x50` using the formula `0x50 + (sector_index × 2)`. Sector index 14: `0x50 + (0xE × 2) = 0x6C` — the field itself. By crafting a BLF file where sector 14's signature is `0xFFFF`, the attacker causes `FlushMetaData()` to overwrite `SignaturesOffset` with `0xFFFF0050`. This corrupted offset bypasses a downstream bounds check in `AllocateSymbol()`, producing a controlled out-of-bounds write that corrupts a `CClfsContainer*` kernel pointer. Dereference yields arbitrary code execution at SYSTEM privilege. Patched in Microsoft's September 2022 Patch Tuesday.

---

## §1 CLFS Architecture — What You're Actually Attacking

CLFS is not a simple file format. It's a transactional kernel logging engine with multi-block redundancy, shadow copies, and marshalling contexts. Understanding its layout is what makes the bug legible.

### Base Log File (BLF) — Six Blocks

```
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  Control Block   │  │   Base Block     │  │  Truncate Block  │
│    (512 KB)      │  │    (512 KB)      │  │    (512 KB)      │
└──────────────────┘  └──────────────────┘  └──────────────────┘
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Control Shadow   │  │  Base Shadow     │  │ Truncate Shadow  │
│    (512 KB)      │  │    (512 KB)      │  │    (512 KB)      │
└──────────────────┘  └──────────────────┘  └──────────────────┘
```

Each block has a shadow copy for crash recovery. The shadow mechanism assumes the primary block's metadata is trustworthy. The exploit undermines that assumption.

### Base Block Layout — The Critical Fields

| Offset | Field | Normal Value | Role |
|---|---|---|---|
| `0x00` | `CLFS_LOG_BLOCK_HEADER` | — | Version, size, checksum |
| `0x50` | Sector Signatures Array | — | 2-byte signature per sector |
| `0x6C` | `SignaturesOffset` | `0x50` | **Where the array starts** |
| `0x70` | `cbSymbolZone` | `0x1000` | Symbol zone byte count |
| `0x74` | `cbContainer` | — | Container segment bounds |
| `0x1BF8` | Sector Signature [14] | `0x0000` | 14th sector's signature |
| `0x1BFC` | Sector Signature [15] | `0x0000` | 15th sector's signature |

`SignaturesOffset` at `0x6C` is the vulnerability's pivot point. Everything in this bug flows through that one field.

### User-Mode API to Kernel Path

```
CreateLogFile()          → CClfsLogFcbPhysical::CreateLogFile()
                            → CClfsBaseFilePersisted::Create()
                              → Base Block allocated, SignaturesOffset = 0x50

AddLogContainer()        → CClfsLogFcbPhysical::AddLogContainer()
                            → cbContainer updated

CreateLogMarshallingArea() → CClfsLogFcbPhysical::CreateMarshallingArea()
                              → Client Context Array built

AllocateAlignedReservation() → CClfsLogFcbPhysical::AllocateSymbol()
                                → cbSymbolZone validation ← BYPASS HERE
```

Each step is legitimate API usage. The exploit doesn't require a kernel driver or special privileges to reach the vulnerable path.

---

## §2 The Root Cause — The Loop That Eats Its Own Metadata

`ClfsEncodeBlockPrivate()` is called during `FlushMetaData()`. Its job: iterate every sector of the block, compute the sector's 2-byte checksum/signature, and write it back into the Sector Signatures Array in the block header.

```c
// ClfsEncodeBlockPrivate — pseudocode
NTSTATUS ClfsEncodeBlockPrivate(PCLFS_BLOCK_HEADER hdr, ULONG blockSize) {
    PUSHORT sigsArray = (PUSHORT)((PUCHAR)hdr + 0x50);  // array base
    ULONG sectorCount = blockSize / 512;

    for (ULONG i = 0; i < sectorCount; i++) {
        USHORT sig = GetSectorSignature(hdr, i);
        sigsArray[i] = sig;                              // write at 0x50 + i*2
    }
    return STATUS_SUCCESS;
}
```

For sector `i = 14` (0xE):

```
write_offset = 0x50 + (0xE × 2) = 0x50 + 0x1C = 0x6C
```

`0x6C` is exactly where `SignaturesOffset` lives in the Base Block header.

The implicit assumption buried in this code: "the sector signature array will never extend far enough to alias with another metadata field." That assumption is wrong by exactly one sector index.

---

## §3 Why Sector 14's Signature Controls the Metadata

Under normal operation, sector 14's signature is a legitimate 2-byte checksum computed from the data in that sector. It isn't attacker-controlled.

The exploit changes this. The attacker directly maps the BLF file into user-mode address space (`CreateFileMapping` + `MapViewOfFile`) and patches two fields:

```c
// Direct BLF manipulation
PBASE_BLOCK bb = (PBASE_BLOCK)MapViewOfFile(hMapping, FILE_MAP_WRITE, ...);

bb->SectorSignatures[14] = 0xFFFFFFFF00000000ULL;  // offset 0x1BF8
*(PUSHORT)((PUCHAR)bb + 0x1BFC) = 0xFFFF;           // sector 15 sig slot
FlushViewOfFile(bb, ...);
```

After this patch:
- `ResetLog()` reads the patched sector 14 signature and propagates it through the internal state
- `FlushMetaData()` calls `ClfsEncodeBlockPrivate()`
- The loop hits `i = 14`, reads the manipulated signature `0xFFFF`
- Writes `0xFFFF` to `hdr + 0x6C` — `SignaturesOffset` is now `0xFFFF0050`

The loop was intended to be a write-only encode pass. Instead, it becomes the corruption vehicle.

---

## §4 Corruption Chain — From Metadata Overwrite to OOB Write

Once `SignaturesOffset = 0xFFFF0050`, every subsequent function that reads it to validate bounds is operating on garbage.

The downstream victim is `AllocateSymbol()`:

```c
// CClfsLogFcbPhysical::AllocateSymbol — pseudocode
NTSTATUS AllocateSymbol(ULONG cbSymbolZone, PVOID *ppSymbol) {
    ULONG sigsOff = this->BaseBlock->SignaturesOffset;  // reads 0xFFFF0050

    // Bounds check intended to prevent overflow:
    if (sigsOff < 0x50 || sigsOff > 0x1000) {
        // BYPASSED — because SignaturesOffset is no longer a pointer into
        // the array; the check's reference range is based on the expected
        // 0x50 baseline, which is now meaningless.
    }

    // cbSymbolZone validation also fails — it depends on sigsOff to compute
    // available space. With sigsOff corrupt, MAX_SYMBOL_ZONE_SIZE calc breaks.

    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, cbSymbolZone, 'CLFS');
    memcpy(buf, source, cbSymbolZone);  // OOB write — cbSymbolZone not constrained
    // CClfsContainer* pointer overwritten
}
```

The OOB write lands past the valid symbol zone into adjacent kernel pool. `CClfsContainer*` — the pointer to the log's container management structure — sits in the adjacent allocation and gets overwritten with attacker-controlled data.

Memory layout after the OOB write:

```
[ Symbol Zone allocation  ]  ← valid, cbSymbolZone bytes
[ CClfsContainer* pointer ]  ← corrupted ← attacker-controlled value
```

---

## §5 Exploit Flow — The Eight Steps

```
1. CreateLogFile()
   → BLF created, SignaturesOffset = 0x50 (normal)

2. AddLogContainer()
   → Container metadata written, cbContainer populated

3. CreateLogMarshallingArea()
   → Client Context Array built with specially crafted cbMarshallingArea
   → Fake Client Context allows subsequent BaseBlock access

4. MapViewOfFile(BLF) + patch sector 14
   → SectorSignatures[14] = 0xFFFFFFFF00000000
   → *(0x1BFC) = 0xFFFF

5. ResetLog()
   → Patched signature read and propagated into internal state

6. FlushMetaData() → ClfsEncodeBlockPrivate()
   → Loop at i=14 writes 0xFFFF to offset 0x6C
   → SignaturesOffset = 0xFFFF0050

7. AllocateAlignedReservation()
   → AllocateSymbol() reads corrupt SignaturesOffset
   → cbSymbolZone validation bypassed
   → OOB write → CClfsContainer* overwritten

8. Dereference corrupt pointer
   → Arbitrary kernel write → token manipulation → SYSTEM
```

Each step is a normal CLFS API call. Steps 4 (direct file map) and 8 (token steal) are the only non-API steps.

---

## §6 The Structural Insight — Implicit Aliasing in Data Layout

The bug is not "missing bounds check" in the simple sense. The bounds check in `AllocateSymbol()` was there. It failed because its inputs were already poisoned. The real root cause is **implicit aliasing between the sector index calculation and a metadata field**.

The `ClfsEncodeBlockPrivate` loop was written with an implicit invariant:

> ∀ i : write_offset(i) = 0x50 + i × 2 lies within the Sector Signatures Array

This invariant is true for sectors 0–12. For sector 14 it produces `0x6C`, which is `SignaturesOffset` — a completely unrelated field that happens to sit at that offset.

No one checked whether the array could alias the header's own control fields. The block layout evolved independently of the signature loop implementation. The collision was invisible until someone looked for it.

The fix Microsoft shipped: add an explicit check that `SignaturesOffset` is within the expected range and that the sector index loop cannot produce an index that falls outside the signature array's *allocated* region within the block header.

---

## §7 Kernel Objects in the Blast Radius

The `CClfsContainer` object manages the physical log container — the file on disk that holds log records. It contains:
- File handle references
- Container size and bounds metadata
- Back-pointer to the owning `CClfsLogFcbPhysical`

Corrupting its pointer gives write-what-where capability at the granularity of whatever `CClfsContainer::SomeFunction()` writes when called post-corruption. Typical follow-on: overwrite `TOKEN` pointer in the current process's `EPROCESS`, substituting a SYSTEM-token address collected via `NtQuerySystemInformation(SystemHandleInformation)`.

This is the same token-steal pattern used in almost every Windows LPE from this era — the CLFS bug is the delivery mechanism, not the escalation primitive itself.

---

## §8 Debugging Artifacts

```
WinDbg commands for CLFS structure inspection:

dt CLFS!_CLFS_LOG_BLOCK_HEADER
dt CLFS!_CLFS_BASE_RECORD_HEADER

Breakpoints at the three critical functions:
bp CLFS!CClfsLogFcbPhysical::ResetLog
bp CLFS!ClfsEncodeBlockPrivate
bp CLFS!CClfsLogFcbPhysical::AllocateSymbol

Key offsets to watch in the Base Block at the AllocateSymbol breakpoint:
  [BaseBlock + 0x6C]  → SignaturesOffset (should be 0x50; corrupted = 0xFFFF0050)
  [BaseBlock + 0x70]  → cbSymbolZone (downstream victim of the bypass)
```

If `[BaseBlock + 0x6C]` is not `0x50` when `AllocateSymbol` is entered, the exploit precondition is met.

---

## §9 Patch — What Changed

The September 2022 Patch Tuesday update (KB5017316) added validation that:

1. `SignaturesOffset` is within `[0x50, block_header_size)` before any subsequent field reads
2. The sector index loop in `ClfsEncodeBlockPrivate` is bounded so that `0x50 + (i × 2)` cannot exceed the allocated signature array region — specifically, it cannot alias `SignaturesOffset` at `0x6C`

One invariant check, inserted at two call sites. The entire 12-year-old logging subsystem was vulnerable because nobody audited sector 14.

---

## §10 Related Writeups

- **Double-Fetch Race Condition** (`../Double-Fetch-Race-Writeup`): Both bugs exploit a temporal or structural gap between a validation step and the use of validated data. CLFS's gap is *spatial* (the array index aliases a control field) rather than temporal, but the formal structure — check happens in a context where its input is already wrong — is identical.

- **GDI Bitmap Abuse / RS2 Bitmap Necromancy** (`../GDI-Bitmap-Abuse-Writeup`, `../RS2-Bitmap-Necromancy-Writeup`): The CLFS OOB write provides a `CClfsContainer*` corruption; the GDI technique provides arbitrary kernel R/W. Both convert a memory corruption primitive into token theft via the same `EPROCESS.Token` overwrite. The underlying LPE chain is the same; the delivery differs.

- **CrackArmor AppArmor LPE** (`../CrackArmor-AppArmor-LPE-Writeup`): Another kernel subsystem (AppArmor's pseudo-file interface) whose security model breaks because a long-standing implicit assumption — "the checking context equals the acting context" — goes unexamined until a CVE surfaces it. Structural cousin to CLFS's "the loop index can't alias a metadata field."

- **EPT Hypervisor Hook** (`../EPT-Hypervisor-Hook-Writeup`): EPT-level hooks can be used to intercept CLFS syscalls at the hypervisor layer for defensive monitoring without touching CLFS.sys itself — the same file I/O that the exploit uses would trigger EPT violations on first access to the BLF mapping.
