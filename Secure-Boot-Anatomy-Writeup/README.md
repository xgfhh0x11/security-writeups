---
title: "The Secure Boot Promise"
subtitle: "Anatomy of a Signature Chain and Its Documented Bypasses"
author: Tyler
date: "2026-05-17"
keywords: [UEFI Secure Boot, Platform Key, KEK, DB, DBX, BootHole, BlackLotus, BootStomp, authenticated variables, chain of trust, signature verification, bootkit, firmware security, anatomical security read]
companion_writeup: "SPI-Firmware-Anatomy (the SPI flash and boot-ROM-chain piece; this writeup is its laser instance on the signature-chain side)"
---

# The Secure Boot Promise
## Anatomy of a Signature Chain and Its Documented Bypasses

---

## Author's Note

Secure Boot is the signature chain on which the running operating
system's integrity rests. Each arrow in that chain is a signature
handoff. The integrity of the OS at boot is the product of every
signature check along the way, in series. Where the chain has
documented gaps in verification ordering, in pre-verification data
parsing, or in the freshness of its revocation list, those gaps
are the subject of the empirical literature.

This writeup reads the chain as a structural object. The intent is
not to celebrate the bypasses, nor to indict the standard. The
intent is the same as in the companion piece on SPI flash and the
boot ROM: dissect the composition, name where each link asserts
what, name where the assertion has historically been invalidated,
and name what assumption each invalidation broke. A reader who
wants to attack the chain can derive their tools from an anatomical
read. A reader who wants to defend the chain can derive their
countermeasures. A reader who wants to do research — to understand
the phenomenon well enough to contribute to the published
literature on bootkit defense, on revocation hygiene, on
authenticated-variable infrastructure — needs the anatomical read
first.

The piece sits in this collection as the *laser instance* of the
boot-ROM-chain section of SPI-Firmware-Anatomy. Where the parent
writeup treated the SPI flash IC, the boot ROM, and the chain of
signatures at the bus and IC level, the present writeup zooms into
the chain's signature side at the level the UEFI specification
defines it: the four variable databases (PK, KEK, DB, DBX), the
authenticated-variable infrastructure that protects their updates,
the SetupMode/UserMode state machine that gates that infrastructure
into being, and the verification ordering that determines whether
a binary boots. The other writeup dissected the chain from the
electrical end; this one dissects it from the cryptographic end;
read together they pair as the same chain seen from both directions.

What follows is six sections. §1 walks the chain — what each
variable is, what it asserts, who verifies it. §2 walks each
link's anatomy at the transition point — what is checked, what
is not, what the authenticated-variable infrastructure does, what
state the platform must be in for the infrastructure to mean
anything. §3 walks the documented bypasses — BootHole, BootStomp,
the longer history of shim and GRUB2 and winload signature
failures, and BlackLotus as the first observed in-the-wild UEFI
bootkit that bypassed Secure Boot on patched, current systems.
§4 walks the DBX problem — the revocation list as an operational
object, the third-party DBX update mechanism, the binaries that
have not been revoked yet and what that means structurally. §5
walks what the literature has shown, with the citations the
sections drew from. §6 closes with open questions and the parts
of the chain the literature has not yet finished reading.

The intended reader is someone arriving at Secure Boot from one of
two directions — the firmware-engineering side (wants to know
what the UEFI specification actually requires of each link in the
chain) or the offensive-security side (wants to know where the
chain has been broken historically and what the breaks invalidated
about the model). The writeup tries to be useful to both without
collapsing into either's vocabulary.

---

## Abstract

This writeup is an anatomical reading of the UEFI Secure Boot
signature chain. It treats the chain — Platform Key, Key Exchange
Keys, allowed-signatures database, forbidden-signatures database,
and the authenticated-variable infrastructure that protects all
four — as a structural object whose composition admits documented
failure states under documented conditions. The contribution is a
link-by-link dissection of what each variable asserts, an account
of the verification-ordering and pre-verification-parsing surface
where the chain has historically been bypassed, a structured tour
of the public bypass record (BootHole CVE-2020-10713, BootStomp,
the shim/GRUB2/winload signature-bypass history, BlackLotus as the
first observed in-the-wild UEFI bootkit to bypass Secure Boot on
fully patched systems), a structural reading of the DBX revocation
list as the chain's only mechanism for retracting trust once
granted, and a list of open questions where the literature is
incomplete. The writeup is companion to SPI-Firmware-Anatomy; the
parent piece reads the same chain from the SPI flash and boot ROM
end, the present writeup reads it from the signature-chain end,
and the two pieces pair as a single dissection of the boot
integrity surface from both directions.

**Keywords:** UEFI Secure Boot, Platform Key, KEK, DB, DBX,
BootHole, BlackLotus, BootStomp, authenticated variables, chain
of trust, signature verification, bootkit, firmware security,
anatomical security read.

---

## 1. The Chain — UEFI Boot Order and Its Four Key Variables

### 1.1 Position in the system

The Secure Boot signature chain begins where the SPI-Firmware-
Anatomy writeup ended: at the moment the platform's boot ROM and
its protected firmware have finished their own verification dance
and are ready to hand off control to a UEFI Boot Services
environment that will, in turn, hand off to an operating-system
loader. At this point the platform is past SEC, PEI, and DXE
phases; it is in the Boot Device Selection (BDS) phase; and the
question Secure Boot is in the business of answering is narrow:
*should the operating-system loader the boot manager has selected
be permitted to execute?*

The answer is yes if and only if the loader's image is signed by
a certificate the chain trusts, hashed by a digest the chain
trusts, and not present on the chain's revocation list. The
machinery that decides this lives in four UEFI variables and one
verification flow. The four variables — Platform Key, Key Exchange
Keys, allowed-signatures database, forbidden-signatures database —
are the chain. The verification flow that consults them is
defined in the UEFI Specification, currently at revision 2.10
(UEFI Forum, 2022), in §32 ("Secure Boot and Driver Signing")
and §8.2 ("Variable Services").

### 1.2 Platform Key (PK)

The Platform Key is the root of the chain. There is exactly one
PK at any time. It is an X.509 certificate whose private key is
held by the platform owner — typically the OEM at first
provisioning and the enterprise IT or end user thereafter,
depending on how MOK/Machine-Owner-Key infrastructure is layered
on top. The PK answers exactly one question: *whose signature is
required to update the KEK?*

PK is itself an authenticated UEFI variable. Updating PK requires
an `EFI_VARIABLE_AUTHENTICATION_2` descriptor — a structure
containing a PKCS#7 SignedData envelope — signed by the current
PK's private key. There is exactly one way to skip this
requirement, and that way is *SetupMode*: when the platform has
no PK enrolled at all, the authenticated-variable infrastructure
treats PK enrollment as unauthenticated, and the first valid PK
write transitions the platform from SetupMode to UserMode. From
that moment on, every subsequent update to PK, KEK, DB, or DBX
requires the proper signature.

The PK's certificate is conventionally the OEM platform vendor
certificate — Lenovo, Dell, HP, Microsoft Surface, depending on
the device. The PK certificate's public key validates the next
layer down.

### 1.3 Key Exchange Keys (KEK)

The KEK is a *database* of certificates, not a single certificate.
Updates to the DB and DBX must be signed by the private key of
one of the certificates in KEK. Updates to KEK itself must be
signed by PK. The composition gives a two-step authority:

- *To rotate KEK*: PK signs the new KEK.
- *To rotate DB or DBX*: any KEK-listed key signs the update.

In practice the KEK on a Windows-shipping platform contains, at
minimum, the *Microsoft Corporation KEK CA 2011* certificate. On
many platforms there is also an OEM-specific KEK entry. The
practical implication: Microsoft, holding the private key for
the Microsoft KEK CA, can push DB and DBX updates that any
Windows-class platform will accept as authenticated. This is
how DBX updates ship for Patch Tuesday revocations.

### 1.4 Allowed Signatures Database (DB)

The DB is the *whitelist* — a database of certificates and/or
hashes against which loaded images are checked. An image whose
PE/COFF Authenticode signature chains to a DB-listed certificate,
or whose SHA-256 hash matches a DB-listed hash, is permitted to
execute (subject to DBX, see below). An image that does not chain
to anything in DB and whose hash is not in DB is rejected with
`EFI_SECURITY_VIOLATION`.

On a Windows-shipping platform DB conventionally contains, at
minimum:

- **Microsoft Windows Production PCA 2011** — the certificate
  Microsoft uses to sign the Windows Boot Manager (`bootmgfw.efi`)
  and other Microsoft-internal boot binaries.
- **Microsoft Corporation UEFI CA 2011** — the certificate
  Microsoft uses to sign third-party UEFI binaries (Linux
  bootloaders, vendor OPROM drivers, recovery tools) after they
  pass Microsoft's review process. This is the certificate every
  signed `shim` binary that any major Linux distribution ships
  chains to.

The DB is the chain's positive authority. Every binary that
boots on a stock Secure-Boot-enabled platform chains to one of
these two certificates (or to an OEM-installed equivalent).

### 1.5 Forbidden Signatures Database (DBX)

The DBX is the *blacklist* — a database of certificates and/or
hashes whose presence in an image's verification path causes
immediate rejection regardless of DB. The DBX exists for one
reason: once a binary has shipped with a valid DB-chaining
signature and has been found to contain a vulnerability that
enables Secure Boot bypass, the platform owner needs a way to
retract trust from that specific binary without revoking the
entire signing certificate (which would brick every other binary
signed under it).

The DBX is the chain's *only* mechanism for retracting trust
once granted. The implications of this fact unfold across §3
and §4 of this writeup: every documented Secure Boot bypass
ends, eventually, with hashes being added to the DBX, and every
unrevoked vulnerable binary is — by the chain's own definition —
still trusted.

### 1.6 The chain as a diagram

```
                       [Platform Owner]
                              |
                              | private key signs
                              v
                          [PK cert]   <-- the root, one cert
                              |
                              | signs updates to
                              v
                       [KEK database]  <-- N certs (typically
                              |                 Microsoft + OEM)
                              | any KEK-listed key
                              | signs updates to
                              |
                +-------------+-------------+
                |                           |
                v                           v
           [DB database]              [DBX database]
           (allowed hashes            (forbidden hashes
            and certs)                 and certs)
                |                           |
                |                           |
                +-----------+   +-----------+
                            |   |
                            v   v
                  [verifier consults both:
                   DBX first, then DB]
                            |
                            v
              [if pass: image executes]
              [if fail: EFI_SECURITY_VIOLATION]
```

Each arrow in the diagram is a signature handoff. PK signs KEK
updates, KEK signs DB and DBX updates, DB and DBX together
authorize image execution. The chain is depth-three on the key
side (PK → KEK → DB/DBX) and depth-N on the certificate-chain
side once an image's Authenticode signature is followed through
intermediate CAs to its DB-listed root.

### 1.7 Who verifies what

The verification labour is distributed across two parties:

- **The UEFI firmware** verifies PK, KEK, DB, and DBX updates
  against the authenticated-variable infrastructure. The
  firmware's Secure Boot image verifier — typically a DXE driver
  — verifies images at `LoadImage()` time.
- **The operating-system loader** (Windows Boot Manager, shim,
  GRUB2 in shim-managed mode) verifies the next stage in the
  chain — typically the kernel and its early-boot drivers —
  against its own embedded certificate or, in shim's case,
  against the *Machine Owner Key* (MOK) database that shim
  maintains independent of UEFI variables.

The first half of this distribution is where the UEFI
specification's authority ends. Once `ExitBootServices()` has
been called and the OS loader has taken over, the verification
of the kernel and beyond is the OS loader's problem, governed by
the OS loader's own integrity contract. The Secure Boot chain
*proper* covers the first half. The OS loader's continuation of
the chain — TPM measurements, Code Integrity, kernel module
signing — is the second half, and its compromise is a distinct
research surface (BlackLotus's persistence mechanism, in §3,
crosses this boundary).

**Assumption invalidated by this section.** *The signature chain
is self-contained.* The corollary: the chain is rooted in a
platform-owner key whose physical custody is the chain's actual
root, and the chain is bounded above by `ExitBootServices()`
beyond which a separate integrity contract takes over. Calling
the whole assembly "Secure Boot" obscures that there are two
domains being composed, neither of which the UEFI specification
covers end-to-end on its own.

---

## 2. Each Link's Anatomy

This section walks the chain at the level of what is actually
checked at each transition. The reading is structural, not
operational — the goal is to surface where each link's assertion
lives, what data the assertion depends on, and where the
assertion's dependencies are reachable to an adversary who has
not yet been granted execution.

### 2.1 The image verification flow

When the boot manager calls `LoadImage()` on a PE/COFF binary
the firmware's Secure Boot image verifier performs, in the
documented order (UEFI Specification §32.5.3.1):

1. Compute the image's authenticode hash — a SHA-256 digest over
   the PE/COFF image with the Authenticode signature field
   itself zeroed for digest purposes.
2. Check the image hash against the *DBX* hash list. If present,
   reject with `EFI_SECURITY_VIOLATION` immediately.
3. Parse the image's WIN_CERTIFICATE structure to extract the
   PKCS#7 SignedData envelope.
4. For each certificate in the SignedData envelope's certificate
   chain, check the certificate against the *DBX* certificate
   list. If any chain certificate is in DBX, reject.
5. Check the image hash against the *DB* hash list. If present,
   accept.
6. For each certificate in the SignedData envelope's chain,
   check whether any of them is in *DB*. If yes, verify the
   signature against that DB-listed certificate. If verification
   succeeds, accept.
7. If none of the above accepted, reject with
   `EFI_SECURITY_VIOLATION`.

The ordering is the load-bearing part. **DBX is checked before
DB.** A binary that is hashed in DBX *and* signed by a DB-listed
certificate is rejected — this is the entire mechanism by which
a vulnerable shim, after it has been revoked, becomes
unbootable on a system whose DBX has been updated. If the
ordering were reversed — if DB acceptance short-circuited DBX
check — revocation would not work, because every revoked binary
is *still* validly signed.

### 2.2 What is checked

The verifier checks:

- That the image's Authenticode hash matches the digest the
  signature was computed over.
- That the signing certificate chains to a DB-listed certificate.
- That the image's hash is not in DBX, that none of the
  certificates in the chain are in DBX.

The verifier does *not* check:

- That the image's runtime behaviour is benign. The verifier is
  a signature checker; it has no semantic model of what the
  binary will do once executed.
- That the image's data dependencies (configuration files,
  embedded resources, files the binary will later open) are
  themselves signed. *This is the surface BootHole, CVE-2024-7344,
  and LogoFAIL all live on.*
- That the binary's behaviour after `LoadImage()` returns is the
  binary's documented behaviour. A signed PE loader that loads
  unsigned content under the cover of its own signature is a
  Secure Boot bypass that requires no verifier bug.

### 2.3 The Authenticated Variable infrastructure

The chain's protection against tampering rests on the UEFI
authenticated-variable infrastructure (UEFI Specification §8.2).
A variable with the `EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS` or
`EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS` attribute
can only be updated by a `SetVariable()` call whose Data field
begins with an `EFI_VARIABLE_AUTHENTICATION_2` descriptor — a
structure containing:

- A timestamp (monotonic per-variable; rollback rejected).
- A PKCS#7 SignedData envelope signed by an appropriate key
  (PK for KEK updates, KEK for DB/DBX updates, DB-listed signer
  for OS-loadable images).

The firmware's `SetVariable()` implementation verifies the
PKCS#7 envelope against the appropriate database before
committing the variable to non-volatile storage. The
verification is the second use of PKCS#7 in the chain (the
first being image-signature verification), and the same
cryptographic libraries are typically used for both.

PK, KEK, DB, and DBX are all authenticated variables. The
infrastructure is the chain's *enforcement layer*: without it
the variables would be mutable from any OS-side runtime caller,
and Secure Boot would collapse.

### 2.4 SetupMode vs UserMode

The chain has two operational states distinguished by a single
UEFI variable, `SetupMode`:

- **SetupMode (`SetupMode = 1`)**: PK is not enrolled. The
  authenticated-variable infrastructure treats PK, KEK, DB, and
  DBX writes as unauthenticated. Any caller can install any
  key. The transition out of SetupMode is enrolling a valid
  PK; once enrolled, the variable flips to UserMode and stays
  there until PK is explicitly deleted (which requires the PK
  private key's signature, returning the platform to
  SetupMode).
- **UserMode (`SetupMode = 0`)**: PK is enrolled. The
  authenticated-variable infrastructure enforces the full
  signature chain on every key-database update.

SetupMode is the chain's first-time-provisioning state. It exists
because the chain has to be bootstrapped from somewhere, and the
bootstrap necessarily admits an unauthenticated key. The
implication, surfaced in §3, is that any path by which a
platform's PK can be deleted — physically, electrically, through
a firmware bug — returns the platform to SetupMode and exposes
the entire chain to re-keying by whoever is present.

### 2.5 The verifier's place in the firmware stack

The image verifier itself is a DXE driver. It is loaded during
DXE phase, before BDS phase, by the firmware's own dispatch
logic, *under the firmware's internal verification* (Intel Boot
Guard, AMD PSP-mediated verification, or vendor-equivalent). The
verifier therefore inherits whatever guarantees the firmware
verification chain provides; if the firmware verification chain
has been bypassed (the SPI-Firmware-Anatomy writeup's territory),
the verifier itself can be substituted with one whose
verification flow accepts arbitrary signatures.

This is the structural connection between the present writeup
and its parent. The signature chain is rooted in PK and verified
by code; the code's integrity is rooted in firmware verification
and the SPI flash that holds the code. Compromise the SPI flash
or the firmware verification, and the signature chain becomes a
formality whose verifier has been replaced.

**Assumption invalidated by this section.** *Verifying the image
is sufficient to verify the boot.* The corollary: the image
verifier verifies the image; the binary's later behaviour, its
data dependencies, and the verifier's own integrity are all
distinct verification problems, and the chain's promise covers
only the first of them.

---

## 3. The Documented Bypasses

This section walks the public record of Secure Boot bypasses.
The reading discipline, in keeping with the writeup's anatomical
register, is to surface for each bypass *which link of the chain
was assumed sound* and *what about that assumption the bypass
invalidated*.

### 3.1 BootHole — CVE-2020-10713

**Disclosed**: 29 July 2020, by Eclypsium (Mickey Shkatov,
Jesse Michael).

**Component**: GRUB2 — specifically the `grub.cfg` parser.

**Mechanism**: GRUB2's configuration file `grub.cfg` is parsed
by a hand-written tokenizer/parser inside GRUB2. The parser's
input buffer is allocated with a length derived from the
configuration file's size, but the parser uses a `strcpy`-style
copy into a fixed-size internal buffer when handling certain
config-file constructs. A malformed `grub.cfg` containing a
sufficiently long token overflows the internal buffer and
overwrites adjacent heap structures, yielding arbitrary code
execution inside GRUB2.

**Why this is a Secure Boot bypass**: `grub.cfg` is not signed.
GRUB2 itself is signed (chains to Microsoft UEFI CA 2011 via
the distribution's shim), but its configuration file is read at
runtime from the ESP and trusted implicitly. An attacker with
write access to the ESP — typically requiring administrator
privilege on the running OS, which is the precondition for the
bypass — replaces `grub.cfg` with a malformed version that
triggers the overflow. GRUB2, which is signed and therefore
permitted to run by Secure Boot, then executes attacker-
controlled code *while still operating under its trusted
signature*. From there the attacker can install a UEFI rootkit,
disable Secure Boot, or modify the boot chain.

**The assumption invalidated**: *that a signed binary's signature
covers its behaviour*. GRUB2's signature attests that the GRUB2
binary is what its publisher said it was. It does not attest
that the binary will not execute attacker-controlled code when
fed a malformed configuration file the binary itself reads
from an unsigned location. The chain's verification stops at
the image; the image's data-handling does not stop with the
verifier.

**Revocation**: Eclypsium and Microsoft coordinated a DBX
update that revoked the hashes of hundreds of vulnerable GRUB2
binaries — every shipped Linux distribution build of GRUB2
predating the fix. The DBX update itself broke previous
versions of installed Linux systems for users who applied it
without first updating their GRUB2; the operational fallout of
the revocation is documented separately and is itself a case
study in revocation deployment cost.

### 3.2 BootStomp — Android variant

**Published**: USENIX Security 2017, by Antonio Bianchi, Yanick
Fratantonio, Aravind Machiry, Christopher Kruegel, Giovanni
Vigna, Simon Pak Ho Chung, Wenke Lee. The full title is
*BootStomp: On the Security of Bootloaders in Mobile Devices*.
Redini et al.'s broader analysis of bootloader security
follows the same research program.

**Scope**: Android bootloaders on Qualcomm, Huawei, MediaTek,
and NVIDIA platforms. Not UEFI Secure Boot directly — Android
bootloaders implement their own chain (typically rooted in a
SoC fuses + ROM verification scheme). The bypasses BootStomp
documents are nonetheless structurally cognate to UEFI Secure
Boot bypasses, and the paper's contribution is to show that the
*pattern* of "signed bootloader parses attacker-controlled
input, parser is exploitable" is general across the bootloader
ecosystem, not specific to GRUB2.

**Mechanism summary**: BootStomp's authors built a custom
symbolic execution tool that taints attacker-reachable inputs
(NVRAM, ESP-equivalent partitions, boot configuration blocks)
through the bootloader binary and looks for unchecked memory
operations downstream of the taint. They found six exploitable
vulnerabilities across five bootloaders: arbitrary memory
writes, code execution, and bypass of bootloader-imposed
verification of the next stage.

**Why this matters to the UEFI Secure Boot reading**: BootStomp
demonstrated, structurally, that the *data dependencies* of a
signed bootloader are the bypass surface. The exact same shape
of bug appeared three years later in BootHole. The UEFI
Specification 2.x's verification flow does not cover this
surface; the verifier verifies the image, and the image's
later data parsing is the image's problem. Every signed
bootloader is a parser of attacker-influenceable input, and
the bootloader's parser is part of the trusted computing base
even though the chain does not name it as such.

**The assumption invalidated**: *that the chain's verification
boundary coincides with the trust boundary*. The chain
verifies the binary; the binary's parser is in the trust
boundary; the chain does not extend to the parser. The same
assumption invalidated by BootStomp on Android in 2017 was
invalidated by BootHole on UEFI in 2020.

### 3.3 The longer history — shim, GRUB2, winload

The bootloader-bypass surface is rich and the public record is
long. A non-exhaustive list of CVEs that materially contributed
to the literature:

- **CVE-2012-1352** (`grub` legacy) — buffer overflow in GRUB
  legacy.
- **CVE-2015-5281** (GRUB2) — password-bypass via backspace
  underflow.
- **CVE-2019-14865** (GRUB2 `acpi` command) — local privilege
  escalation via crafted ACPI table.
- **CVE-2020-10713** (BootHole, GRUB2 grub.cfg parser) — buffer
  overflow, the canonical bypass of the 2020s.
- **CVE-2020-14308 / 14309 / 14310 / 14311** (GRUB2) — the
  cluster of follow-up parser bugs discovered during the
  BootHole post-mortem.
- **CVE-2020-15705 / 15706 / 15707** (GRUB2, shim) — additional
  parser and verification issues.
- **CVE-2022-21894** (`bootmgfw.efi`) — the *baton drop*
  vulnerability in Windows Boot Manager that enabled BlackLotus.
  See §3.4.
- **CVE-2023-24932** (`bootmgr.efi`) — a follow-up
  vulnerability used by BlackLotus variants.
- **CVE-2024-7344** — a signed UEFI utility that loaded
  unsigned content from `cloak.dat` without verification, signed
  by the Microsoft third-party UEFI CA. ESET disclosure.
- **CVE-2025-3052** — a memory-corruption vulnerability in a
  signed UEFI module via an unvalidated NVRAM variable
  (`IhisiParamBuffer`). Binarly disclosure.

The pattern, read across the list, is consistent. Roughly half
the bypasses are *parser bugs* in signed binaries; the other
half are *signed loaders that load unsigned content*. The
second half is the structurally more interesting category —
the parser bugs are conventional memory-safety failures, but
the unsigned-content-loading is a *design* failure of the
binary, not a memory-safety failure, and the chain's
verification cannot catch it.

CVE-2024-7344 deserves a closer reading. The vulnerable binary
was a signed UEFI recovery utility that implemented its own
PE loader. When invoked the utility read a file named
`cloak.dat` from the ESP and parsed it as an embedded PE
image, then loaded and executed the embedded image *without
calling `LoadImage()` and therefore without invoking the
firmware's Secure Boot verifier at all*. The utility had a
valid Microsoft third-party UEFI CA signature; an attacker
who could write to the ESP could place an arbitrary PE inside
a `cloak.dat` and the signed utility would execute it. ESET
disclosed in June 2024; Microsoft issued a DBX update in
January 2025.

The structural reading: a signed binary that re-implements
`LoadImage()` *outside* the firmware's verification flow is a
Secure Boot bypass by design, and there is no mechanism in
the chain to prevent a signed binary from doing this. The
chain's only response is post-facto: revoke the binary's hash
in DBX after discovery.

### 3.4 BlackLotus (2023) — the first observed in-the-wild bypass

**First sampled**: late 2022, sold as a service on underground
forums.

**Analyzed in depth**: ESET, March 2023, by Martin Smolár (the
canonical writeup is *BlackLotus UEFI bootkit: Myth confirmed*).

**Mechanism**: BlackLotus exploits CVE-2022-21894 — the *baton
drop* vulnerability in the Windows Boot Manager. The vulnerable
`bootmgfw.efi` was patched by Microsoft and replaced by a fixed
version. The fixed version was DB-signed. The *vulnerable*
version was also DB-signed (its certificate was not revoked
because revoking the certificate would brick every Windows
binary signed under it). The fix was distributed via the normal
update channel.

The attack: BlackLotus's installer, running on the victim
machine with administrator privilege, copies the *vulnerable
unpatched* `bootmgfw.efi` from a bundled archive into the ESP,
replacing the patched one. Reboot. The vulnerable bootmgfw runs
— it is still validly signed, the DB still trusts its
certificate, the DBX (until the post-disclosure update) does
not contain its hash. BlackLotus exploits CVE-2022-21894 inside
the vulnerable bootmgfw to gain code execution in the boot
environment, installs its rootkit into the firmware NVRAM and
the boot chain, and from that point onward owns the boot chain
on every subsequent boot — *with Secure Boot still enabled and
no warning displayed*.

**Why this is the canonical UEFI Secure Boot bypass**: every
prior bypass either required Secure Boot to be disabled, or
required a vulnerability whose fix had not yet shipped. BlackLotus
required neither. It required that the *vulnerable version of
a previously-signed binary remain valid because its hash had
not been revoked in DBX*. The DBX revocation was the only thing
standing between BlackLotus and a fully patched system, and at
the time the DBX did not contain the hashes. The "fully patched
system bypassed by an old, signed, never-revoked binary" pattern
is what makes BlackLotus the demonstration the literature had
been predicting.

**Persistence**: BlackLotus's rootkit installs into the firmware
NVRAM and survives OS reinstall. Removal requires firmware-level
intervention (DBX update, or in some cases an SPI flash reflash).

**The assumption invalidated**: *that the DBX is current*.
Microsoft's DBX update mechanism was, at the time of BlackLotus's
emergence, not aggressively pushing revocations; the hashes for
the vulnerable bootmgfw versions had not been added even months
after the vulnerability was patched. BlackLotus exploited the
operational gap between *patch availability* and *revocation
deployment*. The structural fact: the chain's revocation list
is the chain's only mechanism for retracting trust, and the
mechanism was operationally slow.

### 3.5 The category map

| Bypass class | Example | What the chain assumed | What was invalidated |
|---|---|---|---|
| Parser bug in signed loader | BootHole CVE-2020-10713 | Signature covers binary behaviour | Signature only covers binary identity |
| Parser bug in bootloader (mobile) | BootStomp 2017 | Trust boundary = verification boundary | Parser is inside trust boundary, outside verification boundary |
| Signed binary loads unsigned content | CVE-2024-7344 | `LoadImage()` is the only loader | A signed binary can implement its own loader and bypass the verifier |
| NVRAM-driven memory corruption | CVE-2025-3052 | NVRAM variable content is trustable | Signed module can use unvalidated NVRAM as a write primitive |
| Unrevoked-but-vulnerable binary | BlackLotus 2023 / CVE-2022-21894 | DBX is current | DBX update cadence lags vulnerability disclosure |
| SetupMode regression | various | Platform stays in UserMode | PK can be deleted under specific firmware conditions |

The category map is the read of §3 in one table. Each row is a
structural invariant the chain assumed and a documented case
where the invariant was not enforced. The first three rows are
*verification-scope* failures; the fourth is a *runtime-data*
failure inside a verified binary; the fifth is a *revocation
operational* failure; the sixth is a *state-machine* failure.
All six map to specific UEFI-specification sections, and the
specification's text in each case prescribes a behaviour that
the documented bypasses show is — in practice — not always met.

**Assumption invalidated by this section.** *The set of binaries
the chain accepts at any moment is the set of binaries that are
both (a) signed by a DB-listed authority and (b) safe to
execute.* The corollary: the two conditions are independent.
(a) is enforced by the verifier; (b) is the product of every
signed binary's own engineering quality and every revocation
that has and has not been pushed. The chain enforces (a) only.

---

## 4. The DBX Problem

The DBX — the forbidden-signatures database — is the chain's
revocation list. It is the chain's only mechanism for retracting
trust from a previously-signed binary without revoking the
binary's signing certificate (which would brick every other
binary signed under it). The DBX is, structurally, the chain's
*regret operator* — the database that exists to say "we should
not have trusted that."

This section reads the DBX as an operational object. The
specification side of the DBX is straightforward; the
operational side is where the chain has historically been
weakest, and the operational side is where the bypasses of §3
live.

### 4.1 The DBX as a UEFI variable

The DBX is a UEFI authenticated variable
(`EFI_IMAGE_SECURITY_DATABASE1` GUID, `dbx` variable name,
`EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_TIME_BASED_
AUTHENTICATED_WRITE_ACCESS`). It stores a list of
`EFI_SIGNATURE_LIST` structures, each of which contains a list
of `EFI_SIGNATURE_DATA` entries. The entries can be:

- `EFI_CERT_SHA256_GUID` — a SHA-256 hash of an image to
  reject.
- `EFI_CERT_X509_GUID` — an X.509 certificate to reject (any
  image whose chain includes this certificate is rejected).
- `EFI_CERT_X509_SHA256_GUID` — a hash-with-timestamp form
  that allows time-bounded revocation of a certificate.

Updates to the DBX are signed by a KEK-listed key — in practice,
on Windows-class platforms, by the Microsoft Corporation KEK CA
2011's private key.

### 4.2 The DBX's storage budget

The DBX lives in NVRAM. NVRAM is finite. The size of the DBX is
bounded by the platform's NVRAM region size, which on most
shipped platforms is in the low tens of kilobytes for the
combined DB + DBX storage. By 2023 — after BootHole, the
BlackLotus-related additions, and the accumulated quarterly
Microsoft revocation pushes — DBX had grown to the point where
some platforms could no longer fit the full DBX update.

Microsoft's response, documented in *KB5025885* and subsequent
updates, was a staged DBX rollout: the DBX update was *split*
into multiple updates that the platform could apply
incrementally, with each update's signature chain verified
against the prior state. The staging is a recognition that the
chain's revocation mechanism has a storage capacity that grows
slower than the volume of binaries the chain needs to revoke.

The structural implication: the chain's revocation mechanism is
*bounded above*. If the DBX fills the NVRAM region, no further
revocations can be added without removing prior entries, and
removing prior entries is itself a security regression. The
chain's only retraction mechanism has a ceiling.

### 4.3 Microsoft's third-party DBX update mechanism

The Microsoft third-party UEFI CA — the certificate against
which most Linux bootloaders (via shim) are signed — has its
own DBX maintenance program. The relevant documents are
Microsoft's *Secure Boot Updates for Servicing* announcements
and the *uefi.org* revocation lists. The mechanism:

1. A vulnerability is disclosed against a third-party UEFI
   binary (typically a Linux shim or GRUB2 variant).
2. The binary's vendor produces a patched build.
3. The patched build is submitted to Microsoft for
   re-signing under the third-party UEFI CA.
4. The patched build is shipped.
5. Microsoft computes the SHA-256 hashes of all known
   vulnerable predecessor builds and adds them to a DBX
   update.
6. The DBX update is shipped through Windows Update (for
   Windows-running platforms) and through firmware-vendor
   update channels (for non-Windows-running platforms).
7. The DBX update is applied at the next boot or reboot.

Steps 5–7 are the bottleneck. The gap between (4) and (5) is
where BlackLotus lived. The gap between (5) and (7) is where
operationally slow revocation deployment lives — a platform
that has not received a Windows Update or has not had a
firmware update in months is running an older DBX.

The colloquial name *Pixie Dust* has been applied (variably,
not always consistently) to the more aggressive form of this
process — pushing DBX updates aggressively even when the
operational cost is high. The trade-off the name encodes:
push aggressively and break installed systems whose unpatched
binaries the update now rejects, or push slowly and leave the
chain exposed to known bypasses. Both choices have been made
at different times.

### 4.4 What hasn't been revoked yet

The DBX, by virtue of being a list of *known revoked* hashes,
implicitly defines what is *not yet revoked*. The literature
on Secure Boot bypass research repeatedly observes that the
gap between disclosure and DBX update is the actionable window,
and that even years after disclosure some hashes remain
unlisted on some platforms.

A non-exhaustive list of categories of binary that, as of
the public-record cutoff for this writeup, remain a concern:

- **Old Linux distribution shim builds** — every shim version
  predating the most recent shim review cycle, on every distro,
  on every architecture. The DBX list of revoked shims is
  long; the list of *unrevoked* old shims is longer.
- **Vulnerable Windows Boot Manager builds** — the BlackLotus
  research demonstrated that even months after Microsoft
  patched CVE-2022-21894, the DBX did not contain the
  vulnerable hashes. The set of hashes that should be in DBX
  but is not at any moment is, structurally, a function of
  the Microsoft DBX update cadence.
- **OEM-signed UEFI utilities** — recovery tools, firmware
  update utilities, diagnostic shells, vendor-shipped UEFI
  applications. These are signed by per-OEM certificates,
  rarely audited at the same depth as Microsoft-signed
  binaries, and rarely revoked even when found vulnerable
  (CVE-2024-7344 was an example of this class).
- **Custom-signed enterprise binaries** — organizations that
  have provisioned their own PKs and signed their own
  binaries are responsible for their own DBX maintenance,
  and the discipline varies widely.

The structural fact: the chain's regret operator is a list. The
list is necessarily incomplete relative to the set of binaries
that *should* be on it. The gap is the chain's continuous
operational vulnerability.

### 4.5 The DBX as a coordination problem

The DBX is, ultimately, a coordination problem. It must be
populated by parties who agree on what should be revoked
(Microsoft, OEMs, Linux distribution maintainers, enterprise
PKI operators), it must be deployed to platforms whose update
channels are heterogeneous (Windows Update, firmware vendor
update tooling, Linux distribution package managers in some
cases), and it must be applied at a moment in the boot flow
where the new entries will take effect before any binary they
revoke is loaded.

Coordination failures along this pipeline are themselves
documented in the literature: DBX updates that broke installed
Linux systems on dual-boot platforms (the BootHole rollout),
DBX updates that have not been signed for non-Windows platforms
in a timely way, DBX entries whose hashes were computed against
a slightly different image than the one in the wild (and
therefore did not match). Each of these coordination failures
has cost the chain weeks or months of effective revocation lag.

**Assumption invalidated by this section.** *Trust, once
revoked, is revoked.* The corollary: revocation is a list, the
list has a budget, the list propagates through update channels
whose cadence and reach are imperfect, and the gap between
disclosure and effective revocation on a given platform is the
actionable window for the bypasses of §3.

---

## 5. What the Literature Has Shown

This section is the citation index for the structural claims in
§1–§4. The intent is to make every empirical claim in the
preceding sections traceable to a published source, in the same
register as the parent SPI-Firmware-Anatomy writeup's
literature-review section.

### 5.1 The specification

The UEFI Specification — currently revision 2.10 (October
2022), published by the UEFI Forum — is the normative document
for everything in §1 and §2. The relevant sections are:

- §32 "Secure Boot and Driver Signing" — the verification flow,
  the variable definitions, the image-signature requirements.
- §8.2 "Variable Services" — the authenticated-variable
  infrastructure, the `EFI_VARIABLE_AUTHENTICATION_2`
  descriptor, the SetVariable() flow.
- §3.3 "Boot Manager" — the BDS-phase boot manager's role in
  selecting the OS loader.
- Appendix M "Cryptographic Hash and Signing Algorithms" —
  the list of accepted hash and signature algorithms.

The specification is freely available from `uefi.org`. The
specification is *normative* — vendor compliance varies in
practice, but the specification defines what the chain is
supposed to be.

### 5.2 BootHole and follow-ups

The canonical BootHole paper is the Eclypsium 2020 disclosure:

> Mickey Shkatov, Jesse Michael. *There's a Hole in the Boot
> (BootHole): Vulnerability in the GRUB2 Bootloader.* Eclypsium
> Research, July 2020. CVE-2020-10713.

The disclosure was accompanied by Microsoft Security Response
Center coordination and a sequence of follow-up CVEs
(CVE-2020-14308 through CVE-2020-15707) discovered during the
post-mortem. Eclypsium's writeup is detailed; the GRUB2
post-mortem analyses by the GRUB2 maintainers and by Canonical,
Red Hat, and SUSE security teams (publicly archived on each
distribution's security advisory site) document the parser-
hardening work that followed.

### 5.3 BootStomp

The BootStomp paper is:

> Antonio Bianchi, Yanick Fratantonio, Aravind Machiry,
> Christopher Kruegel, Giovanni Vigna, Simon Pak Ho Chung,
> Wenke Lee. *BootStomp: On the Security of Bootloaders in
> Mobile Devices.* USENIX Security 2017.

The paper's contribution is twofold: the specific vulnerabilities
they found in five Android-class bootloaders, and the
methodology — taint-tracking symbolic execution from attacker-
reachable inputs through bootloader binaries. The methodology
generalizes; the Redini et al. follow-up work and the broader
bootloader-security literature builds on it.

### 5.4 BlackLotus

The canonical BlackLotus analysis is the ESET 2023 paper:

> Martin Smolár. *BlackLotus UEFI bootkit: Myth confirmed.*
> ESET Research, March 2023. (Public blog post + detailed
> technical writeup.)

The paper documents the malware's exploitation of
CVE-2022-21894, the persistence mechanism, the firmware-NVRAM
implant strategy, and the indicators of compromise. CISA
subsequently issued an advisory (AA23-074A) and Microsoft issued
KB5025885 covering the DBX update strategy. The BlackLotus
research is the most-cited single piece of post-2018 Secure
Boot research because it confirmed a long-predicted threat
model under fully patched, Secure-Boot-enabled conditions.

### 5.5 The CVE record for signed-binary bypasses

The following CVEs are referenced in §3.3 and are individually
documented in the MITRE CVE database and in each affected
vendor's security advisories:

- CVE-2012-1352, CVE-2015-5281 (GRUB legacy / GRUB2 parser).
- CVE-2019-14865 (GRUB2 ACPI command).
- CVE-2020-10713 (BootHole), CVE-2020-14308 / 14309 / 14310 /
  14311 (GRUB2 follow-up cluster).
- CVE-2020-15705 / 15706 / 15707 (GRUB2, shim).
- CVE-2022-21894 (Windows Boot Manager baton drop).
- CVE-2023-24932 (Windows Boot Manager follow-up).
- CVE-2024-7344 (ESET disclosure, signed UEFI utility loading
  cloak.dat without verification).
- CVE-2025-3052 (Binarly disclosure, IhisiParamBuffer NVRAM
  memory corruption in signed module).

Each CVE entry on `nvd.nist.gov` includes the affected vendor's
advisory link and the relevant patch references.

### 5.6 Vendor whitepapers and reference implementations

Three vendor sources are load-bearing for the practical Secure
Boot literature:

- **Microsoft Hardware Compatibility Program** documents — the
  requirements documents that govern what Windows-shipping
  platforms must implement and how. These define the practical
  Microsoft KEK and DB requirements on Windows-class hardware.
- **Intel Trusted Execution Technology** and **Intel Boot
  Guard** whitepapers — the firmware-side verification that
  the present writeup treats as the layer beneath Secure Boot's
  verifier.
- **AMD Platform Security Processor** documentation — the
  equivalent AMD firmware-side verification.

The two-layer composition (firmware-side verification + UEFI
Secure Boot verifier) is documented across these vendor sources
and is the structural connection between the present writeup and
the SPI-Firmware-Anatomy parent.

### 5.7 EDK2 reference implementation

The reference implementation of UEFI — including the Secure Boot
image verifier and the authenticated-variable infrastructure —
is the EDK2 codebase, maintained on `github.com/tianocore/edk2`.
The relevant modules are:

- `SecurityPkg/Library/DxeImageVerificationLib/` — the image
  verifier.
- `MdeModulePkg/Universal/Variable/RuntimeDxe/` — the
  variable-services implementation, including authenticated
  variable handling.
- `SecurityPkg/Library/AuthVariableLib/` — the
  authenticated-variable verifier.

Reading the reference implementation alongside the
specification is the recommended approach for understanding
what the specification's text actually requires of an
implementation. Vendor firmware diverges from EDK2 in
documented and undocumented ways; the divergences are
themselves an active research surface.

### 5.8 LogoFAIL and the data-side adjacency

LogoFAIL (Binarly, 2023) is not strictly a Secure Boot bypass —
it lives inside the firmware-verification layer below — but it
is structurally adjacent and worth naming. LogoFAIL exploits
buffer overflows in the BMP and PNG parsers inside signed
DXE drivers that render the platform boot logo. The logo data
is stored in an unsigned region of SPI flash and is parsed by
a signed driver. A malformed logo can trigger overflow in the
signed parser, yielding code execution *before Secure Boot
runs*. The structural lesson is the same as BootHole's: signed
binaries parse unsigned data, and the unsigned data is the
bypass surface.

The Binarly disclosure (`binarly.io`, December 2023) covers
multiple affected vendors and is the canonical reference.

### 5.9 The literature's shape

Read together, the literature has the following shape:

- A normative specification (UEFI 2.10) that defines the chain.
- An empirical record of *parser bugs* in signed binaries
  (BootHole, BootStomp, LogoFAIL, the GRUB2 follow-up cluster).
- An empirical record of *signed binaries that load unsigned
  content* (CVE-2024-7344, CVE-2025-3052 to a lesser extent).
- A single canonical demonstration of *in-the-wild bypass*
  under patched conditions (BlackLotus / CVE-2022-21894).
- A reference implementation (EDK2) and a set of vendor
  whitepapers that define the practical compliance surface.

The empirical record's *growth* is the literature's most
interesting feature. The rate of disclosed Secure Boot bypasses
has not slowed in the eight years since BootStomp; it has
arguably accelerated, with two major signed-binary bypasses
disclosed in the eighteen months preceding this writeup.

**Assumption invalidated by this section.** *That the chain's
structural problems are known and bounded.* The corollary: the
empirical record is open — new bypasses continue to be
disclosed at a steady cadence, and the literature's job is not
to close the record but to keep it legible.

---

## 6. Open Questions

The list below is the part of the chain the literature has not
yet finished reading. Each item is a specific research surface
where empirical work would clarify a currently-fuzzy structural
question. None of the items are speculative; each is a question
the literature could in principle answer with focused effort.

**Q1. The signed-binary-loads-unsigned-content surface as a
class.** CVE-2024-7344 and CVE-2025-3052 are instances of a
broader pattern: signed UEFI binaries that re-implement
LoadImage()-equivalent functionality without invoking the
firmware's verifier. How large is this class across the
deployed third-party UEFI binary corpus? A systematic audit of
all Microsoft-third-party-UEFI-CA-signed binaries for
unverified-load patterns is, as far as the public literature
goes, not yet done. The corpus is large; the audit is
non-trivial; the result would be a precise count of how much
of the chain's surface is in this category.

**Q2. The DBX storage ceiling.** §4.2 named the structural fact
that the DBX has a finite NVRAM budget and the volume of
revocations is growing. The literature has not yet quantified
the expected timeline at which typical NVRAM budgets become
binding constraints. A study correlating typical DBX size growth
rate with typical NVRAM budgets across the deployed platform
population would name the date by which this becomes a
deployment-blocking concern.

**Q3. The DBX deployment latency distribution.** The gap between
DBX update publication and DBX update *application* on a given
platform is, by anecdote, anywhere from days to never. The
literature does not yet have a careful measurement of this
distribution across the deployed platform population. Such a
measurement — a survey of DBX states across a representative
sample of internet-reachable platforms via TLS handshake
fingerprinting or similar — would name precisely how slow
revocation is in practice.

**Q4. The SetupMode-via-firmware-bug surface.** Returning a
platform to SetupMode requires either deleting PK via an
authenticated PK delete (signed by PK) or finding a firmware
bug that resets the variable. The latter has been demonstrated
sporadically (various LVFS-published advisories cover instances)
but the surface as a class has not been systematically read.
What firmware operations, under what conditions, can reset the
SetupMode variable? A targeted fuzz of vendor SetVariable
implementations against the SetupMode/PK pair would surface
the bugs.

**Q5. The relationship between firmware-side verification
(Boot Guard, PSP) and Secure Boot.** The present writeup names
the firmware-side verification as the layer beneath Secure
Boot. The literature on each is rich; the literature on the
*composition* — what failure modes propagate from one layer to
the other, what redundancies are real and which are nominal —
is thinner. A structured cross-layer threat model treating the
two as a single composed system would clarify which Secure Boot
guarantees rely on which firmware-side properties.

**Q6. The MOK boundary as a Secure Boot extension.** Linux
distributions use shim's Machine Owner Key infrastructure to
extend the chain beyond Microsoft's signing scope. MOK is not
in the UEFI specification; it is shim's own invention. The
literature treats MOK as a Linux operational detail. Reading
it as *part of the chain* — under what conditions a MOK
enrollment is itself a Secure Boot bypass, what the chain's
guarantees mean once MOK is in play — would clarify the
boundary between specification-prescribed and shim-prescribed
behaviour.

**Q7. The post-`ExitBootServices()` continuation as a single
verification problem.** Secure Boot proper ends at
`ExitBootServices()`. The OS loader's continuation — Windows
Code Integrity, Linux module signing, TPM-measured boot — is
the second half of "boot integrity" and is governed by
different mechanisms. The literature reads the two halves
separately. A unified reading — what the OS-side continuation
*assumes* about the UEFI-side chain and how those assumptions
have or have not been met by historic bypasses — would close
the structural gap between the two halves.

---

## References

[UEFI 2.10] UEFI Forum. *Unified Extensible Firmware Interface
  Specification, Version 2.10.* October 2022. Sections §32
  (Secure Boot and Driver Signing), §8.2 (Variable Services),
  §3.3 (Boot Manager), Appendix M (Cryptographic Hash and
  Signing Algorithms).

[Eclypsium BootHole 2020] Shkatov, M., Michael, J. *There's a
  Hole in the Boot (BootHole): Vulnerability in the GRUB2
  Bootloader.* Eclypsium Research, July 2020. CVE-2020-10713.

[Bianchi et al. 2017] Bianchi, A., Fratantonio, Y., Machiry,
  A., Kruegel, C., Vigna, G., Chung, S. P. H., Lee, W.
  *BootStomp: On the Security of Bootloaders in Mobile
  Devices.* USENIX Security 2017.

[ESET BlackLotus 2023] Smolár, M. *BlackLotus UEFI bootkit:
  Myth confirmed.* ESET Research, March 2023.

[ESET CVE-2024-7344] ESET Research. *Under the Cloak of UEFI
  Secure Boot: Introducing CVE-2024-7344.* ESET, January 2025.

[Binarly CVE-2025-3052] Binarly Research. *Another Crack in the
  Chain of Trust.* Binarly, 2025.

[Binarly LogoFAIL 2023] Binarly Research. *The Far-Reaching
  Consequences of LogoFAIL.* Binarly, December 2023.

[Microsoft KB5025885] Microsoft. *KB5025885: How to manage the
  Windows Boot Manager revocations for Secure Boot changes
  associated with CVE-2023-24932.* Microsoft Support, May 2023.

[CISA AA23-074A] CISA. *#StopRansomware: BlackLotus UEFI
  bootkit.* Cybersecurity and Infrastructure Security Agency,
  March 2023.

[CVE-2020-10713] MITRE / NVD. *Vulnerability summary for
  CVE-2020-10713 (BootHole).*

[CVE-2022-21894] MITRE / NVD. *Vulnerability summary for
  CVE-2022-21894 (Windows Boot Manager baton drop).*

[CVE-2023-24932] MITRE / NVD. *Vulnerability summary for
  CVE-2023-24932 (Windows Boot Manager).*

[CVE-2024-7344] MITRE / NVD. *Vulnerability summary for
  CVE-2024-7344.*

[CVE-2025-3052] MITRE / NVD. *Vulnerability summary for
  CVE-2025-3052.*

[Intel Boot Guard] Intel Corporation. *Intel® Hardware Shield
  on Intel vPro® Platforms: Boot Guard Technical
  Overview.* Intel whitepaper, multiple revisions.

[AMD PSP] AMD. *AMD Platform Security Processor: Secure Boot
  Architecture.* AMD technical reference, multiple revisions.

[TianoCore EDK2] TianoCore Project. *EDK II reference
  implementation of UEFI.* `github.com/tianocore/edk2`.
  Modules: `SecurityPkg/Library/DxeImageVerificationLib/`,
  `MdeModulePkg/Universal/Variable/RuntimeDxe/`,
  `SecurityPkg/Library/AuthVariableLib/`.

[Microsoft HCK / HLK] Microsoft Corporation. *Hardware
  Compatibility Program / Hardware Lab Kit documentation —
  Secure Boot requirements for Windows-shipping platforms.*

[Microsoft Secure Boot Advisories] Microsoft Security Response
  Center. *Secure Boot advisories and DBX update notes.*
  Multiple advisories, 2012–present.

[shim project] Garrett, M., et al. *shim — first-stage UEFI
  loader for Linux distributions.* `github.com/rhboot/shim`.
  Source of the MOK infrastructure referenced in §6 Q6.

---

## Appendix A — Pairing with SPI-Firmware-Anatomy

This writeup is the *laser instance* of the boot-ROM-chain
section of the SPI-Firmware-Anatomy collection piece. The two
writeups read the same chain from two complementary directions
and pair, structurally, as the same dissection seen from both
ends.

### A.1 What the parent writeup covered

SPI-Firmware-Anatomy is the wide-survey reading of the boot
integrity surface from the *electrical* end:

- The SPI bus protocol — what is on the wire between the SPI
  controller in the chipset and the SPI flash IC.
- The SPI flash IC — what kind of memory cells, what
  protection registers (WPS, BP bits, SRP), what the chip's
  own firmware-update flow looks like.
- The boot ROM — what is in the on-die mask ROM that the CPU
  executes from reset, what verifications the boot ROM performs
  on the SPI flash content before transferring execution.
- The chain of signatures from boot ROM through firmware
  verification (Intel Boot Guard, AMD PSP) into the UEFI DXE
  environment.
- The four physical fault-injection categories (voltage glitch,
  clock glitch, electromagnetic glitch, SPI bus interception)
  that have been used to bypass the chain at electrical
  layers.
- The empirical literature on fault injection — what has been
  measured on which silicon, by whom.

The parent writeup stops where the present writeup begins. It
covers the chain *up to* the point where the Secure Boot
image verifier loads and starts running; it does not dissect
the verifier or the four variables that drive it.

### A.2 What the present writeup covers

The present writeup is the *cryptographic-end* reading of the
same chain:

- The Platform Key, Key Exchange Keys, allowed-signatures
  database, and forbidden-signatures database as the four
  variables that drive verification.
- The authenticated-variable infrastructure as the chain's
  enforcement layer.
- SetupMode vs UserMode as the state machine that gates the
  enforcement layer into being.
- The image verifier's verification flow and what it checks
  and does not check.
- The bypass record (BootHole, BootStomp, the longer history,
  BlackLotus) as the empirical demonstration of where the
  verification flow has been structurally insufficient.
- The DBX as the chain's revocation list and the operational
  problems that revocation faces.

The present writeup begins where the parent ends and stops at
`ExitBootServices()`. The two-writeup composition covers the
boot integrity surface from electrical bus through to the
handoff to the operating-system kernel.

### A.3 How the two writeups compose

The composition can be read in three ways, depending on the
reader's entry point:

1. **Bottom-up reader** (electrical engineering, embedded
   systems, hardware security): start with SPI-Firmware-Anatomy
   for the bus and flash and boot ROM, then read the present
   writeup for the signature-chain side. The reading order is
   *physical → cryptographic*.

2. **Top-down reader** (software security, malware analysis,
   incident response): start with the present writeup for the
   signature chain and its bypasses, then read SPI-Firmware-
   Anatomy for the layer beneath. The reading order is
   *cryptographic → physical*.

3. **Cross-section reader** (researcher reading for the
   structural pattern): read both writeups' §1 first to get the
   chain's full anatomy, then both §3 sections for the
   bypasses, then both §6 sections for the open questions.
   The reading is *anatomy → bypasses → questions* across both
   writeups.

The third reading is the one this collection is engineered
around. Both writeups are anatomical-register, both have
six-section structures, both close with open questions, and
both pair their open questions across the boundary so that a
single research program can pull from either's question list.

### A.4 The cluster context

The cluster of collection pieces these two sit inside is
broader. The relationships:

- *Mathematical Collapse* is the high-altitude theoretical
  reading — the argument that classical mathematical
  abstractions do not include the silicon they execute on.
- *Silicon Is the Adversary* is the wide-survey reading of
  microarchitectural side-channels post-Spectre. It is at the
  same altitude as SPI-Firmware-Anatomy but on the
  microarchitectural surface rather than the firmware surface.
- *Speculation Barrier Illusion* is the laser instance for
  Silicon Is the Adversary — a CBMC-verified demonstration of
  one specific mismatch.
- *Microarch-Isolation* is the wide-survey reading of
  microarchitectural isolation primitives.
- *SPI-Firmware-Anatomy* is the wide-survey reading of the
  boot integrity surface from the electrical end.
- *The present writeup* is the laser instance for SPI-Firmware-
  Anatomy — the boot-ROM-chain section dissected at the
  signature level.

The pattern across the cluster is *one wide-survey per
research surface, one laser instance per wide-survey*. The
wide-survey gives the map; the laser instance gives the
reproducible reading at one specific point on the map. A
reader finishing the pair (wide-survey + laser instance) on a
given surface has both the structural fluency to navigate the
research literature on that surface and the close-reading
practice to extract a specific contribution from one of its
sub-problems.

The intent of this collection is that any single piece is
useful on its own and the pairs are *more* useful read
together. The present writeup is the closing piece of the
SPI-Firmware-Anatomy pair.

---

*This writeup is the laser-instance companion to
SPI-Firmware-Anatomy in this collection
this collection. Its intent is to read the UEFI Secure
Boot signature chain as a structural object — what each link
asserts, where the chain has historically been bypassed, and
what assumption each bypass invalidated. With acknowledgement
to the academic and industry research communities — at ESET,
Eclypsium, Binarly, the UCSB Seclab and Georgia Tech security
groups whose BootStomp methodology underwrites much of the
modern bootloader-analysis literature, the Microsoft Security
Response Center, the GRUB2 and shim maintainers, and the UEFI
Forum specification editors — whose patient enumeration of the
chain's anatomy and its failure modes the present writeup
synthesizes.*
