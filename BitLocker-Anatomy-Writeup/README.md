---
title: "Anatomy of the BitLocker Stack"
subtitle: "Kernel Driver, TPM Measurement, and the Encrypted Disk"
author: Tyler
date: "2026-05-17"
keywords: [BitLocker, fvevol.sys, TPM, PCR measurement, AES-XTS, full-disk encryption, Windows kernel internals, TPM bus sniffing, cold boot, evil maid, key hierarchy, VMK, FVEK]
cluster_siblings:
  - "Mathematical Collapse"
  - "Silicon Is the Adversary"
  - "Microarch-Isolation"
  - "SPI-Firmware-Anatomy"
  - "Speculation Barrier Illusion"
  - "BFS 2019 Master"
---

# Anatomy of the BitLocker Stack
## Kernel Driver, TPM Measurement, and the Encrypted Disk

---

## Author's Note

BitLocker is the canonical example of a security artefact that is
not one thing. The user-facing concept — "the disk is encrypted" —
collapses into a single noun the multi-layer composition that
actually does the work, and the consequence of that collapse is
that people argue about BitLocker's strength as though it were a
property of an algorithm. It is not a property of an algorithm.
It is a property of a *stack*: a kernel filter driver, a measured
boot chain, a TPM holding a sealed blob, a key hierarchy that
walks from a recovery key down to the per-sector tweak of an
AES-XTS encrypt, and a physical bus running between the CPU and
the TPM chip on a printed circuit board. Each layer has its own
threat model, its own failure modes, and its own observability,
and the composition's strength is bounded by the weakest layer
that the operational scenario actually exposes.

This writeup takes the same third position as the other entries
in the cluster: the anatomical one. The components — `fvevol.sys`,
the TPM, the PCR registers, the LPC/SPI bus, the FVEK, the VMK,
the recovery key, the bootmgr and winload pre-OS chain — are
things in the world. They have electrical, protocol, structural,
and architectural properties. Where the composition is
susceptible, that susceptibility is a structural feature of how
the layers were joined, not a moral failing of any one component
and not a deficit of any one cryptographic primitive. AES-XTS is
not broken. The PCR extend operation is not broken. The TPM 2.0
specification is not broken. What is interesting is what happens
when you read these components as a single object and look at
where the trust boundaries actually run.

The framing matters because BitLocker is one of the most
widely-deployed full-disk-encryption systems in the world and
because the published literature about it is unusually
fragmented. The Microsoft documentation describes the key
hierarchy and the protector types but is silent on the device
stack. Geoff Chappell's reverse-engineering notes describe the
IOCTL surface of `fvevol.sys` but treat the TPM as a black box.
The TPM specification documents the seal/unseal primitive
without reference to the consumer of those primitives. The
cold-boot literature (Halderman et al., 2008) treats the key as
a value in DRAM without reference to how it got there. Henry
Wong's 2021 TPM-sniffing write-up treats the LPC bus as the
object of analysis without reference to the rest of the chain.
The reader who wants a single composite picture has to assemble
it from six or seven sources written for six or seven different
purposes. This document is an attempt at that composite picture.

The structure is observational. Section 1 places BitLocker in
the Windows storage stack and describes what it sits on top of
and what sits on top of it. Section 2 describes the anatomy of
the `fvevol.sys` kernel driver — its position as an NTFS volume
filter, its handling of `IRP_MJ_READ` and `IRP_MJ_WRITE`, its
IOCTL surface, and what it caches in non-paged kernel memory.
Section 3 walks the TPM measurement chain from the platform
reset vector through `bootmgr`, `winload`, and into the kernel,
showing how the PCR-bound seal operation gates VMK release.
Section 4 walks the key hierarchy: VMK, FVEK, key protectors,
recovery key, group-policy-resident escrow, and the specific
AES-XTS configuration BitLocker uses. Section 5 catalogues the
documented bypass surfaces — TPM sniffing on the LPC bus
(Sparks 2006, Wong 2021), DMA attacks at the PCIe boundary,
cold-boot attacks against DRAM remanence, recovery-key exposure
via group-policy escrow, and the structural differences of
BitLocker-To-Go on removable media. Section 6 is an inventory
of what the academic and industry literature has actually
demonstrated, with citations. Section 7 lists open questions
including VBS-protected BitLocker, the Pluton-integrated
key-hierarchy variant, and the post-quantum migration path.

Each section closes with the same form as the rest of the
cluster: a paragraph naming the assumption the corresponding
observation invalidates and identifying the abstraction at
which the susceptibility lives. The reader should come away
with a coherent picture of BitLocker as an anatomical object,
not a catalogue of attacks and defences.

---

## Abstract

This document is a structural reading of the BitLocker
full-disk-encryption stack on contemporary Windows (10 22H2 and
11 23H2). It treats the system as a four-layer composition —
kernel filter driver (`fvevol.sys`), measured boot chain, TPM
seal/unseal primitive, and AES-XTS sector encryption — and
describes each layer's anatomy, its interface to the layers
above and below it, and the trust boundaries the composition
implicitly defines. The published bypass surfaces (Sparks 2006
TPM-reset; Halderman et al. 2008 cold-boot; Wong 2021 LPC
sniffing; DMA attacks against IOMMU-disabled platforms;
group-policy-resident recovery keys) are not framed as attacks
or defences but as instances of where the composition's trust
boundary differs from the user's mental model of it. The
contribution is a single composite anatomy assembled from the
Microsoft documentation, the Windows Internals reference,
Chappell's reverse-engineering notes, and the cited academic
literature, plus a list of open questions that the
VBS-Pluton-post-quantum direction will force the next
generation of this composition to resolve.

**Keywords:** BitLocker, `fvevol.sys`, TPM, PCR measurement,
AES-XTS, full-disk encryption, Windows kernel internals, TPM
bus sniffing, cold boot, evil maid, key hierarchy.

---

## 1. The Position

### 1.1 What BitLocker promises

The user-facing promise of BitLocker is straightforward: if the
disk is lost or stolen, the bytes on the disk are
unintelligible. The promise is conditional on a set of
preconditions the user does not see — the machine was powered
off, the boot chain has not been modified, the recovery key has
not leaked, the TPM has not been physically probed, the system
is not held at the lock screen with the volume already unlocked —
but the conditional structure is invisible from the consumer
view. The system either works or surfaces a recovery prompt;
the boundary between "works" and "recovery" is the only
visible signal.

What BitLocker does *not* promise is more important than what
it promises. It does not promise integrity of the disk against
a running OS — `fvevol.sys` is transparent to authorized
volume readers, which means any code running with the volume
unlocked can read or write it. It does not promise key secrecy
in a running OS — the FVEK is resident in non-paged kernel
memory whenever the volume is mounted. It does not promise
secrecy against a debugger or against kernel code with
sufficient privilege. The promise is a *data-at-rest* promise,
scoped to the state in which the machine is powered off and
the disk is physically removed.

### 1.2 Where BitLocker sits in the stack

BitLocker is an NTFS volume filter driver. The Windows storage
stack, top to bottom, looks like this:

```
                   user-mode I/O
                         |
                         v
                +-----------------+
                |   NTFS / ReFS   |
                +-----------------+
                         |
                         v
                +-----------------+
                |   volmgr.sys    |   (volume manager)
                +-----------------+
                         |
                         v
                +-----------------+
                |   fvevol.sys    |   (BitLocker filter)
                +-----------------+
                         |
                         v
                +-----------------+
                |   partmgr.sys   |   (partition manager)
                +-----------------+
                         |
                         v
                +-----------------+
                |    disk.sys     |
                +-----------------+
                         |
                         v
                +-----------------+
                |   storport.sys  |
                +-----------------+
                         |
                         v
                 +---------------+
                 |   miniport    |   (vendor-specific)
                 +---------------+
                         |
                         v
                  physical medium
```

`fvevol.sys` is positioned below the volume manager and above
the partition manager. Every I/O request packet (IRP) that
travels from the file system toward the physical medium passes
through `fvevol.sys`, and the driver's job is to encrypt outgoing
writes and decrypt incoming reads sector by sector. The driver
is not a file-system filter (which would operate above NTFS) and
it is not a disk filter (which would operate below `disk.sys`);
it sits at the volume layer because the volume is the
granularity at which BitLocker keys are scoped.

### 1.3 What "pre-OS" means in this context

A second positional fact is that BitLocker is partly pre-OS
and partly in-OS. The encryption itself is in-OS — `fvevol.sys`
does not run until the kernel is loaded — but the *unlock* is
gated by a chain that begins before the kernel exists. UEFI
firmware measures itself, hands off to `bootmgr`, which measures
itself and `winload`, which measures itself and the kernel and
its boot drivers. Each measurement extends a PCR register
inside the TPM. By the time `fvevol.sys` is loaded, the TPM
has accumulated a vector of measurements; if and only if that
vector matches what was present at sealing, the TPM unseals the
VMK and the kernel can derive the FVEK and begin decrypting.

This split — encryption is in-OS, unlock is pre-OS-gated — is
the structural origin of most BitLocker discussions. The
encryption side is well-understood AES; the unlock side is a
distributed trust composition that touches firmware, TPM, bus,
and OS, and the composition's perimeter is wider than any
single one of those.

### 1.4 What this section's assumption was

The assumption the section invalidates is the one in which
"BitLocker" refers to an algorithm. It does not. It refers to
a layered composition whose cryptographic core (AES-XTS) is
the least interesting part of its security analysis, because
the layers above the core — the kernel driver, the measured
boot chain, the TPM, the LPC/SPI bus — are where every
documented bypass has lived. The abstraction at which the
susceptibility lives is the *composition*, not the primitive.

---

## 2. The Kernel Driver Anatomy

### 2.1 What fvevol.sys is

`fvevol.sys` is the BitLocker filter driver. It is signed by
Microsoft, ships with every Windows installation since Vista,
and is loaded during boot for every volume that has BitLocker
metadata regardless of whether protection is currently active.
The driver's PE image lives in `%SystemRoot%\System32\drivers`
and its service is `FVEVOL` in the registry.

The driver creates one device object per BitLocker-managed
volume, attached as a filter on top of the underlying volume
device, and a control device object accessible by name for
management operations. The names of the control device objects
have varied across releases (variants seen include
`\Device\FvevolControl` and `\Device\FvevolControlDevice`
behind symbolic links such as `\\.\FvevolControl`); a
running enumeration is the standard way to discover the
current name on a given build.

### 2.2 The volume-filter role

When NTFS submits a read or write for a sector of an
encrypted volume, the IRP travels down the stack and reaches
`fvevol.sys`. The driver intercepts the IRP at its dispatch
routine for `IRP_MJ_READ` or `IRP_MJ_WRITE`:

- For reads, the driver allows the IRP to descend to
  `partmgr`/`disk`/`storport` and reach the physical medium,
  which returns the ciphertext sector. On completion,
  `fvevol.sys` decrypts the sector buffer using AES-XTS
  with the FVEK, with the logical sector number serving as
  the XTS tweak.
- For writes, the driver encrypts the plaintext buffer in
  place (or into a private buffer) before the IRP descends,
  again using AES-XTS keyed by the FVEK and tweaked by the
  sector number.

The decisive structural property of this position is that
`fvevol.sys` is transparent to anything above it. NTFS does
not know it is talking to an encrypted volume; the file
system simply issues sector reads and writes and receives
plaintext back. This is what makes BitLocker compatible with
arbitrary file systems and arbitrary user workloads, and it is
also what determines its threat model: anyone who can issue
I/O to the unlocked volume — any user-mode process with the
right permissions, any kernel code, any debugger — reads
plaintext.

### 2.3 The IOCTL surface

In addition to its data-plane role, `fvevol.sys` exposes a
control-plane IOCTL surface. IOCTL codes in the `0x222000`
range are used for BitLocker management operations: query
volume status, lock/unlock, list protectors, add or remove
protectors, change the encryption state, force a re-key,
manipulate metadata. The exact codes are not part of the
public ABI; they are documented by reverse-engineering
(notably Chappell's BitLocker pages) and they shift between
builds. The surface is large enough that any meaningful
analysis requires enumerating it dynamically, mapping codes
to handlers, and recording for each code the required
privilege level, expected input/output buffer sizes, and the
response under malformed inputs.

User-mode tooling reaches this surface through three
channels:

- The WMI provider `Win32_EncryptableVolume`, which is a COM
  facade over the IOCTL surface.
- The `manage-bde.exe` and `BdeHdCfg.exe` utilities, which
  also use the WMI/COM facade.
- Direct `DeviceIoControl` calls against the control device
  or against a volume handle, which is what reverse-engineering
  tools do.

The control device's security descriptor controls who can
open a handle and which IOCTL codes can be invoked. A standard
analysis step is `sc sdshow fvevol` and the WinDbg `!sd`
extension on the device object to inventory the ACL.

### 2.4 Metadata layout

A BitLocker-protected volume reserves a region (historically
the last megabyte, varying with version) for metadata. The
metadata contains:

- A header with version, status, and volume GUID.
- One or more key protector entries, each containing a
  wrapped VMK and metadata identifying the protector type
  (TPM, TPM+PIN, recovery key, password, startup key, etc.).
- Volume state flags (encrypting, decrypting, paused, suspended,
  decrypted).
- Hardware-encryption and integrity flags.

`fvevol.sys` caches this structure in non-paged kernel memory
on volume mount and consults it for protector operations. The
on-disk structure is replicated in multiple locations on the
volume for fault tolerance.

### 2.5 What lives in non-paged kernel memory

While the volume is unlocked, the FVEK is resident in
non-paged kernel memory inside `fvevol.sys`. The VMK is
discarded after it has been used to unwrap the FVEK; only the
FVEK is retained for the data path. The recovery key, when
not in use, is not resident in memory at all — it lives
externally (a printed sheet, an Active Directory attribute,
an Intune escrow record) and is only loaded for the duration
of a manual unlock operation.

A consequence of this layout is that the FVEK is the
single most concentrated secret in the BitLocker model. Any
mechanism that can read a known region of kernel non-paged
memory — a kernel debugger, a physical memory acquisition tool
running with administrator privileges, a DMA primitive against
the host's DRAM, or in some cold-boot scenarios the DRAM cells
themselves — has, in principle, access to the FVEK.

### 2.6 What this section's assumption was

The assumption the section invalidates is that BitLocker
"encrypts the disk" in a way that is separate from the OS. It
is not. The encryption is performed by a kernel driver running
in the same address space as the rest of the OS, holding the
key in non-paged kernel memory that any sufficiently privileged
agent inside that address space can in principle read. The
abstraction at which BitLocker is independent of the OS is the
*at-rest* abstraction, and the moment the volume is mounted that
abstraction is no longer in force.

---

## 3. The TPM Measurement Chain

### 3.1 The TPM as a state machine

The Trusted Platform Module is a small, physically-distinct
cryptographic processor specified by the Trusted Computing Group.
It implements a fixed instruction set including key generation,
sealed storage, attestation quotes, and a register file of
Platform Configuration Registers (PCRs) that can only be modified
by an *extend* operation. The extend operation takes the current
value of a PCR and a new measurement and computes:

```
PCR_new = HASH(PCR_old || measurement)
```

where `HASH` is SHA-1 on TPM 1.2 and either SHA-1 or SHA-256
(or both, on a dual-bank TPM 2.0) on TPM 2.0. The PCR cannot
be assigned, only extended; the only way to reach a given PCR
value is to perform the same sequence of extends that originally
produced it.

A TPM 2.0 has 24 PCRs in each bank. Convention assigns ranges
to phases of boot: PCRs 0–7 are static-root-of-trust
measurements made by firmware, PCRs 8–15 are made by the OS
loader and kernel, and PCRs 16–23 are reserved for dynamic and
debug use.

### 3.2 The boot chain

A typical BitLocker boot on a UEFI machine measures, in order:

1. **Reset vector and platform firmware** extend into PCR 0 and
   neighbouring registers as the firmware executes. Vendor SRTM
   code, the PEI/DXE dispatcher, and platform configuration data
   contribute measurements.
2. **Option ROMs** loaded by firmware extend into PCR 2.
3. **`bootmgr.efi`** is loaded from the EFI System Partition,
   measured into PCR 4, and dispatched.
4. **The boot configuration data** (the BCD store) is measured
   into PCR 5.
5. **Secure Boot state** — whether Secure Boot is enabled, which
   keys are in the platform key databases — is measured into
   PCR 7.
6. **`winload.efi`** is loaded by `bootmgr`, measured, and
   dispatched.
7. **The kernel and boot-class drivers** are measured as
   `winload` loads them.

The exact PCR set that BitLocker binds to is configurable; the
default profile on modern systems is PCRs 0, 2, 4, 11 (the
BitLocker access control PCR), and depending on configuration
PCRs 7 and 14. On TPM 2.0 systems with Secure Boot enabled, the
default is a Secure-Boot-aware profile centred on PCR 7 (which
reflects the policy rather than the individual binaries).

### 3.3 The seal and unseal primitive

The TPM's seal operation takes a value (the VMK, in BitLocker's
case) and a policy expression — typically an authorization
policy that asserts the bound PCRs must hold specified values —
and returns a sealed blob. The blob is opaque to the host and is
stored alongside the BitLocker metadata. The TPM's unseal
operation takes the blob and the current PCR state; it returns
the sealed value if and only if the policy is satisfied.

In BitLocker's case, the sealed blob is the VMK, and the policy
is the set of PCR values that were current at the time of
sealing. The pre-OS chain, on every boot, extends the PCRs as
above and then asks the TPM to unseal the blob. If the chain is
unmodified, the PCR values match, and the TPM returns the VMK.
If anything in the measured chain has changed — a firmware
update, a Secure Boot policy change, a bootloader patch — the
PCRs differ and the TPM refuses to unseal. BitLocker then
falls back to recovery.

### 3.4 Where the boundary actually runs

The decisive structural property is that the trust boundary
between the host and the TPM runs *physically* between two
chips. On most desktop and laptop platforms before circa 2020,
the TPM is a discrete chip soldered to the motherboard and
connected to the platform controller hub by a Low Pin Count
(LPC) bus or, on newer systems, an SPI bus. The CPU sends TPM
commands to that chip over the bus; the chip returns the
unsealed VMK over the same bus. The PCB traces between CPU and
TPM are the trust boundary, and they are exposed.

On platforms with *firmware* TPM (Intel PTT, AMD fTPM), the
TPM is implemented as firmware running in a security
co-processor inside the SoC. The bus between CPU and TPM in
this case is on-die and is not externally observable, which
changes the threat model materially (and introduces its own
threats, treated in the SPI-Firmware-Anatomy and Microarch-
Isolation cluster siblings).

### 3.5 What this section's assumption was

The assumption the section invalidates is that the TPM is a
secure container which only releases keys to authorized
software. Under the seal/unseal primitive, the TPM is exactly
that — but the *channel* over which "release" occurs is, on
discrete-TPM platforms, a printed-circuit-board trace
carrying the unsealed key in cleartext. The abstraction at
which the TPM is a secure container is the TPM-internal
abstraction; the abstraction at which it is a clear-text
emitter is the platform abstraction. The composition's
strength is bounded by the second of these.

---

## 4. The Key Hierarchy

### 4.1 Sector key: FVEK

At the bottom of the hierarchy is the Full Volume Encryption
Key (FVEK). This is the key actually used by AES-XTS to encrypt
and decrypt sectors. It is generated randomly when BitLocker is
first applied to a volume, has 128 or 256 bits of effective
length depending on configuration (XTS-AES uses two AES keys
internally, so the on-disk-quoted "256-bit XTS" corresponds to
two 256-bit AES keys), and never appears in plaintext on disk.

The FVEK is encrypted by the VMK and stored alongside the
volume metadata. It is loaded into non-paged kernel memory at
mount time and is the secret consumed on every sector read
and write.

### 4.2 Master key: VMK

The Volume Master Key (VMK) is the layer that decouples the
sector key from the user-facing protector. It exists so that
the protector set can be changed (a PIN added, a recovery key
rotated) without re-encrypting the volume. The VMK is generated
randomly, encrypts the FVEK, and is itself encrypted once per
key protector.

A volume with TPM-only protection has one VMK entry, encrypted
by a TPM-sealed key. A volume with TPM+PIN protection has its
VMK encrypted by a key derived from the TPM seal and the PIN.
A volume with a recovery key has an additional VMK entry
encrypted by a key derived from the recovery key. Multiple
entries can coexist; any one of them, if its protector is
satisfied, releases the VMK and through it the FVEK.

### 4.3 Protectors

The protector set is the interface between the
cryptographically-defined VMK and the world. The supported
protector types are:

- **TPM-only.** The VMK is encrypted by a TPM-sealed key
  bound to a PCR policy. On a clean boot with an unmodified
  chain, the TPM unseals automatically and the volume mounts
  without user interaction.
- **TPM+PIN.** The user provides a PIN at pre-boot. The PIN is
  combined with the TPM-sealed key to produce the wrapping key
  for the VMK.
- **TPM+startup-key.** A binary key on a FAT-formatted USB
  device is required at pre-boot.
- **TPM+PIN+startup-key.** The full three-factor combination.
- **Password.** A user-provided password is run through
  PBKDF2-HMAC-SHA256 with a per-volume salt to produce the
  wrapping key. This is the standard protector for removable
  drives (BitLocker-To-Go).
- **Recovery password (numerical key).** A 48-digit
  numerical key generated at provisioning time and stored
  out-of-band (printed, in Active Directory, in Microsoft
  account, in Intune). The recovery password derives a
  wrapping key for an emergency VMK entry.
- **Recovery key file.** A binary key file equivalent in
  function to the recovery password.
- **Smart card.** A smart-card-resident key wraps the VMK.

### 4.4 The recovery path

The recovery protector is the operational backstop. If the TPM
refuses to unseal (PCR mismatch), if the user forgets the PIN,
if the hardware is replaced, or if the volume is moved to a
different machine, the volume mounts via the recovery
protector. This is the protector with the broadest threat
surface because it is the protector that does not depend on
the machine being intact: the recovery key alone is enough.

Group policy can require that the recovery key be escrowed to
Active Directory or to Microsoft's Azure-AD-backed account
service before provisioning is permitted to complete. This
makes the recovery key recoverable but also makes the AD
attribute or the Microsoft-account record a key-equivalent
secret.

### 4.5 The AES-XTS configuration

BitLocker on modern Windows uses AES-XTS as specified by
IEEE 1619 and approved by NIST in SP 800-38E. The block
encryption is AES (128 or 256-bit, depending on group-policy
configuration), and the XTS tweak is derived from the logical
sector number. The mode is appropriate for fixed-size,
random-access block devices: it permits independent re-encryption
of any single sector, makes the ciphertext indistinguishable from
random for non-equal plaintexts at the same sector, and avoids
the malleability of CBC at the cost of being non-authenticated.

The non-authentication is structural: AES-XTS does not detect
ciphertext tampering. A modification to a sector's ciphertext
produces a deterministic, attacker-controlled plaintext
modification on decrypt. BitLocker does not layer a MAC over
AES-XTS in its standard configuration; the integrity story is
delegated to the file system and to the measured-boot chain.

### 4.6 What this section's assumption was

The assumption the section invalidates is that the key hierarchy
is single-rooted. It is not. It is multi-rooted: every protector
is a potential root. The TPM root, the PIN root, the recovery
key root, the smart card root, and the password root are
parallel paths to the VMK, each with its own threat surface and
its own out-of-band storage. The abstraction at which BitLocker
has "one key" is the FVEK abstraction; the abstraction at which
the security analysis must be done is the protector abstraction,
where the system has as many key-equivalents as it has
protectors.

---

## 5. The Documented Bypass Surfaces

This section is an inventory of the documented surfaces at which
the BitLocker composition's trust boundary can be observed to
differ from the user's mental model of it. The treatment is
anatomical: each surface is a fact about the composition's
structure, not a recipe.

### 5.1 TPM bus sniffing on discrete TPMs

The most-discussed surface in the 2020s literature is the LPC
or SPI bus between the CPU and a discrete TPM chip. On
TPM-only configurations, the unsealed VMK travels from the TPM
to the CPU over this bus in cleartext, because the bus protocol
specifies no encryption and the TPM 2.0 specification's
session-encryption feature is not used by BitLocker in its
default configuration (a fact independently observed by Wong
and by other reverse-engineers). A logic analyser clipped to
the bus traces records the VMK as it transits.

The technique was demonstrated in proof-of-concept form by
several researchers; Henry Wong's 2021 write-up is widely
cited as the most accessible end-to-end demonstration of a
TPM-only laptop being unlocked via LPC sniffing in a few
hours of bench work using off-the-shelf logic analysers. The
earlier Sparks 2006 TPM-reset paper documented an adjacent
technique against TPM 1.2 — a low-level reset signal that
restores PCRs without resetting the rest of the chip — which
permitted a chosen-PCR-state replay; the 2.0 spec mitigated
this particular variant but the bus-cleartext property is
independent.

Mitigations exist at the platform level (TPM 2.0 session
encryption, firmware TPMs on the SoC die, full discrete-to-fTPM
migration); BitLocker's reliance on the unencrypted-bus
configuration of TPM 2.0 is a configuration property, not a
cryptographic one. On platforms with firmware TPM, the bus is
on-die and the observation surface disappears, although it is
replaced by the surfaces specific to the security co-processor
(Intel ME/CSME and AMD PSP families).

### 5.2 DMA attacks at the PCIe/Thunderbolt boundary

A running, unlocked Windows machine holds the FVEK in non-paged
kernel memory. A peripheral device that can perform bus-mastering
DMA — historically FireWire, latterly Thunderbolt 3/4 and
PCIe-hotplug-capable interfaces — can in principle read any
physical address, including the page containing the FVEK, if
the IOMMU is disabled or the device's address space is not
constrained.

Modern Windows defends this surface with Kernel DMA Protection
(KDP), which requires platform IOMMU support and which
constrains pre-boot and lock-screen Thunderbolt devices to a
restricted address space. Pre-KDP platforms and platforms with
KDP disabled retain the surface. The surface is independent of
BitLocker's cryptography; it is a property of how the FVEK
lives in DRAM once the machine is running.

### 5.3 Cold-boot attacks against DRAM remanence

The Halderman et al. 2008 USENIX Security paper, "Lest We
Remember: Cold Boot Attacks on Encryption Keys," established
that DRAM contents do not vanish instantly on power-off. At
room temperature, DRAM cells retain their state for seconds
to minutes; at low temperatures (a can of compressed-air
duster sprayed onto the modules), retention extends to tens
of minutes. A machine that is powered off while the volume is
unlocked, then powered back on into a minimal recovery
environment within the retention window, exposes the FVEK in
the DIMMs.

The structural property the paper observes is that "powered
off" is not equivalent to "memory cleared." BitLocker's
threat model assumes the former implies the latter; it does
not. Modern platforms ship with DRAM-clear-on-reset firmware
behaviour for some configurations, and BitLocker provides a
group policy ("Allow standby states (S1-S3) when sleeping")
that constrains the states in which the machine is permitted
to be left, but the underlying physical fact about DRAM
remains.

### 5.4 Recovery-key exposure through escrow

The recovery key, by virtue of being the operational backstop,
is a VMK-equivalent secret. Every system that stores it
externally — Active Directory's `msFVE-RecoveryInformation`
attribute, Azure AD's BitLocker-key escrow service, Microsoft
account's online backup, Intune's tenant-side records, or a
printed sheet in a desk drawer — is a system that must be
trusted at the same level as BitLocker itself.

The structural observation is that the security perimeter of a
BitLocker deployment that uses recovery-key escrow is not
"the encrypted disk." It is "the encrypted disk plus every
system that holds the recovery key." A compromise of the AD
domain, of the Azure AD tenant, of the Microsoft account, or
of a person's filing cabinet is sufficient to dissolve the
encryption. This is not a cryptographic defect; it is a
property of where the key has been put.

### 5.5 BitLocker-To-Go on removable media

BitLocker-To-Go is the removable-media variant. It does not
have a TPM in the loop, because the volume is meant to be
mountable on machines other than its host. The standard
protectors are password and smart card, and a recovery key.
The cryptographic primitives are the same (AES-XTS, PBKDF2 for
password protectors), but the measured-boot chain is absent,
and the pre-OS unlock UI is absent (the volume is unlocked at
file-system mount time on Windows).

The structural difference is that on a fixed system disk, the
TPM contributes a hardware-bound factor that is unavailable
off-platform; on a removable disk, that factor cannot exist
without precluding the device's portability. BitLocker-To-Go
is therefore a *password-equivalent* full-disk encryption
system, with the password's strength determining the system's
strength, and PBKDF2's iteration count determining the cost of
guessing.

### 5.6 Evil-maid and bootloader modification

The evil-maid scenario assumes physical access to a powered-off
machine for a short interval (a hotel-room cleaning visit, a
border-crossing inspection, a left-on-a-desk lunch break). The
attacker modifies the bootloader to capture credentials on the
next boot — historically, replacing `bootmgr.efi` with a
patched version that prompts the user for their PIN and writes
it to a hidden region.

The measured-boot chain is the defence: any modification to
`bootmgr.efi` extends a different value into PCR 4, the TPM
refuses to unseal, and BitLocker drops into recovery. The
user sees the recovery prompt and is alerted that something
has changed. The structural observation is that this defence
depends on the user *noticing* and *acting on* the recovery
prompt rather than entering the recovery key out of frustration;
the social-engineering layer of the chain is the layer the
PCR mechanism cannot reach.

### 5.7 Configuration drift and group policy

A non-physical surface is configuration drift. Group policy can
weaken BitLocker in many ways without disabling it: permit
no PIN, permit Secure Boot disabled, escrow the recovery key
to a soft store, permit S3 sleep, disable Kernel DMA Protection.
Each of these decisions is reasonable in some operational
context and weakens the composition in another. The
documented attack against this surface is a registry/WMI
modification to the `HKLM\SOFTWARE\Policies\Microsoft\FVE`
hive by a process with sufficient privilege, followed by
re-keying or by a policy-driven re-protector that uses the
weakened settings.

The structural property is that BitLocker's strength is
configuration-dependent in a way that is not surfaced at the
user-facing layer ("BitLocker is on"). Two machines with the
same "BitLocker is on" status can be on radically different
parts of the security/usability frontier.

### 5.8 What this section's assumption was

The assumption the section invalidates is that BitLocker
bypasses are exotic. They are not. Each surface in the
inventory is a structural property of how the composition
joins its layers: the TPM-CPU bus is a PCB trace, the FVEK
lives in DRAM, DRAM has remanence, recovery keys live in
escrow, removable-media variants cannot have a TPM, evil-maid
defences depend on the user, and the configuration surface is
wide. The abstraction at which BitLocker is "secure full-disk
encryption" is the cryptographic-primitive abstraction; the
abstraction at which it is a specific operational composition
with documented bypass surfaces is the platform abstraction.

---

## 6. What the Literature Has Shown

This section catalogues the documented results that establish
the structural claims in §5. Each item names the work, the
year, the venue or distribution channel, and the specific
structural fact it established.

### 6.1 The cold-boot paper

Halderman, Schoen, Heninger, Clarkson, Paul, Calandrino,
Feldman, Appelbaum, and Felten, "Lest We Remember: Cold Boot
Attacks on Encryption Keys," USENIX Security 2008, established
DRAM remanence experimentally and demonstrated FVEK extraction
from a Vista-era BitLocker-protected laptop using straightforward
bench equipment. The paper is the founding work in the
DRAM-as-disclosure-channel literature; its observations have
been refined for DDR4 and DDR5 by subsequent work (Bauer et
al., "Lest We Forget," CCS 2016; Anagnostopoulos et al. on
DDR4 remanence) but the structural fact — power-off is not
memory-clear — is the durable contribution.

### 6.2 The TPM-reset paper

Sparks, "A Security Assessment of Trusted Platform Modules,"
Dartmouth College technical report, 2007 (often cited as
"2006" after the original work). The paper documented that on
TPM 1.2 the chip's reset line could be asserted independently
of the rest of the platform, leaving the host running but the
PCRs reset to their power-on values. A subsequent extend
sequence could then be issued by host code, populating the
PCRs with any chosen values. This permitted any pre-boot-bound
seal to be opened.

TPM 2.0 specification mitigates the specific reset behaviour,
but the structural lesson — that the TPM's physical signals
are part of its threat surface — has been generalised into the
subsequent bus-sniffing literature.

### 6.3 Bus sniffing on TPM 2.0

Henry Wong, "Sniffing BitLocker Keys from a TPM," personal
write-up published 2021 on his website, is the most-cited
end-to-end demonstration of LPC-bus sniffing against a modern
laptop with TPM-only BitLocker. Wong's contribution is
methodological: a low-cost logic analyser, a soldered tap into
the LPC bus, and a decoder for the TPM 2.0 command set are
sufficient to recover the VMK on unseal. Related work by
Pulse Security ("Extracting BitLocker keys from a TPM"),
Microsoft's own Black Hat advisories, and Olle Segerdahl and
Pasi Saarinen's 2018 F-Secure work (cold-boot 2.0 on modern
DDR4 platforms) covers adjacent ground.

The structural fact these works establish is that the
discrete-TPM bus is a cleartext key channel for the BitLocker
configuration set Microsoft documents as default.

### 6.4 DMA and Thunderclap

Markettos, Rothwell, Gutstein, Pearce, Neumann, Moore, and
Watson, "Thunderclap: Exploring Vulnerabilities in Operating
System IOMMU Protection via DMA from Untrustworthy
Peripherals," NDSS 2019, established that Thunderbolt and
PCIe peripherals on then-current systems could bypass IOMMU
configurations that operating systems considered protective.
The paper's contribution is the demonstration that DMA-attack
surface had survived a generation of mitigations and that the
attack remained tractable against modern OSes.

Microsoft's Kernel DMA Protection, introduced in Windows 10
1803 and extended in subsequent releases, is the platform
response. The structural fact remains that DMA is a memory
read on the platform memory bus, and that wherever the FVEK
lives in DRAM, a DMA primitive that reaches that page
recovers it.

### 6.5 Windows Internals and Russinovich

Russinovich, Solomon, Allchin, Yosifovich, and Ionescu,
*Windows Internals* (variously editions, Microsoft Press,
2009–2022), is the reference work for the Windows kernel
storage stack and for the position of filter drivers within
it. The treatment of `fvevol.sys` is brief but authoritative
on the device-stack layering and on the volume-filter
contract. The book is the source for the IRP-dispatch
sequence given in §2 and for the broader Windows kernel
context invoked throughout.

### 6.6 The Geoff Chappell notes

Chappell's online BitLocker pages
(`geoffchappell.com/notes/windows/bitlocker/`) are the most
detailed publicly-available description of the `fvevol.sys`
IOCTL surface. The pages are organised by IOCTL code and
record, per code, the build range in which the code is
present, the expected input/output buffer shape, and (where
known) the operation performed. The pages are uneven and
based on reverse-engineering rather than Microsoft
documentation, but they are the standard starting point for
analysis of the control-plane surface.

### 6.7 The Microsoft BitLocker documentation

Microsoft's official documentation
(`learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/`)
covers the user-facing key hierarchy, the protector types,
the group policy surface, the recovery key flow, and the
WMI/PowerShell API. It is silent on the IOCTL surface and on
the device-stack layering. It is the canonical source for
the configuration surface and for the documented threat
model boundary (the "data-at-rest" framing).

### 6.8 Academic crypto-storage literature

The broader academic literature on storage encryption modes
includes Rogaway's analysis of XEX/XTS, the IEEE 1619
standardisation process, and Ferguson's 2006 Microsoft
white paper, "AES-CBC + Elephant diffuser: A Disk Encryption
Algorithm for Windows Vista," which described BitLocker's
original pre-Windows-10 mode. The Elephant diffuser was
removed in Windows 8 in favour of straight XTS-AES, a
decision documented in Microsoft's release notes and
discussed at length in Ferguson's own retrospectives. The
structural fact is that BitLocker's cryptographic mode is a
design decision with a history, not a fixed property.

### 6.9 What this section's assumption was

The assumption the section invalidates is that the BitLocker
literature is unified. It is not. The cold-boot literature,
the TPM-bus literature, the kernel-driver reverse-engineering
literature, the Microsoft documentation, the standards
literature, and the configuration-surface literature each
describe a different slice of the same composition, written
for different audiences and with different framings. The
abstraction at which the composition is well-described in any
single source is no abstraction at all; the composite picture
must be assembled.

---

## 7. Open Questions

The questions below are open in the sense that the published
literature does not yet establish, for each one, a settled
structural answer. They are the directions the next generation
of this composition will force.

### 7.1 VBS-protected BitLocker

Virtualization-Based Security (VBS) introduces a hypervisor
layer beneath the Windows kernel, with isolated user-mode
processes (trustlets) running in Virtual Trust Level 1
inaccessible to VTL 0 kernel code. The question for BitLocker
is whether the FVEK can be moved into a VTL 1 trustlet and
the AES-XTS data path serviced from there, with the result
that a VTL 0 kernel compromise no longer exposes the FVEK in
non-paged memory.

The structural answer is partly known: Microsoft has published
work on Credential Guard's VTL 1 isolation of NTLM and Kerberos
secrets, and on Secure Launch's use of DRTM for VBS-bootstrap
integrity. The extension to BitLocker key isolation has been
discussed but not, at time of writing, fully documented in the
public sources.

### 7.2 Pluton-integrated key hierarchy

Microsoft Pluton is a TPM-equivalent security processor
integrated on-die with the CPU in supported AMD, Intel, and
Qualcomm platforms. Pluton's design eliminates the
external-bus TPM-sniffing surface (§5.1) by placing the TPM
on the same die as the CPU. The question is what other
surfaces it introduces — Pluton firmware update flow, Pluton
attestation chain to Microsoft cloud services, Pluton-resident
keys not accessible to non-Microsoft software — and how
BitLocker's threat model changes once Pluton is the
default rather than discrete TPM.

The structural answer here is just beginning to be
documented; Microsoft's Pluton white papers describe the
intended architecture but the third-party analytical
literature is sparse.

### 7.3 Post-quantum migration

AES-XTS is symmetric-key and is not directly threatened by
known quantum algorithms beyond a square-root speedup
(Grover) that the 256-bit configuration already over-provisions
against. The migration question is therefore not "replace
AES-XTS" but "replace the asymmetric parts of the trust
chain." The TPM uses RSA and ECDSA in its attestation and
sealing flows; the Microsoft account recovery escrow uses
asymmetric crypto for transport; the firmware-signing PKI
underneath Secure Boot is asymmetric.

The structural question is which of these need to migrate to
post-quantum primitives on what timeline, and what the
backward-compatibility constraints look like for a system as
widely-deployed as BitLocker.

### 7.4 Removable-media TPM equivalence

BitLocker-To-Go's password-equivalent property (§5.5) is
structural rather than incidental: a removable device has no
host-bound trust anchor. The question is whether some form of
host-bound factor — a host-signed challenge cached on first
use, a Pluton-attested portable factor, a phone-based pairing
analogous to FIDO2 hardware-bound credentials — could be
combined with the removable disk to produce a hybrid factor
that retains portability while binding to known hosts.

### 7.5 Recovery-key escrow without trust

The recovery-key escrow surface (§5.4) is a single-point-of-trust
in any system that uses it, and most operational BitLocker
deployments do. The open question is whether a threshold-secret
escrow (a Shamir-style split across multiple cloud providers, or
a multi-party-computation backed by Microsoft's existing custody
flow) could provide recovery without making any single escrow
holder a VMK-equivalent secret.

### 7.6 Telemetry and observability gaps

The kernel and configuration sides of BitLocker are documented;
the bus side is not observable from the OS. A platform that
could expose to the OS the fact that the TPM is being
externally probed — a tamper-evident bus, a TPM-side
session-encryption-was-not-used counter, a Pluton attestation
that the channel was on-die — would let detection capabilities
reach a layer they currently cannot.

### 7.7 Configuration-surface formalisation

The configuration surface (§5.7) is currently described by
prose in the group-policy reference. The open question is
whether the configuration space could be formalised — a typed
policy language with semantic constraints, a static analyser
that flags policy combinations that fall below a documented
threat model — so that the "BitLocker is on" status carried
a meaningful invariant about the composition's parameters
rather than an opaque flag.

---

## References

1. Halderman, J. A., Schoen, S. D., Heninger, N., Clarkson, W.,
   Paul, W., Calandrino, J. A., Feldman, A. J., Appelbaum, J.,
   and Felten, E. W. "Lest We Remember: Cold Boot Attacks on
   Encryption Keys." USENIX Security Symposium, 2008.
2. Sparks, E. R. "A Security Assessment of Trusted Platform
   Modules." Dartmouth College Computer Science Technical
   Report TR2007-597, 2007.
3. Wong, H. "Sniffing BitLocker Keys from a TPM." Personal
   write-up, 2021. Available at the author's website.
4. Markettos, A. T., Rothwell, C., Gutstein, B. F., Pearce, A.,
   Neumann, P. G., Moore, S. W., and Watson, R. N. M.
   "Thunderclap: Exploring Vulnerabilities in Operating System
   IOMMU Protection via DMA from Untrustworthy Peripherals."
   NDSS, 2019.
5. Russinovich, M. E., Solomon, D. A., Allchin, J., Yosifovich,
   P., and Ionescu, A. *Windows Internals*. Microsoft Press,
   various editions, 2009 through 2022.
6. Chappell, G. "BitLocker." Personal site
   `geoffchappell.com/notes/windows/bitlocker/`, ongoing.
7. Microsoft Corporation. "BitLocker Overview" and related
   topics, `learn.microsoft.com/windows/security/
   operating-system-security/data-protection/bitlocker/`.
   Reference documentation, ongoing.
8. Ferguson, N. "AES-CBC + Elephant Diffuser: A Disk Encryption
   Algorithm for Windows Vista." Microsoft white paper, 2006.
9. Rogaway, P. "Efficient Instantiations of Tweakable
   Blockciphers and Refinements to Modes OCB and PMAC."
   ASIACRYPT, 2004.
10. IEEE Std 1619-2018. "IEEE Standard for Cryptographic
    Protection of Data on Block-Oriented Storage Devices."
    IEEE, 2018.
11. NIST Special Publication 800-38E. "Recommendation for Block
    Cipher Modes of Operation: The XTS-AES Mode for
    Confidentiality on Storage Devices." NIST, 2010.
12. Trusted Computing Group. "TPM 2.0 Library Specification,"
    parts 1–4. TCG, latest revision.
13. Trusted Computing Group. "PC Client Platform TPM Profile
    Specification for TPM 2.0." TCG, latest revision.
14. Segerdahl, O., and Saarinen, P. "Cold Boot Attacks Are Still
    Hot: Security Analysis of Memory Scramblers in Modern
    Processors." F-Secure technical report, 2018.
15. Bauer, J., et al. "Lest We Forget: Cold-Boot Attacks on
    Scrambled DDR3 Memory." DFRWS, 2016.
16. Microsoft Corporation. "Kernel DMA Protection for
    Thunderbolt 3." Microsoft Learn documentation, ongoing.
17. Microsoft Corporation. "Microsoft Pluton Security
    Processor." Microsoft architectural overview, 2020 and
    subsequent updates.
18. Microsoft Corporation. "Virtualization-Based Security
    (VBS)." Microsoft Learn documentation, ongoing.
19. NVISO Labs. "Defeating BitLocker via TPM Sniffing." Blog
    post, 2023.
20. Pulse Security. "Extracting BitLocker Keys from a TPM."
    Blog post, ongoing.

---

## Appendix A — Related Writeups

This writeup is one entry in a cluster of structural
observations collected here. The cluster's organising principle is
the anatomical register: components are described as objects
with electrical, protocol, structural, and architectural
properties, and the susceptibilities of compositions are
treated as properties of how those components were joined.

### A.1 Direct pairings

**Microarch-Isolation** is the cluster sibling that develops
the TPM and TEE substrate that BitLocker depends on. The
TPM-bus surface in §5.1, the firmware-TPM transition in §3.4,
and the Pluton question in §7.2 all read naturally against
the wider TPM/TEE anatomy developed there. A reader who wants
to understand why the §3 measurement chain has the shape it
does should pair this document with Microarch-Isolation.

**SPI-Firmware-Anatomy** is the cluster sibling that develops
the firmware substrate beneath the measured-boot chain.
PCRs 0–7 are extended by code that SPI-Firmware-Anatomy
describes; the question of what is *in* PCR 0 is a question
about platform firmware, not about BitLocker. The pairing
points the §3 reader at the firmware-layer detail.

**BFS 2019 Master** is the cluster sibling that develops
Windows kernel internals in depth, including the IRP dispatch
model and the device-stack layering invoked in §2. A reader
who wants to follow `fvevol.sys`'s IRP path through the
storage stack should pair this document with BFS 2019.

### A.2 Conceptual pairings

**Silicon Is the Adversary** establishes the cluster's
position that the threat model and the defensive model live
at different abstractions. BitLocker is a textbook example of
that asymmetry: the threat surfaces (bus traces, DRAM cells,
PCIe transactions, escrow records) live at layers the
defender's tools (kernel filter driver, group policy,
WMI/PowerShell) cannot reach. Reading §5 against the Silicon
Is the Adversary framing surfaces the structural reason the
bypass inventory has the shape it does.

**Mathematical Collapse** establishes that cryptographic
primitives can be sound in isolation while their composition
collapses around an unmodelled fact. BitLocker's
AES-XTS-is-sound / composition-leaks-on-the-LPC-bus pattern
is a clean instance of that collapse: the algorithm is fine,
the implementation of the algorithm is fine, the standard the
algorithm follows is fine, and the unmodelled fact is the
PCB trace.

**Speculation Barrier Illusion** is, in its single-instance
form, a study of how a primitive (LFENCE) is correct on its
own but insufficient against the composition the threat
actually inhabits. BitLocker has the same shape with respect
to AES-XTS and the seal/unseal primitive: the primitives are
sufficient for their stated contracts and insufficient for
the composition's actual threat model.

### A.3 What this collection is doing

Each entry in the cluster names a different composition and
performs the same operation on it: pulls the layers apart,
reads each layer as an object with its own properties,
documents where the composition's seams expose surfaces the
single-layer view did not name. BitLocker is the entry where
the composition is a storage system; the others are the
entries where the composition is a CPU pipeline, a
boot-firmware stack, a TEE substrate, a memory subsystem, or
a kernel-defence model.

The intended contribution to this collection is the
demonstration that this register — anatomical, structural,
not defensive and not offensive — can be sustained across a
range of system substrates and that it produces a more
useful picture of each substrate's susceptibilities than
either the defensive guide or the attack-tutorial register
does.

---
