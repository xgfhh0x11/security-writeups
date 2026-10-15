# Security Research — Writeups

28 long-form technical writeups spanning CVE analysis, architectural threat-model readings, and tool-chain anatomy. Each writeup includes explicit scope limits, defensive framing, and a threat model section distinguishing what is demonstrated from what is an integration point.

All content is licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

> Companion repository: my portfolio of working implementations (drivers, fuzzers, analyzers, pipelines) is indexed at <https://github.com/xgfhh0x11>.

---

## Hypervisor / VMX / Ring -1

| Writeup | Subject |
|---|---|
| [PatchGuard-Hypervisor-Bypass-Writeup](./PatchGuard-Hypervisor-Bypass-Writeup/) | EPT shadowing, DPC timer trap injection, VTL trap chain — defeating PatchGuard from VMX root |
| [VMExit-API-Unhook-Writeup](./VMExit-API-Unhook-Writeup/) | Just-in-time EDR inline-hook removal via EPT write-protect VMExit; blue-team telemetry correlation |
| [EPT-Hypervisor-Hook-Writeup](./EPT-Hypervisor-Hook-Writeup/) | EPT-based syscall intercept from first principles: VMXON, VMCS construction, EPT violation handler |

## CVE Analysis / Exploitation

| Writeup | Subject |
|---|---|
| [Vsock-UAF-Writeup](./Vsock-UAF-Writeup/) | CVE-2025-21756 — AF_VSOCK refcount underflow, LSM-free oracle, sk_error_report overwrite, VM escape |
| [CLFS-ZeroDay-Writeup](./CLFS-ZeroDay-Writeup/) | CVE-2022-37969 — CLFS SignaturesOffset aliasing, OOB pool write, SYSTEM via EPROCESS token overwrite |
| [io-uring-UAF-Writeup](./io-uring-UAF-Writeup/) | CVE-2022-29582 — flush path / timer path race on linked timeout object, SLUB reuse, container escape |
| [CrackArmor-AppArmor-LPE-Writeup](./CrackArmor-AppArmor-LPE-Writeup/) | CVE-2026-23268 — AppArmor confused deputy + four LPE branches; nine CVEs, 12.6M affected systems |
| [Qualcomm-Kgsl-SignExt-Writeup](./Qualcomm-Kgsl-SignExt-Writeup/) | CVE-2026-21385 — CISA KEV integer overflow in kgsl driver, sign-extension collapse, OOB write |
| [GDI-Bitmap-Abuse-Writeup](./GDI-Bitmap-Abuse-Writeup/) | SURFOBJ.pvScan0 overwrite → arbitrary kernel read/write → token steal via Manager/Worker pattern |
| [RS2-Bitmap-Necromancy-Writeup](./RS2-Bitmap-Necromancy-Writeup/) | RS2 bitmap heap bypass: session pool slot reuse, desktop heap range constraint satisfied via UAF |
| [Double-Fetch-Race-Writeup](./Double-Fetch-Race-Writeup/) | TOCTOU double-fetch in kernel handlers; win-rate scaling on multi-core; CVE-2013-1254/1278 |
| [BFS2019-Master-Writeup](./BFS2019-Master-Writeup/) | BFS 2019 CTF full chain: type confusion → gadget dispatcher hijack → TEB leak → COP ROP → WinExec |

## Control-Flow Enforcement

| Writeup | Subject |
|---|---|
| [CET-COOP-Bypass-Writeup](./CET-COOP-Bypass-Writeup/) | COOP chain against Intel CET/IBT/Shadow Stack; LdrpDispatchUserCallTarget delivers the payload |

## Microarchitecture / Side Channels

| Writeup | Subject |
|---|---|
| [Silicon-Adversary-Writeup](./Silicon-Adversary-Writeup/) | Spectre → Hertzbleed arc: silicon side-effects the software threat model never modelled |
| [Mathematical-Collapse-Writeup](./Mathematical-Collapse-Writeup/) | Classical mathematics as a DSL that doesn't cover the silicon substrate; six failure points |
| [Microarch-Isolation-Writeup](./Microarch-Isolation-Writeup/) | Five trust-boundary layers broken by microarchitectural reality; VMScape + GhostRace |
| [Speculation-Barrier-Illusion-Writeup](./Speculation-Barrier-Illusion-Writeup/) | CBMC proof that `lfence` is correct under the ISA model — and why that is a category error |
| [GPU-Side-Channel-AI-Writeup](./GPU-Side-Channel-AI-Writeup/) | GPU overclocking as a side-channel amplifier for AI inference workloads |

## Confidential Computing / TEE

| Writeup | Subject |
|---|---|
| [Confidential-VM-Writeup](./Confidential-VM-Writeup/) | Where SEV-SNP, TDX, and CCA fail to project their isolation contract onto the shared substrate |
| [Interrupt-Injection-CC-Writeup](./Interrupt-Injection-CC-Writeup/) | Heckler + WeSee: hypervisor-injected interrupts bypass Confidential VM control-flow confidentiality |

## Firmware / Hardware Attack Surfaces

| Writeup | Subject |
|---|---|
| [SPI-Firmware-Anatomy-Writeup](./SPI-Firmware-Anatomy-Writeup/) | SPI bus, flash die state machine, boot ROM signature chain, four physical fault-injection categories |
| [Rowhammer-Decade-Writeup](./Rowhammer-Decade-Writeup/) | Kim 2014 → DDR5 Phoenix 2024: each vendor mitigation assumption and the finding that broke it |
| [Secure-Boot-Anatomy-Writeup](./Secure-Boot-Anatomy-Writeup/) | PK/KEK/DB/DBX chain; BootHole, BlackLotus, shim/grub2 bypass history |
| [DMA-IOMMU-Writeup](./DMA-IOMMU-Writeup/) | Physical RAM as a flat address space on IOMMU-disabled systems; MmMapIoSpace LSASS read demo |
| [BitLocker-Anatomy-Writeup](./BitLocker-Anatomy-Writeup/) | fvevol.sys + boot measurement chain + TPM seal/unseal + AES-XTS; attack surface in the layer gaps |

## Windows Internals / Detection / EDR

| Writeup | Subject |
|---|---|
| [ETW-Mirage-Writeup](./ETW-Mirage-Writeup/) | ETW as a security boundary: structural bypasses, four detection vectors, each vector's failure mode |
| [Decoy-Surface-Writeup](./Decoy-Surface-Writeup/) | Hypervisor-mediated kernel deception anatomy; SSDT/handle/APC/network primitives in offense + defense |

## AI Systems

| Writeup | Subject |
|---|---|
| [ACMM-Writeup](./ACMM-Writeup/) | LLM auxiliary memory as a virtual memory subsystem; memory-corruption primitives mapped to context layer |

---

`_HBO-PITCHES.md` — one-paragraph elevator pitches for every item, structured for application essays and CV descriptions.
