---
title: "CVE-2022-29582 io_uring UAF: Race Between Flush Path and Timer Path on a Linked Timeout Object"
author: Utku
date: 2026
tags: [CVE-2022-29582, io_uring, UAF, use-after-free, Linux, LPE, container-escape, SLUB, heap-feng-shui, hrtimer, concurrency, kernel-5.17]
license: CC BY 4.0
---

> **Author's Note:** Most kernel UAFs are single-path: one function frees the object, one other function still holds a pointer to it, and the race is about timing those two paths against each other. CVE-2022-29582 is more subtle. The object — a link-timeout (`LT`) request — has *two independent free paths*, and the kernel's own specification requires both of them to exist: one triggered when the linked operation completes (flush path), one triggered when the timer fires first (timer path). The bug is not that the code is wrong in isolation; it is that the lifecycle invariant "list-unlink happens before refcount-drop happens before free" is supposed to be maintained by the code that coordinates these two paths, and it isn't. The race window is narrow. The consequence is a SLUB-reuse UAF that reaches the kernel from an unprivileged user without any namespace setup, making it practical for container escape. The fix is one line: unlink from the list *before* dropping refs.

---

## Abstract

`io_uring` is Linux's asynchronous I/O subsystem: a pair of shared ring buffers (Submission Queue, Completion Queue) mapped via `mmap` between user space and kernel, designed to minimize system call overhead. Operations can be chained with `IOSQE_IO_LINK`: a target operation `T` followed by a link-timeout `LT` that cancels `T` if it does not complete within a deadline. CVE-2022-29582 arises when both `T` and `LT` complete concurrently: the flush path (triggered by `T` finishing) and the timer path (triggered by `LT`'s `hrtimer` expiring) both attempt to free `LT`, racing through `io_put_req_deferred()`. The second free produces a dangling pointer inside `T`'s `link_list`. SLUB immediately reuses the freed slot, and the flush path's subsequent access to "LT" now touches attacker-controlled memory. The exploit chain: heap feng-shui using `pipe_buffer`/`struct file`/`msg_msg` to occupy the freed slot → refcount corruption → function pointer hijack via `f_op.release` → `commit_creds(prepare_kernel_cred(0))` → root. No user namespace is required. Patched in kernel 5.17.3 (April 2022); fix: `list_del_init()` before `io_put_req_deferred()`.

---

## §1 io_uring Architecture

```
User space                         Kernel
──────────                         ──────
SQ ring  ──── SQE[0], SQE[1] ────► worker threads
(user writes)                          │
                                       ▼ I/O performed
CQ ring  ◄──── CQE[0], CQE[1] ──────── completions
(user reads)
```

Both ring buffers are mapped via `mmap` after `io_uring_setup()`. This means the user writes SQEs directly into shared memory without a syscall, and reads CQEs back the same way. The only system call needed per batch is `io_uring_enter()` to notify the kernel that new SQEs are available.

The SQE structure:

```c
struct io_uring_sqe {
    __u8    opcode;         // IORING_OP_READ, IORING_OP_TEE, IORING_OP_LINK_TIMEOUT, ...
    __u8    flags;          // IOSQE_IO_LINK, IOSQE_IO_HARDLINK, ...
    __u16   ioprio;
    __s32   fd;
    __u64   off;
    __u64   addr;
    __u32   len;
    __u32   timeout_flags;
    __u64   user_data;      // returned verbatim in the CQE — used for correlation
    __u16   buf_index;
    __u16   personality;
    __s32   splice_fd_in;
    __u64   __pad2[3];
};
```

`user_data` is the caller-assigned 64-bit tag that the kernel echoes back in the CQE. It is the primary correlation handle in complex multi-operation sequences.

---

## §2 Linked Timeouts: Chaining T and LT

`IOSQE_IO_LINK` creates an ordered dependency: the second SQE does not start until the first completes. `IORING_OP_LINK_TIMEOUT` as the second SQE acts as a deadline enforcer: if the first operation (`T`) does not finish within the specified duration, the timeout (`LT`) cancels it.

User submission:
```c
// SQE[0]: target operation
sqe[0].opcode = IORING_OP_TEE;
sqe[0].flags  = IOSQE_IO_LINK;   // chain to next

// SQE[1]: link timeout — cancels sqe[0] if not done within deadline
sqe[1].opcode = IORING_OP_LINK_TIMEOUT;
sqe[1].addr   = (uintptr_t)&ts;  // struct __kernel_timespec
```

Inside the kernel, both operations are represented as `struct io_kiocb`:

```c
struct io_kiocb {
    // ...
    struct list_head  link_list;    // T's link_list points to LT
    struct io_kiocb  *link;         // explicit back-pointer
    // ...
    struct io_timeout_data {
        struct hrtimer timer;       // LT's high-resolution timer
    } *async_data;
};
```

When `T` is submitted with `IOSQE_IO_LINK`, the kernel connects `T->link_list` to `LT`. This pointer is the source of the UAF: it persists until explicitly cleared, and clearing it is what the two racing paths both attempt to do.

---

## §3 Two Completion Paths

Every linked `(T, LT)` pair has exactly two legitimate completion orderings:

**Path A — T finishes first (flush path):**
1. `T` completes → `io_commit_cqring(ctx)` called
2. `io_flush_timeouts(ctx)` runs: "are there any timeouts I can now cancel?"
3. `list_del_init(&lT->timeout.list)` — removes LT from the timeout list
4. `io_kill_timeout(lT, 0)` → `hrtimer_try_to_cancel(&lT->timer)` — cancels LT's timer
5. `io_put_req_deferred(lT, 1)` — decrements LT's refcount; if 0, frees LT

**Path B — LT's timer fires first (timer path):**
1. `hrtimer` expires → `io_link_timeout_fn(timer)` callback invoked
2. `io_fail_links(lT)` — cancels remaining linked operations (T, if still pending)
3. `io_put_req_deferred(lT, 1)` — decrements LT's refcount; if 0, frees LT

Under normal, sequential operation these paths are mutually exclusive: only one fires. The race occurs when T and LT complete within nanoseconds of each other.

---

## §4 The Race: Concurrent Free of LT

**Timeline of the bug:**

```
t0:      LT's hrtimer expires → timer path starts → io_fail_links(LT) running

t0 + ε:  T also completes → flush path starts → io_flush_timeouts sees LT in list

t1:      timer path calls io_put_req_deferred(LT, 1)
             → refcount reaches 0
             → io_free_req_deferred(LT) scheduled

t1 + ε:  flush path: list_del_init(&LT->timeout.list) ← LT already freed
             SLUB has already given LT's slot to a new allocation
             flush path is now writing to/reading from the new object

t2:      flush path dereferences T->link_list → UAF
```

The kernel code in `io_kill_timeout()`:

```c
static void io_kill_timeout(struct io_kiocb *req, int status) {
    struct io_timeout_data *io = req->async_data;
    int ret = hrtimer_try_to_cancel(&io->timer);

    if (ret != -1) {
        list_del_init(&req->timeout.list);   // BUG: should happen BEFORE put
        io_cqring_fill_event(req, status);
        io_put_req_deferred(req, 1);         // if this drops to 0, LT is freed
    }
}
```

The invariant that should be maintained:

```
1. list_del_init()        ← break the link, so no other path can find this object
2. refcount_dec()         ← reduce ownership count
3. free()                 ← only when refcount == 0
```

The actual code violates step 1: `list_del_init()` is inside `io_kill_timeout()`, which is called *after* the timer cancel. But the timer path has already called `io_put_req_deferred()` concurrently. Both paths can see `ret != -1` from `hrtimer_try_to_cancel()` depending on timing, and both proceed through the free path.

The patch (kernel 5.17.3): move `list_del_init()` to before any `io_put_req_deferred()` call, ensuring the object is removed from all lists before either path drops the last reference.

---

## §5 SLUB Reuse and UAF

Linux's slab allocator (SLUB) is designed for speed. When an object is freed, its slot is marked available and the next allocation of the same cache returns that slot immediately — often within the same `kmalloc()` call.

```
LT freed (refcount → 0)
    → SLUB marks slot as available in io_kiocb cache
    
exploit: allocate pipe_buffer / struct file / msg_msg of same size
    → SLUB returns LT's former slot
    → attacker controls bytes at LT's old address

flush path dereferences T->link_list (→ LT's old address)
    → reads/writes attacker's controlled object
    → UAF
```

The critical property: the size of `struct io_kiocb` must match one of the standard SLUB caches. If it does, the attacker can use any allocation of the same cache to fill the freed slot. Common spray targets:

| Object | Size range | Technique |
|---|---|---|
| `pipe_buffer` | 64 bytes | `pipe(2)` loop |
| `struct file` | 256 bytes | `open(2)` loop |
| `msg_msg` | variable, up to 4096 | `msgsnd(2)` |
| `struct sk_buff` | 320 bytes | `socket` + `send` |

The heap feng-shui sequence: exhaust free slots in the target cache size by opening many pipes/files → trigger the LT free → immediately spray the preferred object → verify via `user_data` feedback from CQEs that the correct slot was occupied.

---

## §6 Exploitation Chain

### Stage 1: Refcount Corruption

Once the fake object occupies LT's slot, the flush path calls `io_put_req_deferred()` on it, which is:

```c
if (refcount_sub_and_test(refs, &req->refs))
    io_free_req_deferred(req);
```

If the attacker's object has a controllable field at the `refcount` offset, this becomes an arbitrary decrement. An `io_kiocb` `refs` field sits at a known offset; filling LT's slot with an object whose same-offset field is important (e.g., a `struct file`'s `f_count`) allows the attacker to decrement the file's reference count, eventually dropping it to zero and triggering `fput()`.

### Stage 2: Function Pointer Hijack

`fput()` → `file->f_op->release()`. If the `struct file` whose refcount was decremented is controlled by the attacker (pointing into attacker-controlled memory for `f_op`), then `release` is a function pointer the attacker owns. Redirecting it to a kernel gadget or directly to the privilege escalation stub gives RIP control.

### Stage 3: Privilege Escalation

The canonical Linux LPE payload:

```c
// Execute in kernel context (from hijacked callback)
commit_creds(prepare_kernel_cred(0));
```

`prepare_kernel_cred(0)` creates a new credential structure with UID/GID/capabilities all set to root. `commit_creds()` applies it to the current task. After this executes in kernel context, the calling process has `uid=0` — root without any namespace setup.

**No user namespace required.** Most Linux kernel exploits from this era require `unshare(CLONE_NEWUSER)` to access certain dangerous primitives. CVE-2022-29582 does not: `io_uring` is available to any user who has access to the `io_uring_setup()` syscall, which on unpatched systems is unrestricted. This means any low-privilege account — including those inside containers that inherit the host's io_uring access — can use this for container escape.

---

## §7 Exploit Flow Summary

```
1. io_uring_setup() — create submission/completion ring pair

2. Heap feng-shui:
   - Exhaust target SLUB cache with pipe_buffer / msg_msg sprays
   - Leave one slot free at a controlled address

3. Submit T + LT chain:
   sqe[0]: IORING_OP_TEE (IOSQE_IO_LINK)
   sqe[1]: IORING_OP_LINK_TIMEOUT, ts = 1ns

4. Race trigger:
   - T completes (or is designed to complete) at the same moment LT expires
   - Both flush path and timer path enter io_put_req_deferred(LT, 1)
   - LT freed → SLUB marks slot available

5. Immediately: controlled allocation fills LT's slot
   - struct file with controlled f_op pointer

6. Flush path uses T->link_list (dangling):
   - Touches attacker's struct file
   - io_put_req_deferred decrements f_count → fput()

7. fput() → f_op->release():
   - Attacker's function pointer → kernel payload

8. commit_creds(prepare_kernel_cred(0)) → uid=0
```

---

## §8 Code Path Trace

`io_commit_cqring()` — the entry point of the flush path:

```c
static void io_commit_cqring(struct io_ring_ctx *ctx) {
    io_flush_timeouts(ctx);        // ← where LT free begins
    __io_commit_cqring(ctx);
    if (unlikely(!list_empty(&ctx->defer_list)))
        __io_queue_deferred(ctx);
}
```

`io_kill_timeout()` — where the double-free window exists:

```c
static void io_kill_timeout(struct io_kiocb *req, int status) {
    struct io_timeout_data *io = req->async_data;
    int ret = hrtimer_try_to_cancel(&io->timer);

    if (ret != -1) {
        list_del_init(&req->timeout.list);   // ← unlinks LT from timeout list
        io_cqring_fill_event(req, status);
        io_put_req_deferred(req, 1);         // ← may free LT
    }
}
```

`io_link_timeout_fn()` — the timer callback that is the other racing path:

```c
static enum hrtimer_restart io_link_timeout_fn(struct hrtimer *timer) {
    struct io_timeout_data *data =
        container_of(timer, struct io_timeout_data, timer);
    struct io_kiocb *req = data->req;

    io_fail_links(req);             // cancel remaining linked ops (T)
    io_put_req_deferred(req, 1);    // ← may also free LT concurrently
    return HRTIMER_NORESTART;
}
```

Both paths call `io_put_req_deferred(req, 1)` on the same `req`. If LT's refcount is 1 at the time both paths execute this, both see a transition to 0 and both schedule a free.

---

## §9 The Fix

```diff
- list_del_init(&req->timeout.list);   // was inside io_kill_timeout
+ list_del_init(&req->timeout.list);   // moved to before io_put_req_deferred
  io_cqring_fill_event(req, status);
  io_put_req_deferred(req, 1);
```

The correct lifecycle order:
1. Remove from all lists first (`list_del_init`) — after this, no new path can acquire a reference to LT
2. Drop the reference count
3. If zero, free

This is a general principle for kernel linked-list lifecycle: *unlink before drop*. The list membership is itself a form of reference; treating them as independent operations is the class of bug.

---

## §10 Threat Context

| Property | Value |
|---|---|
| CVE | CVE-2022-29582 |
| Affected versions | Linux kernel < 5.17.3 |
| Patched | April 2022, kernel 5.17.3 |
| Privilege required | Unprivileged local user |
| User namespace required | No |
| Container escape | Yes (Google COS PoC demonstrated) |
| CVSS | High (local privilege escalation to root) |
| Exploit complexity | Medium (heap feng-shui timing-sensitive) |

**Container escape context:** Google COS (Container-Optimized OS) is the base OS for GKE node pools. A process inside a container that retains `io_uring` access (not blocked by seccomp policy) can use this to escape to the host. This was the primary demonstrated impact beyond standard LPE.

---

## §11 Cross-OS Comparison: Linux vs. Windows UAF Primitives

The same conceptual structure appears in both operating systems:

| Concept | Linux (this CVE) | Windows |
|---|---|---|
| Kernel object with lifecycle | `struct io_kiocb` (link timeout) | IRP, `EPROCESS`, socket |
| Reference counting | `req->refs` (atomic refcount) | Object manager ref count |
| List-based ownership | `io_kiocb.timeout.list` | `LIST_ENTRY` in handle tables |
| Double-free trigger | Two concurrent completion paths | Cancel routine + DPC timer |
| Post-free spray target | `pipe_buffer`, `struct file` | Pool tag spray, `_POOL_HEADER` |
| Privilege escalation primitive | `commit_creds(prepare_kernel_cred(0))` | Token stealing shellcode |

The "unlink before drop before free" invariant is universal. Its violation is CVE-2022-29582 on Linux, and the same pattern appears in dozens of Windows kernel UAFs in IRP cancellation and socket cleanup paths.

---

## Related Writeups

- **[Vsock UAF](../Vsock-UAF-Writeup/)** — Linux kernel UAF from a different subsystem (AF_VSOCK) and a different lifecycle bug (refcount underflow on double connect failure vs. concurrent free). Direct comparison case for understanding lifecycle-based UAF primitives.
- **[CLFS Zero-Day](../CLFS-ZeroDay-Writeup/)** — Windows kernel write primitive without UAF; shows the alternative attack surface (logical corruption vs. memory corruption).
- **[PatchGuard Hypervisor Bypass](../PatchGuard-Hypervisor-Bypass-Writeup/)** — Linux vs. Windows security model comparison: Linux has no hardware-enforced Ring -1 integrity checking equivalent to VBS/KDP, which changes the post-exploitation landscape.
