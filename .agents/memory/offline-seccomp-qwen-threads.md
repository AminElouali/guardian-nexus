---
name: Offline seccomp for llama.cpp threads
description: Thread-only clone filtering for local llama.cpp inference.
---
For the standalone x86_64 offline Qwen process, return `ENOSYS` for `clone3`
so libc can fall back to classic `clone`; allow `clone` only when
`CLONE_VM|CLONE_SIGHAND|CLONE_THREAD` are present and all other flags are in
the pthread allowlist. Deny fork/vfork/exec and socket syscalls. Do not treat
this process-local filter as Docker or broker isolation.

**Why:** Classic seccomp BPF cannot safely dereference `clone3`'s user-space
arguments. Broadly allowing it would permit process creation; denying it with
`EPERM` blocked llama-cpp-python thread creation.

**How to apply:** Keep the guard local to the offline runner. Test successful
thread creation and negative fork, vfork, exec, clone-flag, and network-socket
cases; keep cgroup PID isolation and the container/broker boundary as separate
requirements.
