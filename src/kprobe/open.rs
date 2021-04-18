#![no_std]
#![no_main]

program!(0xFFFFFFFE, "GPL");

use redbpf_probes::kprobe::prelude::*;

#[map("syscall_events")]
static mut syscall_events: HashMap<u64, u64> = HashMap::with_max_entries(1024);

#[kprobe("__x64_sys_openat")]
fn syscall_enter(regs: Registers) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid >> 32;
    let ip = regs.ip();

    unsafe {
        syscall_events.set(&pid, &ip)
    };
}