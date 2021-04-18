#![no_std]
#![no_main]

program!(0xFFFFFFFE, "GPL");

use redbpf_probes::kprobe::prelude::*;

#[map("syscall_events")]
static mut syscall_events: HashMap<u64, u64> = HashMap::with_max_entries(1024);

fn syscall_enter(regs: Registers) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid >> 32;
    let parm1 = regs.parm1();

    unsafe {
        syscall_events.set(&pid, &parm1)
    };
}

#[kprobe("__x64_sys_open")]
fn syscall_openat(regs: Registers) {
    syscall_enter(regs);
}

#[kprobe("__x64_sys_read")]
fn syscall_read(regs: Registers) {
    syscall_enter(regs);
}

#[kprobe("__x64_sys_fork")]
fn syscall_fork(regs: Registers) {
    syscall_enter(regs);
}
