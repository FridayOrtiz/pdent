mod syscall_table;

use nix::sys::ptrace as ptrace;
use std::env;
use nix::unistd::Pid;
use nix::sys::wait::waitpid;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        std::process::exit(1);
    }
    let pid = Pid::from_raw((&args[1]).parse::<i32>().unwrap());
    ptrace::attach(pid).unwrap();
    waitpid(pid, None).unwrap();
    loop {
        ptrace::syscall(pid, None).unwrap();
        waitpid(pid, None).unwrap();
        let regs = ptrace::getregs(pid).unwrap();
        println!("Syscall: {:?}", syscall_table::lookup(regs.orig_rax));
    }
    //ptrace::detach(pid, None).unwrap();
}
