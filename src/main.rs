mod syscall_table;

use tokio::runtime;
use tokio::signal::ctrl_c;
use redbpf::Module;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {

        let prog = include_bytes!("../target/bpf/programs/open/open.elf");
        let mut module = Module::parse(prog).expect("error parsing BPF code");

        for program in module.programs.iter_mut() {
            println!("Loading program: {}", program.name());
            program.load(module.version, module.license.clone()).unwrap();
        }

        for program in module.kprobes_mut() {
            println!("Attaching Kprobe: {}", program.name());
            program.attach_kprobe(&program.name(), 0).unwrap();
        }

        let _ = ctrl_c().await;
        Ok(())
    })
}
