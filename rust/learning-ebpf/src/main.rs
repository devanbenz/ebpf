use aya::{include_bytes_aligned, Bpf};
use aya::programs::SockOps;
use aya_log::BpfLogger;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
   #[clap(short, long, default_value = "/sys/fs/cgroup")]    
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    
    let opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Debug, 
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(), 
        TerminalMode::Mixed, 
        ColorChoice::Auto,
        )?;

    let mut bpf = Bpf::load(include_bytes_aligned!(
            "../ebpf/target/bpfel-unknown-none/release/ebpf"
    ))?;
    BpfLogger::init(&mut bpf)?;
    let program: &mut SockOps = bpf.program_mut("bpftest").expect("could not find bpf program").try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
