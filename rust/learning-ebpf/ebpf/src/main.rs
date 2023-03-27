#![no_std]
#![no_main]
use aya_bpf::{macros::sock_ops, programs::SockOpsContext};
use aya_log_ebpf::info;

#[sock_ops(name = "bpftest")]
pub fn bpftest(ctx: SockOpsContext) -> u32 {
    match unsafe { try_bpftest(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bpftest(ctx: SockOpsContext) -> Result<u32, u32> {

    info!(&ctx, "op ({}) local_port {}", ctx.op(), ctx.local_port());
    let _ = ctx.set_cb_flags(1 << 2);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
