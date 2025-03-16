/* Copyright (c) [2023] [Syswonder Community]
 *   [Ruxos] is licensed under Mulan PSL v2.
 *   You can use this software according to the terms and conditions of the Mulan PSL v2.
 *   You may obtain a copy of Mulan PSL v2 at:
 *               http://license.coscl.org.cn/MulanPSL2
 *   THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *   See the Mulan PSL v2 for more details.
 */

//! [Ruxos] hardware abstraction layer, provides unified APIs for
//! platform-specific operations.
//!
//! It does the bootstrapping and initialization process for the specified
//! platform, and provides useful operations on the hardware.
//!
//! Currently supported platforms (specify by cargo features):
//!
//! - `x86-pc`: Standard PC with x86_64 ISA.
//! - `riscv64-qemu-virt`: QEMU virt machine with RISC-V ISA.
//! - `aarch64-qemu-virt`: QEMU virt machine with AArch64 ISA.
//! - `aarch64-raspi`: Raspberry Pi with AArch64 ISA.
//! - `dummy`: If none of the above platform is selected, the dummy platform
//!    will be used. In this platform, most of the operations are no-op or
//!    `unimplemented!()`. This platform is mainly used for [cargo test].
//!
//! # Cargo Features
//!
//! - `smp`: Enable SMP (symmetric multiprocessing) support.
//! - `fp_simd`: Enable floating-point and SIMD support.
//! - `paging`: Enable page table manipulation.
//! - `irq`: Enable interrupt handling support.
//!
//! [Ruxos]: https://github.com/syswonder/ruxos
//! [cargo test]: https://doc.rust-lang.org/cargo/guide/tests.html

#![no_std]
#![feature(asm_const)]
#![feature(naked_functions)]
#![feature(const_option)]
#![feature(doc_auto_cfg)]

#[allow(unused_imports)]
#[macro_use]
extern crate log;

mod platform;

pub mod arch;
pub mod cpu;
pub mod mem;
pub mod time;
pub mod trap;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "irq")]
pub mod irq;

#[cfg(feature = "paging")]
pub mod paging;

/// Console input and output.
pub mod console {
    pub use super::platform::console::*;

    /// Write a slice of bytes to the console.
    pub fn write_bytes(bytes: &[u8]) {
        for c in bytes {
            putchar(*c);
        }
    }
}

/// Miscellaneous operation, e.g. terminate the system.
pub mod misc {
    pub use super::platform::misc::*;
}

/// Multi-core operations.
#[cfg(feature = "smp")]
pub mod mp {
    pub use super::platform::mp::*;
}

use core::arch::asm;

pub use self::platform::platform_init;

#[cfg(feature = "smp")]
pub use self::platform::platform_init_secondary;

/// A cmdline buf for x86_64
///
/// The Multiboot information structure may be placed anywhere in memory by the boot loader,
/// so we should save cmdline in a buf before this memory is set free
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub static mut COMLINE_BUF: [u8; 256] = [0; 256];

#[allow(unused)]
/// read a tty device specified by its name.
pub fn tty_read(buf: &mut [u8], dev_name: &str) -> usize {
    #[cfg(not(feature = "tty"))]
    {
        let mut read_len = 0;
        while read_len < buf.len() {
            if let Some(c) = console::getchar().map(|c| if c == b'\r' { b'\n' } else { c }) {
                buf[read_len] = c;
                read_len += 1;
            } else {
                break;
            }
        }
        read_len
    }

    #[cfg(feature = "tty")]
    {
        tty::tty_read(buf, dev_name)
    }
}

#[cfg(feature = "alloc")]
extern crate alloc;

/// get all tty devices' names.
#[cfg(feature = "alloc")]
pub fn get_all_device_names() -> alloc::vec::Vec<alloc::string::String> {
    #[cfg(feature = "tty")]
    {
        tty::get_all_device_names()
    }
    #[cfg(not(feature = "tty"))]
    {
        alloc::vec![alloc::string::String::from("notty")]
    }
}

/// write a tty device specified by its name.
pub fn tty_write(buf: &[u8], _dev_name: &str) -> usize {
    #[cfg(feature = "tty")]
    {
        tty::tty_write(buf, _dev_name)
    }
    #[cfg(not(feature = "tty"))]
    {
        console::write_bytes(buf);
        return buf.len();
    }
}

// TODO: implement switch_to_el0 for x86_64 and riscv64
// assume current EL is EL1, switch to EL0
#[cfg(target_arch = "aarch64")]
use aarch64_cpu::{
    asm,
    registers::{ELR_EL1, SPSR_EL1, SP_EL0},
};
use tock_registers::interfaces::Writeable;
pub unsafe fn switch_to_el0(entry_el0: u64, sp_el0: u64) -> ! {
    #[cfg(not(target_arch = "aarch64"))]
    error!("switch_to_el0 is not implemented for x86_64 and riscv64");

    // set SPSR_EL1 to EL0t
    #[cfg(target_arch = "aarch64")]
    {
        SPSR_EL1.write(
            SPSR_EL1::M::EL0t
                + SPSR_EL1::D::Masked
                + SPSR_EL1::A::Masked
                + SPSR_EL1::I::Masked
                + SPSR_EL1::F::Masked,
        );

        SP_EL0.set(sp_el0);
        ELR_EL1.set(entry_el0);

        asm::eret();
    }
}


pub unsafe fn ret_from_clone() {
    // restore neno registers
    asm! {
        "
        mrs x0, sp_el0
        mov sp, x0
        ldp     q0, q1, [sp, 0 * 16]
        ldp     q2, q3, [sp, 2 * 16]
        ldp     q4, q5, [sp, 4 * 16]
        ldp     q6, q7, [sp, 6 * 16]
        ldp     q16, q17, [sp, 8 * 16]
        ldp     q18, q19, [sp, 10 * 16]
        ldp     q20, q21, [sp, 12 * 16]
        ldp     q22, q23, [sp, 14 * 16]
        ldp     q24, q25, [sp, 16 * 16]
        ldp     q26, q27, [sp, 18 * 16]
        ldp     q28, q29, [sp, 20 * 16]
        ldp     q30, q31, [sp, 22 * 16]
        ldp     x9,x10, [sp, 48 *  8]
        msr     fpcr, x9
        msr     fpsr, x10
        add     sp, sp, 50 * 8",

        "ldp     x10, x11, [sp, 32 * 8]
        ldp     x30, x9, [sp, 30 * 8]
        msr     elr_el1, x10
        msr     spsr_el1, x11
        msr     sp_el0, x9

        ldp     x28, x29, [sp, 28 * 8]
        ldp     x26, x27, [sp, 26 * 8]
        ldp     x24, x25, [sp, 24 * 8]
        ldp     x22, x23, [sp, 22 * 8]
        ldp     x20, x21, [sp, 20 * 8]
        ldp     x18, x19, [sp, 18 * 8]
        ldp     x16, x17, [sp, 16 * 8]
        ldp     x14, x15, [sp, 14 * 8]
        ldp     x12, x13, [sp, 12 * 8]
        ldp     x10, x11, [sp, 10 * 8]
        ldp     x8, x9, [sp, 8 * 8]
        ldp     x6, x7, [sp, 6 * 8]
        ldp     x4, x5, [sp, 4 * 8]
        ldp     x2, x3, [sp, 2 * 8]
        ldp     x0, x1, [sp]
        add     sp, sp, 34 * 8",
        "mov x0, #0",
        "eret",
        options(noreturn)
    }
}
