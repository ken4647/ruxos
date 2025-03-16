/* Copyright (c) [2023] [Syswonder Community]
 *   [Ruxos] is licensed under Mulan PSL v2.
 *   You can use this software according to the terms and conditions of the Mulan PSL v2.
 *   You may obtain a copy of Mulan PSL v2 at:
 *               http://license.coscl.org.cn/MulanPSL2
 *   THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *   See the Mulan PSL v2 for more details.
 */

use alloc::string::String;
use core::{mem::ManuallyDrop, str};
use memory_addr::PAGE_SIZE_4K;
mod auxv;
mod stack;
use alloc::{vec, vec::Vec};
use auxv::*;
use elf::ElfBytes;
use memory_addr::VirtAddr;
use ruxfs::fops::{File, OpenOptions};

#[derive(Debug)]
pub struct ElfProg {
    base: usize,
    interp_base: usize,
    entry: usize,
    interp_path: String,
    phent: usize,
    phnum: usize,
    phdr: usize,
}

impl ElfProg {
    /// read elf from `path`, and copy LOAD segments to a alloacated memory
    ///
    /// and load interp, if needed.
    /// assume `base` is big enough to load elf.
    pub fn load(filepath: &str, load_vbase: Option<VirtAddr>) -> Self {
        debug!("elf load: new elf prog: {filepath}");

        // open elf-file
        let mut options = OpenOptions::new();
        options.read(true);
        options.write(true);
        options.create(false);
        let elf_file = File::open(filepath, &options).expect("elf file open failed");

        // get elf-file size
        let file_size = elf_file
            .get_attr()
            .expect("sys_execve: failed to get file size")
            .size() as usize;
        debug!("sys_execve: file size 0x{file_size:x}");

        // read elf-file
        let mut content = vec![0u8; file_size];
        let _ = elf_file.read_at(0, &mut content);
        debug!("sys_execve: read file size 0x{file_size:x}");

        // parse elf-file
        let parsed_elf: ElfBytes<'_, elf::endian::AnyEndian> =
            ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&content).expect("parse ELF failed");

        let segs = parsed_elf.segments().expect("no segments found");

        let base = if let Some(vaddr) = load_vbase {
            vaddr.align_up_4k().as_usize()
        } else {
            0x123456789000 // TODO: allocate memory
        };
        debug!("load_elf: loading ELF in 0x{:x}", base);
        // copy LOAD segments
        let mut interp_base = 0;
        for seg in segs {
            if seg.p_type == elf::abi::PT_LOAD {
                let data = parsed_elf.segment_data(&seg).unwrap();
                let dst = (seg.p_vaddr as usize + base) as *mut u8;
                debug!(
                    "load_elf: loading segment elf's 0x{:x} to vaddr=0x{:x}, size 0x{:x}",
                    seg.p_vaddr,
                    dst as usize,
                    data.len()
                );
                unsafe { dst.copy_from_nonoverlapping(data.as_ptr(), data.len()) };
                interp_base = (seg.p_vaddr as usize + base) + data.len() as usize;
            }
        }

        // phdr
        let phdr = base + parsed_elf.ehdr.e_phoff as usize;
        // get entry
        let entry = parsed_elf.ehdr.e_entry as usize + base;

        // parse interpreter
        let mut interp_path = String::new();
        for seg in parsed_elf.segments().unwrap() {
            if seg.p_type == elf::abi::PT_INTERP {
                let data = parsed_elf
                    .segment_data(&seg)
                    .expect("interp data not found")
                    .to_vec();
                interp_path = String::from_utf8(data).expect("interp path not utf8");
                break;
            }
        }

        // create retval
        Self {
            base,
            interp_base,
            entry,
            interp_path,
            phent: parsed_elf.ehdr.e_phentsize as usize,
            phnum: parsed_elf.ehdr.e_phnum as usize,
            phdr,
        }
    }

    // return the entry point of the program and sp
    pub fn build(
        &self,
        argv: &[&str],
        envp: &[&str],
        sp: usize,
        stack_size: usize,
    ) -> (usize, usize) {
        // get entry
        let mut entry = self.entry;
        // if interp is needed
        let mut at_base = 0;

        // TODO: Support for dynamic linker
        if !self.interp_path.is_empty() {
            let interp_path = &self.interp_path;
            let interp_prog = ElfProg::load(interp_path, Some(VirtAddr::from(self.interp_base)));
            entry = interp_prog.entry;
            at_base = interp_prog.base;
            debug!("sys_execve: INTERP base is {:x}", at_base);
        };

        // create stack
        // memory broken, use stack alloc to store args and envs
        let mut stack = stack::Stack::from_address(sp, stack_size);

        // handle envs and args
        // put args and envs in stack
        let mut env_vec: Vec<usize> = vec![];
        let mut arg_vec: Vec<usize> = vec![];

        let platform = stack.push(platform(), 8);
        let elf_path = stack.push("/bin/busybox".as_bytes(), 8);

        let length = argv.len();
        for i in 0..length {
            stack.push(argv[i].as_bytes(), 8);
            arg_vec.push(stack.sp());
        }
        let length = envp.len();
        for i in 0..length {
            stack.push(envp[i].as_bytes(), 8);
            env_vec.push(stack.sp());
        }

        // non 8B info
        stack.push(&[0u8; 32], 16);
        // let rand = unsafe { [sys_random(), sys_random()] };
        // TODO: get random
        let rand = [1234i64, 4121i64];
        let p_rand = stack.push(&rand, 16);

        // auxv
        // TODO: vdso
        let auxv = vec![
            AT_PHDR,
            self.phdr,
            AT_PHNUM,
            self.phnum,
            AT_PHENT,
            self.phent,
            AT_BASE,
            at_base,
            AT_PAGESZ,
            PAGE_SIZE_4K,
            AT_HWCAP,
            0,
            AT_PLATFORM,
            platform,
            AT_CLKTCK,
            100,
            AT_FLAGS,
            0,
            AT_ENTRY,
            self.entry,
            AT_UID,
            1000, // TODO: get uid
            AT_EUID,
            1000, // TODO: get euid
            AT_EGID,
            1000, // TODO: get egid
            AT_GID,
            1000, // TODO: get gid
            AT_SECURE,
            0,
            AT_EXECFN,
            elf_path,
            AT_RANDOM,
            p_rand,
            AT_SYSINFO_EHDR,
            0,
            AT_IGNORE,
            0,
            AT_NULL,
            0,
        ];

        // push
        stack.push(&auxv, 8);
        stack.push(&[0u8; 1], 8);
        stack.push(&env_vec, 8);
        stack.push(&[0u8; 1], 8);
        stack.push(&arg_vec, 8);
        let sp = stack.push(&[arg_vec.len()], 8); // argc

        // try run
        debug!(
            "sys_execve: sp is 0x{sp:x}, run at 0x{entry:x}, then jump to 0x{:x} ",
            self.entry
        );

        // stack should not be dropped here, because it is used by the program
        let _ = ManuallyDrop::new(stack);

        (entry, sp)
    }
}

fn platform<'a>() -> &'a [u8] {
    #[cfg(target_arch = "aarch64")]
    const PLATFORM_STRING: &[u8] = b"aarch64\0";
    #[cfg(target_arch = "x86_64")]
    const PLATFORM_STRING: &[u8] = b"x86_64\0";
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    const PLATFORM_STRING: &[u8] = b"unknown\0";

    PLATFORM_STRING
}
