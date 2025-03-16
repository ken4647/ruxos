mod auxv;
mod load_elf;
mod stack;

use crate::ctypes;
use alloc::vec;
use alloc::vec::Vec;
use auxv::*;
use core::ffi::c_char;
use ruxconfig::TASK_STACK_SIZE;
use ruxhal::{mem::PAGE_SIZE_4K, switch_to_el0};

use crate::{
    imp::stat::{sys_getgid, sys_getuid},
    sys_getegid, sys_geteuid, sys_mmap, sys_random,
    utils::char_ptr_to_str,
};

/// int execve(const char *pathname, char *const argv[], char *const envp[] );
pub fn sys_execve(pathname: *const c_char, argv: usize, envp: usize) -> ! {
    debug!(
        "execve: pathname {:?}, argv {:?}, envp {:?}",
        pathname, argv, envp
    );

    let path = char_ptr_to_str(pathname).unwrap();
    debug!("sys_execve: path is {}", path);
    let prog = load_elf::ElfProg::new(path);

    // get entry
    let mut entry = prog.entry;

    // if interp is needed
    let mut at_base = 0;
    if !prog.interp_path.is_empty() {
        let interp_path = char_ptr_to_str(prog.interp_path.as_ptr() as _).unwrap();
        let interp_prog = load_elf::ElfProg::new(interp_path);
        entry = interp_prog.entry;
        at_base = interp_prog.base;
        debug!("sys_execve: INTERP base is {:x}", at_base);
    };

    // create stack
    // memory broken, use stack alloc to store args and envs
    let prot = ctypes::PROT_WRITE | ctypes::PROT_READ | ctypes::PROT_EXEC;
    let flags = ctypes::MAP_ANONYMOUS | ctypes::MAP_PRIVATE;
    let stack_addr = sys_mmap(
        core::ptr::null_mut(),
        TASK_STACK_SIZE,
        prot as i32,
        flags as i32,
        -1,
        0,
    );
    let mut stack = stack::Stack::from_address(
        stack_addr as usize + TASK_STACK_SIZE - 8,
        TASK_STACK_SIZE - 8,
    );

    // handle envs and args
    // put args and envs in stack
    let mut env_vec: Vec<usize> = vec![];
    let mut arg_vec: Vec<usize> = vec![];

    let platform = stack.push(platform(), 8);
    let elf_path = stack.push(path.as_bytes(), 8);

    let mut envp = envp as *const usize;
    unsafe {
        while *envp != 0 {
            env_vec.push(*envp);
            envp = envp.add(1);
        }
    }

    let mut argv = argv as *const usize;
    unsafe {
        while *argv != 0 {
            arg_vec.push(*argv);
            argv = argv.add(1);
        }
    }

    // non 8B info
    stack.push(&[0u8; 32], 16);
    let rand = unsafe { [sys_random(), sys_random()] };
    let p_rand = stack.push(&rand, 16);

    // auxv
    // TODO: vdso
    let auxv = vec![
        AT_PHDR,
        prog.phdr,
        AT_PHNUM,
        prog.phnum,
        AT_PHENT,
        prog.phent,
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
        prog.entry,
        AT_UID,
        sys_getuid() as usize, // TODO: get uid
        AT_EUID,
        sys_geteuid() as usize, // TODO: get euid
        AT_EGID,
        sys_getegid() as usize, // TODO: get egid
        AT_GID,
        sys_getgid() as usize, // TODO: get gid
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
    warn!(
        "sys_execve: sp is 0x{sp:x}, run at 0x{entry:x}, then jump to 0x{:x} ",
        prog.entry
    );

    // set_sp_and_jmp(sp, entry);
    unsafe { switch_to_el0(entry as u64, sp as u64) }
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
