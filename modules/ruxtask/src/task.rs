/* Copyright (c) [2023] [Syswonder Community]
 *   [Ruxos] is licensed under Mulan PSL v2.
 *   You can use this software according to the terms and conditions of the Mulan PSL v2.
 *   You may obtain a copy of Mulan PSL v2 at:
 *               http://license.coscl.org.cn/MulanPSL2
 *   THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *   See the Mulan PSL v2 for more details.
 */

use crate::fs::FileSystem;
use alloc::collections::BTreeMap;
use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::{Arc, Weak},
};
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicU8, Ordering};
use core::{alloc::Layout, cell::UnsafeCell, fmt, ptr::NonNull};
use page_table::PageSize;
use page_table_entry::MappingFlags;
use ruxconfig::TASK_STACK_SIZE;
#[cfg(feature = "paging")]
use ruxhal::paging::PageTable;
use ruxhal::{ret_from_clone, switch_to_el0};
use spinlock::SpinNoIrq;

#[cfg(feature = "preempt")]
use core::sync::atomic::AtomicUsize;

#[cfg(feature = "tls")]
use ruxhal::tls::TlsArea;

use memory_addr::{align_up_4k, VirtAddr, PAGE_SIZE_4K};
use ruxhal::arch::{flush_tlb, TaskContext};

#[cfg(not(feature = "musl"))]
use crate::tsd::{DestrFunction, KEYS, TSD};
#[cfg(feature = "paging")]
use crate::vma::MmapStruct;
use crate::{current, execv, RUN_QUEUE};
use crate::{AxRunQueue, AxTask, AxTaskRef, WaitQueue};

/// A unique identifier for a thread.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TaskId(u64);

/// The possible states of a task.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TaskState {
    /// Task is running on cpu
    Running = 1,
    /// Task is ready for schedule
    Ready = 2,
    /// Task is blocked
    Blocked = 3,
    /// Task exits, waiting for gc
    Exited = 4,
}

/// The inner task structure.
pub struct TaskInner {
    parent_process: Option<Weak<AxTask>>,
    process_task: Weak<AxTask>,
    id: TaskId,
    name: String,
    is_idle: bool,
    is_init: bool,
    entry: Option<*mut dyn FnOnce()>,
    state: AtomicU8,

    in_wait_queue: AtomicBool,
    #[cfg(feature = "irq")]
    in_timer_list: AtomicBool,

    #[cfg(feature = "preempt")]
    need_resched: AtomicBool,
    #[cfg(feature = "preempt")]
    preempt_disable_count: AtomicUsize,

    exit_code: AtomicI32,
    wait_for_exit: WaitQueue,

    // kernel stack
    kstack: SpinNoIrq<Arc<Option<TaskStack>>>,
    // user stack
    ustack: SpinNoIrq<Arc<Option<TaskStack>>>,
    ctx: UnsafeCell<TaskContext>,

    #[cfg(feature = "tls")]
    tls: TlsArea,

    #[cfg(not(feature = "musl"))]
    tsd: TSD,

    // set tid
    #[cfg(feature = "musl")]
    set_tid: AtomicU64,
    // clear tid
    #[cfg(feature = "musl")]
    tl: AtomicU64,
    #[cfg(feature = "paging")]
    // The page table of the task.
    pub pagetable: Arc<SpinNoIrq<PageTable>>,
    // file system
    pub fs: Arc<SpinNoIrq<Option<FileSystem>>>,
    // memory management
    pub mm: Arc<MmapStruct>,
}

impl TaskId {
    fn new() -> Self {
        static ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(ID_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Convert the task ID to a `u64`.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<u8> for TaskState {
    #[inline]
    fn from(state: u8) -> Self {
        match state {
            1 => Self::Running,
            2 => Self::Ready,
            3 => Self::Blocked,
            4 => Self::Exited,
            _ => unreachable!(),
        }
    }
}

unsafe impl Send for TaskInner {}
unsafe impl Sync for TaskInner {}

impl TaskInner {
    /// Gets the ID of the task.
    pub const fn id(&self) -> TaskId {
        self.id
    }

    /// Gets the clear tid of the task.
    #[cfg(feature = "musl")]
    pub const fn tl(&self) -> &AtomicU64 {
        &self.tl
    }

    /// Gets the name of the task.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Get a combined string of the task ID and name.
    pub fn id_name(&self) -> alloc::string::String {
        alloc::format!("Task({}, {:?})", self.id.as_u64(), self.name)
    }

    /// Get pointer for parent process task
    pub fn parent_process(&self) -> Option<AxTaskRef> {
        if let Some(parent_process) = self.parent_process.as_ref() {
            return parent_process.upgrade();
        }
        None
    }

    /// Get pointer for process task
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::Acquire)
    }

    /// Get process task
    pub fn process_task(&self) -> Arc<AxTask> {
        if let Some(process_task) = self.process_task.upgrade() {
            process_task.clone()
        } else {
            current().as_task_ref().clone()
        }
    }

    /// Get pid of the process of the task.
    pub fn process_id(&self) -> TaskId {
        if let Some(process_task) = self.process_task.upgrade() {
            process_task.id
        } else {
            self.id
        }
    }

    /// Wait for the task to exit, and return the exit code.
    ///
    /// It will return immediately if the task has already exited (but not dropped).
    pub fn join(&self) -> Option<i32> {
        self.wait_for_exit
            .wait_until(|| self.state() == TaskState::Exited);
        Some(self.exit_code.load(Ordering::Acquire))
    }

    /// set 0 to thread_list_lock
    #[cfg(feature = "musl")]
    pub fn free_thread_list_lock(&self) {
        let addr = self.tl.load(Ordering::Relaxed);
        if addr == 0 {
            return;
        }
        unsafe { &*(addr as *const AtomicI32) }.store(0, Ordering::Release)
    }
}

pub static PROCESS_MAP: SpinNoIrq<BTreeMap<u64, Arc<AxTask>>> = SpinNoIrq::new(BTreeMap::new());

// TODO: move these segments to a config file
const USER_STACK_TOP: usize = 0x0000_7fff_ffff_f000;
const USER_STACK_SIZE: usize = ruxconfig::TASK_STACK_SIZE;
const USER_STACK_BEGIN: usize = USER_STACK_TOP - USER_STACK_SIZE;
const USER_STACK_START: usize = 0x0000_6000_0000_0000;

const USER_HEAP_END: usize = 0x0000_4000_0000_0000;
const USER_HEAP_BEGIN: usize = 0x0000_3000_0000_0000;

const EXE_LOAD_BASE: usize = 0x0000_0000_0040_0000;
const EXE_LOAD_SIZE: usize = 0x0000_1000_0000_0000;

const TLS_AREA_BEGIN: usize = 0x0000_2000_0000_0000;
const TLS_AREA_END: usize = 0x0000_2800_0000_0000;
const TLS_PER_SIZE: usize = 0x1000_0000;

const PROT_WRITE: u32 = 0x2;
const PROT_READ: u32 = 0x4;
const PROT_EXEC: u32 = 0x10;

const MAP_ANONYMOUS: u32 = 0x20;
const MAP_PRIVATE: u32 = 0x0;

unsafe fn init_task_entry() {
    unsafe {
        RUN_QUEUE.force_unlock();
    }
    let elf_prog = execv::ElfProg::load("bin/busybox", Some(VirtAddr::from(EXE_LOAD_BASE)));
    let (entry, sp) = elf_prog.build(&["bin/busybox", "sh"], &[], USER_STACK_TOP, USER_STACK_SIZE);
    switch_to_el0(entry as u64, sp as u64);
}

pub fn forked_task_entry(){
    debug!("forked_task_entry: process_id={:#}, name={:?}", current().id_name(), current().id.0);
    unsafe {
        RUN_QUEUE.force_unlock();
        ret_from_clone();
    }
}

// private methods
impl TaskInner {
    // clone a thread
    fn new_common(id: TaskId, name: String) -> Self {
        debug!(
            "new_common: process_id={:#}, name={:?}",
            current().id_name(),
            id.0
        );
        Self {
            parent_process: Some(Arc::downgrade(current().as_task_ref())),
            process_task: Arc::downgrade(&current().process_task()),
            id,
            name,
            is_idle: false,
            is_init: false,
            entry: None,
            state: AtomicU8::new(TaskState::Ready as u8),
            in_wait_queue: AtomicBool::new(false),
            #[cfg(feature = "irq")]
            in_timer_list: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            need_resched: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            preempt_disable_count: AtomicUsize::new(0),
            exit_code: AtomicI32::new(0),
            wait_for_exit: WaitQueue::new(),
            kstack: SpinNoIrq::new(Arc::new(None)),
            ustack: SpinNoIrq::new(Arc::new(None)),
            ctx: UnsafeCell::new(TaskContext::new()),
            #[cfg(feature = "tls")]
            tls: TlsArea::new_with_addr(TLS_AREA_BEGIN + TLS_PER_SIZE * id.0 as usize),
            #[cfg(not(feature = "musl"))]
            tsd: spinlock::SpinNoIrq::new([core::ptr::null_mut(); ruxconfig::PTHREAD_KEY_MAX]),
            #[cfg(feature = "musl")]
            set_tid: AtomicU64::new(0),
            #[cfg(feature = "musl")]
            tl: AtomicU64::new(0),
            #[cfg(feature = "paging")]
            pagetable: current().pagetable.clone(),
            fs: current().fs.clone(),
            mm: current().mm.clone(),
        }
    }

    #[cfg(feature = "musl")]
    fn new_common_tls(
        id: TaskId,
        name: String,
        #[cfg_attr(not(feature = "tls"), allow(unused_variables))] tls: usize,
        set_tid: AtomicU64,
        tl: AtomicU64,
    ) -> Self {
        use crate::current;
        Self {
            parent_process: Some(Arc::downgrade(current().as_task_ref())),
            process_task: Arc::downgrade(&current().process_task()),
            id,
            name,
            is_idle: false,
            is_init: false,
            entry: None,
            state: AtomicU8::new(TaskState::Ready as u8),
            in_wait_queue: AtomicBool::new(false),
            #[cfg(feature = "irq")]
            in_timer_list: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            need_resched: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            preempt_disable_count: AtomicUsize::new(0),
            exit_code: AtomicI32::new(0),
            wait_for_exit: WaitQueue::new(),
            kstack: SpinNoIrq::new(Arc::new(None)),
            ustack: SpinNoIrq::new(Arc::new(None)),
            ctx: UnsafeCell::new(TaskContext::new()),
            #[cfg(feature = "tls")]
            tls: TlsArea::new_with_addr(tls),
            set_tid,
            // clear child tid
            tl,
            #[cfg(feature = "paging")]
            pagetable: current().pagetable.clone(),
            fs: current().fs.clone(),
            mm: current().mm.clone(),
        }
    }

    pub fn stack_top(&self) -> VirtAddr {
        self.kstack.lock().as_ref().as_ref().unwrap().top()
    }

    pub fn set_stack_top(&self, begin: usize, size: usize) {
        debug!("set_stack_top: begin={:#x}, size={:#x}", begin, size);
        *self.ustack.lock() = Arc::new(Some(TaskStack {
            ptr: NonNull::new(begin as *mut u8).unwrap(),
            layout: Layout::from_size_align(size, PAGE_SIZE_4K).unwrap(),
        }));
    }

    /// for set_tid_addr
    #[cfg(feature = "musl")]
    pub fn set_child_tid(&self, tid: usize) {
        self.set_tid.store(tid as _, Ordering::Release);
    }

    /// Create a new task with the given entry function, stack size and tls area address
    #[cfg(feature = "musl")]
    pub(crate) fn new_musl<F>(
        entry: F,
        name: String,
        stack_size: usize,
        tls: usize,
        set_tid: AtomicU64,
        // clear child tid
        tl: AtomicU64,
    ) -> AxTaskRef
    where
        F: FnOnce() + Send + 'static,
    {
        let mut t = Self::new_common_tls(TaskId::new(), name, tls, set_tid, tl);
        let kstack = TaskStack::alloc(align_up_4k(stack_size));
        #[cfg(feature = "tls")]
        let tls = VirtAddr::from(t.tls.tls_ptr() as usize);
        #[cfg(not(feature = "tls"))]
        let tls = VirtAddr::from(0);

        t.entry = Some(Box::into_raw(Box::new(entry)));
        t.ctx
            .get_mut()
            .init(task_entry as usize, kstack.top(), VirtAddr::from(0), tls);
        t.kstack = SpinNoIrq::new(Arc::new(Some(kstack)));
        if t.name == "idle" {
            t.is_idle = true;
        }
        Arc::new(AxTask::new(t))
    }

    /// Create a new task with the given entry function and stack size.
    pub(crate) fn new<F>(entry: F, name: String, stack_size: usize) -> AxTaskRef
    where
        F: FnOnce() + Send + 'static,
    {
        let mut t = Self::new_common(TaskId::new(), name);
        debug!("new task: {}", t.id_name());
        let kstack = TaskStack::alloc(align_up_4k(stack_size));
        let ustack_begin = current()
            .as_task_ref()
            .mm
            .find_free_region(
                None,
                align_up_4k(stack_size),
                (USER_STACK_START, USER_STACK_TOP),
            )
            .expect("failed to find free user stack");
        
        current().as_task_ref().mm.add_vma(ustack_begin, ustack_begin + align_up_4k(stack_size), PROT_WRITE | PROT_READ | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE);

        #[cfg(feature = "tls")]
        let tls = VirtAddr::from(t.tls.tls_ptr() as usize);
        #[cfg(not(feature = "tls"))]
        let tls = VirtAddr::from(0);

        t.entry = Some(Box::into_raw(Box::new(entry)));
        t.ctx
            .get_mut()
            .init(task_entry as usize, kstack.top(), VirtAddr::from(ustack_begin), tls);
        t.kstack = SpinNoIrq::new(Arc::new(Some(kstack)));
        if t.name == "idle" {
            t.is_idle = true;
        }
        Arc::new(AxTask::new(t))
    }

    // TODO: support args and env
    pub fn create_user_process(init_proc_path: &str, _args: &[&str], _env: &[&str]) -> AxTaskRef {
        // TODO: init file system
        let page_table = PageTable::try_new().expect("failed to create page table");
        let mm = MmapStruct::new();
        let fs = current().fs.clone();

        let prot = PROT_WRITE | PROT_READ | PROT_EXEC;
        let flags = MAP_ANONYMOUS | MAP_PRIVATE;
        // map memory for user stack
        mm.add_vma(USER_STACK_BEGIN, USER_STACK_TOP, prot, flags);
        // map user heap in to mm's vma_map
        mm.add_vma(USER_HEAP_BEGIN, USER_HEAP_END, prot, flags);
        // map user mmap in to mm's vma_map
        mm.add_vma(EXE_LOAD_BASE, EXE_LOAD_BASE + EXE_LOAD_SIZE, prot, flags);
        // map tls area in to mm's vma_map
        #[cfg(feature = "tls")]
        mm.add_vma(TLS_AREA_BEGIN, TLS_AREA_END, prot, flags);

        // create a new process task
        let new_id = TaskId::new();
        let new_id_usize = new_id.as_u64() as usize;
        let mut t = Self {
            parent_process: None,
            process_task: Weak::new(),
            id: new_id,
            name: String::from("init"),
            is_idle: false,
            is_init: true,
            entry: None,
            state: AtomicU8::new(TaskState::Ready as u8),
            in_wait_queue: AtomicBool::new(false),
            #[cfg(feature = "irq")]
            in_timer_list: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            need_resched: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            preempt_disable_count: AtomicUsize::new(0),
            exit_code: AtomicI32::new(0),
            wait_for_exit: WaitQueue::new(),
            kstack: SpinNoIrq::new(Arc::new(Some(TaskStack::alloc(align_up_4k(
                TASK_STACK_SIZE,
            ))))),
            ustack: SpinNoIrq::new(Arc::new(None)),
            ctx: UnsafeCell::new(TaskContext::new()),
            #[cfg(feature = "tls")]
            tls: TlsArea::new_with_addr(TLS_AREA_BEGIN + TLS_PER_SIZE * new_id_usize as usize),
            #[cfg(not(feature = "musl"))]
            tsd: spinlock::SpinNoIrq::new([core::ptr::null_mut(); ruxconfig::PTHREAD_KEY_MAX]),
            #[cfg(feature = "musl")]
            set_tid: AtomicU64::new(0),
            #[cfg(feature = "musl")]
            tl: AtomicU64::new(0),
            #[cfg(feature = "paging")]
            pagetable: Arc::new(SpinNoIrq::new(page_table)),
            fs,
            mm: mm.into(),
        };
        error!("tls area addr: {:#x?}", t.tls.tls_ptr());

        debug!(
            "new task; name={:?}, pagetable's rootaddr={:#x}",
            t.name,
            t.pagetable.lock().root_paddr()
        );
        // set up task context
        // TODO: tls unimplemented
        t.set_stack_top(USER_STACK_BEGIN, USER_STACK_SIZE);

        let kstack_top = t.kstack.lock().as_ref().as_ref().unwrap().top();
        warn!("new_task: kstack_top={:#x}", kstack_top);
        // re-compute entry ptr and sp for the new process, as the new process's page table is
        // different from now.
        t.ctx.get_mut().init(
            init_task_entry as usize,
            kstack_top,
            VirtAddr::from(USER_STACK_BEGIN),
            VirtAddr::from(t.tls.tls_ptr() as usize),
        );

        // add it into process map
        let task_ref = Arc::new(AxTask::new(t));
        PROCESS_MAP
            .lock()
            .insert(task_ref.id().as_u64(), task_ref.clone());

        task_ref
    }

    /// duplicate a task with process level inner state
    pub fn fork() -> AxTaskRef {
        let current_task = crate::current();
        let name = current_task.as_task_ref().name().to_string();
        let current_stack_bindings = current_task.as_task_ref().kstack.lock();
        let current_stack = current_stack_bindings.as_ref().as_ref().clone().unwrap();
        let stack_size = current_stack.layout.size();

        // clone page table and mm for the new process
        let mut parent_page_table = current_task.pagetable.lock();
        let parent_mm = current_task.mm.as_ref();
        let mut parent_fs = current_task.fs.lock();

        // new setuped data structure for the new process
        let new_fs = parent_fs.as_mut().unwrap().clone();
        let new_mm = parent_mm.clone();
        let mut new_page_table = PageTable::try_new().expect("failed to create page table");

        //TODO: avoid clone page table if the page won't be dropped when updating mapping.
        for (vaddr, page_info) in parent_mm.mem_map.lock().iter() {
            let paddr = page_info.paddr;

            // Copy-on-write for the new page table and the parent page table.
            new_page_table
                .map(
                    (*vaddr).into(),
                    paddr,
                    PageSize::Size4K,
                    MappingFlags::READ | MappingFlags::EXECUTE | MappingFlags::USER,
                )
                .expect("failed to map when forking");
            parent_page_table
                .update(
                    (*vaddr).into(),
                    None,
                    Some(MappingFlags::READ | MappingFlags::EXECUTE | MappingFlags::USER),
                )
                .expect("failed to update mapping when forking");
            flush_tlb(Some((*vaddr).into()));
        }

        let new_pid = TaskId::new();
        // build the new task
        let mut t = Self {
            parent_process: Some(Arc::downgrade(current_task.as_task_ref())),
            process_task: Weak::new(),
            id: new_pid,
            name,
            is_idle: false,
            is_init: false,
            entry: None,
            state: AtomicU8::new(TaskState::Ready as u8),
            in_wait_queue: AtomicBool::new(current_task.in_wait_queue.load(Ordering::Relaxed)),
            #[cfg(feature = "irq")]
            in_timer_list: AtomicBool::new(current_task.in_timer_list.load(Ordering::Relaxed)),
            #[cfg(feature = "preempt")]
            need_resched: AtomicBool::new(current_task.need_resched.load(Ordering::Relaxed)),
            #[cfg(feature = "preempt")]
            preempt_disable_count: AtomicUsize::new(
                current_task.preempt_disable_count.load(Ordering::Relaxed),
            ),
            exit_code: AtomicI32::new(0),
            wait_for_exit: WaitQueue::new(),
            kstack: SpinNoIrq::new(Arc::new(Some(TaskStack::alloc(align_up_4k(stack_size))))),
            ustack: SpinNoIrq::new(Arc::new(None)),
            ctx: UnsafeCell::new(TaskContext::new()),
            #[cfg(feature = "tls")]
            tls: TlsArea::new_with_addr(current_task.as_task_ref().tls.tls_ptr() as usize),
            #[cfg(not(feature = "musl"))]
            tsd: spinlock::SpinNoIrq::new([core::ptr::null_mut(); ruxconfig::PTHREAD_KEY_MAX]),
            #[cfg(feature = "musl")]
            set_tid: AtomicU64::new(0),
            #[cfg(feature = "musl")]
            tl: AtomicU64::new(0),
            #[cfg(feature = "paging")]
            pagetable: Arc::new(SpinNoIrq::new(new_page_table)),
            fs: Arc::new(SpinNoIrq::new(Some(new_fs))),
            mm: Arc::new(new_mm),
        };

        // TODO: tls unimplemented
        #[cfg(feature = "tls")]
        let tls = VirtAddr::from(t.tls.tls_ptr() as usize);
        #[cfg(not(feature = "tls"))]
        let tls = VirtAddr::from(0);

        fn read_sp_el0() -> u64 {
            let mut sp_el0: u64;
            unsafe {
                core::arch::asm!(
                    "mrs {0}, sp_el0",
                    out(reg) sp_el0
                );
            }
            sp_el0
        }

        // clone the context from the parent's stack top
        let parent_sp = read_sp_el0() as *const u8;
        let mut children_sp = t
            .kstack
            .lock()
            .as_ref()
            .as_ref()
            .unwrap()
            .top()
            .as_mut_ptr();

        // recover regs
        unsafe {
            children_sp = children_sp.wrapping_sub(34 * 8 + (50 * 8));
            children_sp.copy_from_nonoverlapping(parent_sp, 34 * 8 + (50 * 8));
        }

        t.ctx.get_mut().init(
            forked_task_entry as usize,
            VirtAddr::from(children_sp as usize),
            VirtAddr::from(children_sp as usize), // restore in ret_from_clone
            tls,
        );

        let task_ref = Arc::new(AxTask::new(t));
        PROCESS_MAP
            .lock()
            .insert(new_pid.as_u64(), task_ref.clone());

        task_ref
    }

    /// Creates an "init task" using the current CPU states, to use as the
    /// current task.
    ///
    /// As it is the current task, no other task can switch to it until it
    /// switches out.
    ///
    /// And there is no need to set the `entry`, `kstack` or `tls` fields, as
    /// they will be filled automatically when the task is switches out.
    pub(crate) fn new_init(name: String) -> AxTaskRef {
        let mut t = Self {
            parent_process: None,
            process_task: Weak::new(),
            id: TaskId::new(),
            name,
            is_idle: false,
            is_init: false,
            entry: None,
            state: AtomicU8::new(TaskState::Ready as u8),
            in_wait_queue: AtomicBool::new(false),
            #[cfg(feature = "irq")]
            in_timer_list: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            need_resched: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            preempt_disable_count: AtomicUsize::new(0),
            exit_code: AtomicI32::new(0),
            wait_for_exit: WaitQueue::new(),
            kstack: SpinNoIrq::new(Arc::new(None)),
            ustack: SpinNoIrq::new(Arc::new(None)),
            ctx: UnsafeCell::new(TaskContext::new()),
            #[cfg(feature = "tls")]
            tls: TlsArea::alloc(),
            #[cfg(not(feature = "musl"))]
            tsd: spinlock::SpinNoIrq::new([core::ptr::null_mut(); ruxconfig::PTHREAD_KEY_MAX]),
            #[cfg(feature = "musl")]
            set_tid: AtomicU64::new(0),
            #[cfg(feature = "musl")]
            tl: AtomicU64::new(0),
            #[cfg(feature = "paging")]
            pagetable: Arc::new(SpinNoIrq::new(
                PageTable::try_new().expect("failed to create page table"),
            )),
            fs: Arc::new(SpinNoIrq::new(None)),
            mm: Arc::new(MmapStruct::new()),
        };
        debug!("new init task: {}", t.id_name());
        t.set_stack_top(boot_stack as usize, ruxconfig::TASK_STACK_SIZE);
        t.ctx.get_mut().init(
            task_entry as usize,
            VirtAddr::from(boot_stack as usize),
            VirtAddr::from(0),
            VirtAddr::from(t.tls.tls_ptr() as usize),
        );
        let task_ref = Arc::new(AxTask::new(t));
        PROCESS_MAP
            .lock()
            .insert(task_ref.id().as_u64(), task_ref.clone());
        task_ref
    }

    pub fn new_idle(name: String) -> AxTaskRef {
        const IDLE_STACK_SIZE: usize = 4096;
        let bindings = PROCESS_MAP.lock();
        let (&_parent_id, &ref task_ref) = bindings.first_key_value().unwrap();
        let idle_kstack = TaskStack::alloc(align_up_4k(IDLE_STACK_SIZE));

        let mut t = Self {
            parent_process: Some(Arc::downgrade(task_ref)),
            process_task: task_ref.process_task.clone(),
            id: TaskId::new(),
            name,
            is_idle: true,
            is_init: false,
            entry: Some(Box::into_raw(Box::new(|| crate::run_idle()))),
            state: AtomicU8::new(TaskState::Ready as u8),
            in_wait_queue: AtomicBool::new(false),
            #[cfg(feature = "irq")]
            in_timer_list: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            need_resched: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            preempt_disable_count: AtomicUsize::new(0),
            exit_code: AtomicI32::new(0),
            wait_for_exit: WaitQueue::new(),
            kstack: SpinNoIrq::new(Arc::new(None)),
            ustack: SpinNoIrq::new(Arc::new(None)),
            ctx: UnsafeCell::new(TaskContext::new()),
            #[cfg(feature = "tls")]
            tls: TlsArea::alloc(),
            #[cfg(not(feature = "musl"))]
            tsd: spinlock::SpinNoIrq::new([core::ptr::null_mut(); ruxconfig::PTHREAD_KEY_MAX]),
            #[cfg(feature = "musl")]
            set_tid: AtomicU64::new(0),
            #[cfg(feature = "musl")]
            tl: AtomicU64::new(0),
            #[cfg(feature = "paging")]
            pagetable: task_ref.pagetable.clone(),
            fs: task_ref.fs.clone(),
            mm: task_ref.mm.clone(),
        };

        #[cfg(feature = "tls")]
        let tls = VirtAddr::from(t.tls.tls_ptr() as usize);
        #[cfg(not(feature = "tls"))]
        let tls = VirtAddr::from(0);

        debug!("new idle task: {}", t.id_name());
        t.ctx.get_mut().init(
            task_entry as usize,
            idle_kstack.top(),
            VirtAddr::from(0),
            tls,
        );

        let task_ref = Arc::new(AxTask::new(t));

        task_ref
    }

    /// Get task state
    #[inline]
    pub fn state(&self) -> TaskState {
        self.state.load(Ordering::Acquire).into()
    }

    /// Set task state
    #[inline]
    pub fn set_state(&self, state: TaskState) {
        self.state.store(state as u8, Ordering::Release)
    }

    #[inline]
    pub(crate) fn is_running(&self) -> bool {
        matches!(self.state(), TaskState::Running)
    }

    #[inline]
    pub(crate) fn is_ready(&self) -> bool {
        matches!(self.state(), TaskState::Ready)
    }

    /// Check blocking
    #[inline]
    pub fn is_blocked(&self) -> bool {
        matches!(self.state(), TaskState::Blocked)
    }

    #[inline]
    pub(crate) const fn is_init(&self) -> bool {
        self.is_init
    }

    #[inline]
    pub(crate) const fn is_idle(&self) -> bool {
        self.is_idle
    }

    #[inline]
    pub(crate) fn in_wait_queue(&self) -> bool {
        self.in_wait_queue.load(Ordering::Acquire)
    }

    #[inline]
    pub(crate) fn set_in_wait_queue(&self, in_wait_queue: bool) {
        self.in_wait_queue.store(in_wait_queue, Ordering::Release);
    }

    #[inline]
    #[cfg(feature = "irq")]
    pub(crate) fn in_timer_list(&self) -> bool {
        self.in_timer_list.load(Ordering::Acquire)
    }

    #[inline]
    #[cfg(feature = "irq")]
    pub(crate) fn set_in_timer_list(&self, in_timer_list: bool) {
        self.in_timer_list.store(in_timer_list, Ordering::Release);
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn set_preempt_pending(&self, pending: bool) {
        self.need_resched.store(pending, Ordering::Release)
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn can_preempt(&self, current_disable_count: usize) -> bool {
        self.preempt_disable_count.load(Ordering::Acquire) == current_disable_count
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn disable_preempt(&self) {
        self.preempt_disable_count.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "preempt")]
    pub(crate) fn enable_preempt(&self, resched: bool) {
        if self.preempt_disable_count.fetch_sub(1, Ordering::Relaxed) == 1 && resched {
            // If current task is pending to be preempted, do rescheduling.
            Self::current_check_preempt_pending();
        }
    }

    #[cfg(feature = "preempt")]
    fn current_check_preempt_pending() {
        let curr = crate::current();
        if curr.need_resched.load(Ordering::Acquire) && curr.can_preempt(0) {
            let mut rq = crate::RUN_QUEUE.lock();
            if curr.need_resched.load(Ordering::Acquire) {
                rq.preempt_resched();
            }
        }
    }

    pub(crate) fn notify_exit(&self, exit_code: i32, rq: &mut AxRunQueue) {
        self.exit_code.store(exit_code, Ordering::Release);
        self.wait_for_exit.notify_all_locked(false, rq);
    }

    #[inline]
    pub(crate) const unsafe fn ctx_mut_ptr(&self) -> *mut TaskContext {
        self.ctx.get()
    }
}

#[cfg(not(feature = "musl"))]
impl TaskInner {
    /// Allocate a key
    pub fn alloc_key(&self, destr_function: Option<DestrFunction>) -> Option<usize> {
        unsafe { KEYS.lock() }.alloc(destr_function)
    }
    /// Get the destructor function of a key
    pub fn free_key(&self, key: usize) -> Option<()> {
        unsafe { KEYS.lock() }.free(key)
    }
    /// Get the destructor function of a key
    pub fn set_tsd(&self, key: usize, value: *mut core::ffi::c_void) -> Option<()> {
        if key < self.tsd.lock().len() {
            self.tsd.lock()[key] = value;
            Some(())
        } else {
            None
        }
    }
    /// Get the destructor function of a key
    pub fn get_tsd(&self, key: usize) -> Option<*mut core::ffi::c_void> {
        if key < self.tsd.lock().len() {
            Some(self.tsd.lock()[key])
        } else {
            None
        }
    }
    /// Get the destructor function of a key
    pub fn destroy_keys(&self) {
        unsafe { KEYS.lock() }.destr_used_keys(&self.tsd)
    }
}

impl fmt::Debug for TaskInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TaskInner")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("state", &self.state())
            .finish()
    }
}

#[derive(Debug)]
pub struct TaskStack {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl TaskStack {
    pub fn alloc(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 8).unwrap();
        Self {
            ptr: NonNull::new(unsafe { alloc::alloc::alloc(layout) }).unwrap(),
            layout,
        }
    }

    pub const fn top(&self) -> VirtAddr {
        unsafe { core::mem::transmute(self.ptr.as_ptr().add(self.layout.size())) }
    }

    pub const fn end(&self) -> VirtAddr {
        unsafe { core::mem::transmute(self.ptr.as_ptr()) }
    }

    pub fn size(&self) -> usize {
        self.layout.size()
    }
}

impl Drop for TaskStack {
    fn drop(&mut self) {
        warn!(
            "taskStack drop: ptr={:#x}, size={:#x}",
            self.ptr.as_ptr() as usize,
            self.layout.size()
        );
        unsafe { alloc::alloc::dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

use core::mem::ManuallyDrop;

/// A wrapper of [`AxTaskRef`] as the current task.
pub struct CurrentTask(ManuallyDrop<AxTaskRef>);

impl CurrentTask {
    pub(crate) fn try_get() -> Option<Self> {
        let ptr: *const super::AxTask = ruxhal::cpu::current_task_ptr();
        if !ptr.is_null() {
            Some(Self(unsafe { ManuallyDrop::new(AxTaskRef::from_raw(ptr)) }))
        } else {
            None
        }
    }

    pub(crate) fn get() -> Self {
        Self::try_get().expect("current task is uninitialized")
    }

    /// Converts [`CurrentTask`] to [`AxTaskRef`].
    pub fn as_task_ref(&self) -> &AxTaskRef {
        &self.0
    }

    pub fn clone(&self) -> AxTaskRef {
        self.0.deref().clone()
    }

    pub(crate) fn ptr_eq(&self, other: &AxTaskRef) -> bool {
        Arc::ptr_eq(&self.0, other)
    }

    pub(crate) unsafe fn init_current(init_task: AxTaskRef) {
        #[cfg(feature = "tls")]
        ruxhal::arch::write_thread_pointer(init_task.tls.tls_ptr() as usize);
        let ptr = Arc::into_raw(init_task);
        ruxhal::cpu::set_current_task_ptr(ptr);
    }

    pub(crate) unsafe fn set_current(prev: Self, next: AxTaskRef) {
        debug!(
            "-----------set_current,next task_id={:#}-------------",
            next.id_name()
        );
        let Self(arc) = prev;
        ManuallyDrop::into_inner(arc); // `call Arc::drop()` to decrease prev task reference count.
        let ptr = Arc::into_raw(next);
        ruxhal::cpu::set_current_task_ptr(ptr);
    }
}

impl Deref for CurrentTask {
    type Target = TaskInner;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

extern "C" fn task_entry() -> ! {
    // release the lock that was implicitly held across the reschedule
    unsafe { crate::RUN_QUEUE.force_unlock() };
    #[cfg(feature = "irq")]
    ruxhal::arch::enable_irqs();
    let task = crate::current();
    if let Some(entry) = task.entry {
        unsafe {
            let in_entry = Box::from_raw(entry);
            in_entry()
        };
    }
    crate::exit(0);
}

extern "C" {
    fn boot_stack();
}
