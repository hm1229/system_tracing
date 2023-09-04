use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};
use core::cell::RefCell;
use core::convert::TryInto;
use core::ops::FnMut;
use core::pin::Pin;
use core::slice::{from_raw_parts, from_raw_parts_mut};
use spin::Mutex;
use lazy_static::*;
use riscv_insn_decode::{insn_decode, InsnStatus, get_insn_length};
use super::probes::{get_sp, ProbeType};
use trapframe::UserContext;

#[derive(Clone)]
struct  KernelFunctionInner {
    get_exec_path: Option<Arc<Mutex<dyn FnMut() -> String + Send>>> ,
    get_new_page: Option<Arc<Mutex<dyn FnMut(usize, usize) -> usize + Send>>>,
}

#[derive(Clone)]
struct KernelFunction {
    inner: RefCell<KernelFunctionInner>,
}


pub struct Uprobes {
    pub inner: RefCell<BTreeMap<usize, UprobesInner>>,
}

struct CurrentUprobes{
    inner: RefCell<BTreeMap<usize, UprobesInner>> ,
}

struct CurrentProcessUprobesInner{
    uprobes: Uprobes,
    current_uprobes: CurrentUprobes,
}

struct CurrentProcessUprobes{
    inner: RefCell<BTreeMap<String, CurrentProcessUprobesInner>>,
}

#[derive(Clone)]
pub struct UprobesInner {
    pub addr: usize,
    pub length: usize,
    pub slot_addr: usize,
    pub addisp: usize,
    pub func_ra: Vec<usize>,
    pub func_ebreak_addr: usize,
    pub insn_ebreak_addr: usize,
    pub handler: Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>,
    pub post_handler: Option<Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>>,
    pub probe_type: ProbeType,
}


unsafe impl Sync for Uprobes {}
unsafe impl Sync for UprobesInner {}
unsafe impl Sync for CurrentUprobes {}
unsafe impl Sync for KernelFunction {}
unsafe impl Sync for KernelFunctionInner {}
unsafe impl Sync for CurrentProcessUprobes {}
unsafe impl Sync for CurrentProcessUprobesInner {}

lazy_static! {
    static ref UPROBES: Uprobes = Uprobes::new();
    static ref CURRENT_PROCESS_UPROBES: CurrentProcessUprobes = CurrentProcessUprobes::new();
    static ref KERNEL_FUNCTIONS: KernelFunction = KernelFunction::new();
}

#[naked]
extern "C" fn __ebreak() {
    unsafe {
        asm!("c.ebreak", "c.ebreak");
    }
}

impl KernelFunction {
    fn new() -> Self {
        Self {
            inner: RefCell::new(KernelFunctionInner {
                get_exec_path: None,
                get_new_page: None,
            })
        }
    }

    fn initialization(
        &self,
        get_exec_path: Arc<Mutex<dyn FnMut() -> String + Send>>,
        get_new_page: Arc<Mutex<dyn FnMut(usize, usize) -> usize + Send>>
    ) -> isize {
        self.inner.borrow_mut().get_exec_path = Some(get_exec_path);
        self.inner.borrow_mut().get_new_page = Some(get_new_page);
        0
    }
}

impl CurrentProcessUprobes{
    fn new() -> Self{
        Self{
            inner: RefCell::new(BTreeMap::new()),
        }
    }

    fn uprobes_init(&self){
        if let Some(get_exec_path) = KERNEL_FUNCTIONS.inner.borrow().clone().get_exec_path{
            let path = get_exec_path.lock()();
            if let Some(inner) = self.inner.borrow().get(&path){
                inner.uprobes.add_uprobepoint();
            }
        }

        else{
            error!("[Uprobes] get_exec_path not found!")
        }

    }

    fn register_uprobes(
        &self,
        path: String,
        addr: usize,
        handler: Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>,
        post_handler: Option<Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>>,
        probe_type: ProbeType
    ) -> isize {
        let mut uprobes_inner = self.inner.borrow_mut();
        if let Some(inner) = uprobes_inner.get_mut(&path.clone()){
            inner.uprobes.register_uprobe(addr, handler, post_handler, probe_type);
        }
        else{
            let uprobes = Uprobes::new();
            info!("uprobes: add new path");
            uprobes.register_uprobe(addr, handler, post_handler, probe_type);
            let current_uprobes = CurrentUprobes::new();
            uprobes_inner.insert(path.clone(), CurrentProcessUprobesInner{
                uprobes,
                current_uprobes,
            });
            info!("uprobes: insert success");
        }
        // info!("uprobes: path={}", get_exec_path());
        if let Some(get_exec_path) = KERNEL_FUNCTIONS.inner.borrow().clone().get_exec_path{
            if path == get_exec_path.lock()(){
                uprobes_inner.get_mut(&path.clone()).unwrap().uprobes.inner.borrow_mut().get_mut(&addr).unwrap().add_uprobepoint();
            }
        }
        0
    }

    fn uprobes_trap_handler(&self, cx: &mut UserContext){
        let mut path = String::new();
        if let Some(get_exec_path) = KERNEL_FUNCTIONS.inner.borrow().clone().get_exec_path{
            path = get_exec_path.lock()();
        }
        let path = path;
        let mut uprobes_inner = self.inner.borrow_mut();
        let mut uprobes = uprobes_inner.get(&path.clone()).unwrap().uprobes.inner.borrow_mut();
        let mut current_uprobes = uprobes_inner.get(&path.clone()).unwrap().current_uprobes.inner.borrow_mut();
        match uprobes.get_mut(&cx.sepc) {
            Some(probe) => {
                // run user defined handler
                (probe.handler.lock())(cx);
                // single step the probed instruction
                match probe.probe_type{
                    ProbeType::SyncFunc =>{
                        cx.general.sp = cx.general.sp.wrapping_add(probe.addisp);
                        cx.sepc = cx.sepc.wrapping_add(probe.length);
                        if let Some(_) = probe.post_handler{
                            if !current_uprobes.contains_key(&probe.func_ebreak_addr){
                                current_uprobes.insert(probe.func_ebreak_addr, probe.clone());
                            }
                            let current_uprobe = current_uprobes.get_mut(&probe.func_ebreak_addr).unwrap();
                            current_uprobe.func_ra.push(cx.general.ra);
                            cx.general.ra = probe.func_ebreak_addr as usize;
                        }
                    },
                    ProbeType::Insn =>{
                        cx.sepc = probe.slot_addr as usize;
                        probe.insn_ebreak_addr = cx.sepc + probe.length;
                        if !current_uprobes.contains_key(&probe.insn_ebreak_addr){
                            current_uprobes.insert(probe.insn_ebreak_addr, probe.clone());
                        }
                    }
                    ProbeType::AsyncFunc => {
                        unimplemented!("probing async function is not implemented yet")
                    }
                }
            }
            None => {
                match current_uprobes.get_mut(&cx.sepc){
                    Some(probe) =>{
                        if probe.insn_ebreak_addr == cx.sepc{
                            if let Some(post_handler) = &probe.post_handler{
                                (post_handler.lock())(cx);
                            }
                            let sepc = probe.addr + probe.length;
                            current_uprobes.remove(&cx.sepc);
                            cx.sepc = sepc;
                        }
                        else{
                            (probe.post_handler.as_ref().unwrap().lock())(cx);
                            cx.sepc = probe.func_ra.pop().unwrap();
                            if probe.func_ra.len() == 0{
                                current_uprobes.remove(&cx.sepc);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

impl CurrentUprobes{
    fn new() -> Self{
        Self{
            inner: RefCell::new(BTreeMap::new()),
        }
    }
}

impl UprobesInner {
    pub fn new(
        addr: usize,
        handler: Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>,
        post_handler: Option<Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>>,
        probe_type: ProbeType
    ) -> Option<Self> {
        Some(Self {
            addr,
            length: 0,
            slot_addr: 0,
            addisp: 0,
            func_ra: Vec::new(),
            func_ebreak_addr: 0,
            insn_ebreak_addr: 0,
            handler,
            post_handler,
            probe_type,
        })
    }

    fn add_uprobepoint(&mut self){
        // get free point in user stack
        let addr = self.addr;
        // let test = KERNEL_FUNCTIONS.inner.borrow();
        if let Some(get_new_page) = KERNEL_FUNCTIONS.inner.borrow().clone().get_new_page{
            self.func_ebreak_addr = get_new_page.lock()(addr, 2);
            self.slot_addr = get_new_page.lock()(addr, 6);
        }
        else {
            error!("[Uprobes]: get_new_page function not found!")
        }
        // self.func_ebreak_addr = KERNEL_FUNCTIONS.inner.borrow().get_new_page.unwrap()(addr, 2);
        // self.slot_addr = KERNEL_FUNCTIONS.inner.borrow().get_new_page.unwrap()(addr, 6);
        let mut slot = unsafe { from_raw_parts_mut(self.slot_addr as *mut u8, 6)};

        let inst = unsafe { from_raw_parts(addr as *const u8, 2) };
        // read the lowest byte of the probed instruction to determine whether it is compressed
        let length = get_insn_length(addr);
        self.length = length;
        // save the probed instruction to a buffer
        slot[..length].copy_from_slice(&inst[..length]);

        // decode the probed instruction to retrive imm
        let ebreak = unsafe { from_raw_parts(__ebreak as *const u8, 2) };

        match self.probe_type{
            ProbeType::Insn =>{
                match insn_decode(addr){
                    InsnStatus::Legal =>{
                        slot[length..length+2].copy_from_slice(ebreak);
                        self.insn_ebreak_addr = self.slot_addr + length;
                    },
                    _ => {warn!("uprobes: instruction is not legal");},
                }
            }
            ProbeType::SyncFunc =>{
                let mut ebreak_ptr = unsafe { from_raw_parts_mut(self.func_ebreak_addr as *mut u8, 2)};
                ebreak_ptr.copy_from_slice(ebreak);

                match get_sp(addr){
                    Some(sp) => self.addisp = sp,
                    None => {error!("sp not found!");}
                }
            }
            ProbeType::AsyncFunc =>{
                error!("not implemented yet!");
            }
        }
        self.arm()
    }

    pub fn arm(&self) {
        let ebreak = unsafe { from_raw_parts(__ebreak as *const u8, self.length) };
        let mut inst = unsafe { from_raw_parts_mut(self.addr as *mut u8, self.length) };
        inst.copy_from_slice(ebreak);
        unsafe { asm!("fence.i") };
    }

    pub fn disarm(&self) {
        let mut inst = unsafe { from_raw_parts_mut(self.addr as *mut u8, self.length) };
        let slot = unsafe { from_raw_parts(self.slot_addr as *const u8, self.length)};
        inst.copy_from_slice(slot);
        unsafe { asm!("fence.i") };
    }
}

impl Uprobes {
    fn register_uprobe(
        &self,
        addr: usize,
        handler: Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>,
        post_handler: Option<Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>>,
        probe_type: ProbeType,
    ) -> isize{
        let probe = UprobesInner::new(addr, handler, post_handler, probe_type);
        if let Some(probe) = probe {
            self.inner.borrow_mut().insert(addr, probe);
            info!("uprobes: register success");
            1
        } else {
            error!("uprobes: probe initialization failed");
            -1
        }
    }

    fn new() -> Self {
        Self {
            inner: RefCell::new(BTreeMap::new()),
        }
    }

    fn add_uprobepoint(&self){
        let mut uproebs = self.inner.borrow_mut();
        for inner in uproebs.values_mut(){
            inner.add_uprobepoint();
        }
    }
}

/// # Uprobes Register
///
/// You can use this function to register trace points in user mode. You need to provide the path of the
/// user-mode program to be traced, the address within the user-mode program that needs to be traced,
/// a handler function to be executed before the instruction/function runs,  an optional handler
/// function to be executed after the instruction/function has completed, and ['ProbeType'].
///
/// # Example
///
/// ```rust
/// system_tracing::uprobe_register(
///     "rust/test_uprobes",
///     self.addr,
///     alloc::sync::Arc::new(Mutex::new(move |cx: &mut UserContext| {
///         interpret(&prog, &HELPERS, cx as *const UserContext as usize as u64);
///     })),
///     Some(alloc::sync::Arc::new(Mutex::new(move |cx: &mut UserContext| {
///         test_post_handler(cx);
///     }))),
///     ProbeType::Insn
/// )
/// ```
pub fn uprobe_register(
    path: String,
    addr: usize,
    handler: Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>,
    post_handler: Option<Arc<Mutex<dyn FnMut(&mut UserContext) + Send>>>,
    probe_type: ProbeType
) -> isize {
    CURRENT_PROCESS_UPROBES.register_uprobes(path ,addr, handler, post_handler, probe_type)
}

/// # Uprobes Trap Handler
///
/// If you want to use Uprobes you need to place it in the operating system's handler function for the `ebreak` interrupt occurring in user mode.
///
/// The type of the parameter is `&mut trapframe::UserContext`
///
/// ```toml
/// [dependencies]
/// trapframe = { git = "https://github.com/rcore-os/trapframe-rs", rev = "bdfe5aa" }
/// ```
///
/// # Example
///
/// ```rust
/// match trap_num {
/// 	_ if is_ebreak(trap_num) => {
///         let cx: &mut UserContext = &mut thread_context.user;
///         systemp_tracing::uprobes_trap_handler(cx);
///     }
/// }
/// ```
pub fn uprobes_trap_handler(cx: &mut UserContext) {
    info!("uprobes: into uprobes trap handler");
    CURRENT_PROCESS_UPROBES.uprobes_trap_handler(cx);
}

///# Uprobes Init
///
/// If you want to use Uprobes you need to place it in the operating system every time a new user-mode program is started.
///
/// # Example
///
/// ```rust
/// pub fn sys_exec() -> isize{
///    // execution work
///    system_tracing::uprobes_init();
///     0
/// }
/// ```
pub fn uprobes_init(){
    CURRENT_PROCESS_UPROBES.uprobes_init();
    info!("uprobes: init sucess");
}

/// # Uprobes Kernel Function Initialization
/// If you want to use Uprobes, you need to first initialize a `add_new_page` function
/// and a 'get_exec_path' function through the init function, before user mode starts.
///
/// Function feature requirements：
///
/// - add new page
///
///   Given an address and a required length, the function creates a blank page closest to the
///   address and returns the address of the blank page.
///
/// - get execution path
///
///   Get the path of the currently running user-mode program.
///
/// # Example
///
/// ```rust
/// fn get_exec_path() -> String{
///     current_thread().unwrap().proc.try_lock().expect("locked!").exec_path.clone()
/// }
///
/// fn get_new_page(addr: usize, len: usize) -> usize{
///     let thread = current_thread().unwrap();
///     let mut vm = thread.vm.lock();
///     let addr = vm.find_free_area(addr, len);
///     vm.push(
///         addr,
///         addr + len,
///         MemoryAttr::default().user().execute().writable(),
///         ByFrame::new(GlobalFrameAlloc),
///         "point",
///     );
///     unsafe {asm!("fence.i");}
///     addr
/// }
///
/// pub fn init(){
///     system_tracing::uprobes_kernel_function_initialization(
///         Arc::new(Mutex::new(|| get_exec_path())),
///         Arc::new(Mutex::new(move |addr: usize, len: usize| get_new_page(addr, len)))
///     )
/// }
/// ```
pub fn uprobes_kernel_function_initialization(
    get_exec_path: Arc<Mutex<dyn FnMut() -> String + Send>>,
    get_new_page: Arc<Mutex<dyn FnMut(usize, usize) -> usize + Send>>
){
    KERNEL_FUNCTIONS.initialization(get_exec_path, get_new_page);
}