use frida_gum as gum;
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, Transformer};
use frida_gum::interceptor::{Interceptor, InvocationContext, InvocationListener};
use frida_gum::{Module, NativePointer};
use lazy_static::lazy_static;
use ctor::ctor;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

lazy_static! {
    static ref GUM: gum::Gum = unsafe { gum::Gum::obtain() };
}

struct SampleEventSink {
    blocks: Arc<Mutex<Vec<u64>>>,
}

impl EventSink for SampleEventSink {
    fn query_mask(&mut self) -> EventMask {
        EventMask::None
    }

    fn start(&mut self) {
        println!("start");
    }

    fn process(&mut self, _event: &Event) {
        match _event {
            Event::Block { start, end } => {
                println!("process: {:x?}", start);
            }
            _=> {}
        }
    }

    fn flush(&mut self) {
        println!("flush");
    }

    fn stop(&mut self) {
        println!("stop");
    }
}

struct HookListener {
    followed: bool,
}

impl InvocationListener for HookListener {
    fn on_enter(&mut self, _context: InvocationContext) {
        println!("entered");
    }

    fn on_leave(&mut self, _context: InvocationContext) {
        println!("leave");
    }
}


struct Corpus {
    coverage_bitmap: Vec<AtomicU64>,
}

struct Fuzzer {
    target_addr: usize,
}

impl Fuzzer {
    fn new(target: usize) -> Self {
        Fuzzer {
            target_addr: target,
        }
    }

    /// 0 stalking diri sendiri
    fn setup_stalker(&mut self, tid: i64) {
        let mut stalker = Stalker::new(&GUM);

        let corpus = Arc::new(Corpus {
            coverage_bitmap: (0..1024).map(|_| AtomicU64::new(0)).collect(),
        });
        let corpus = corpus.clone();

        let transformer = Transformer::from_callback(&GUM, move |basic_block, _output| {
            for instr in basic_block {
                let insn = instr.instr();

                let ptr = insn.address() as *const u8;
                let op = unsafe { *ptr };

                match op {
                    0xE8 => print!("call         {:#x}\n", insn.address()),
                    0xEB => print!("jmp 05       {:#x}\n", insn.address()),
                    0xE9 => print!("jmp 0x123    {:#x}\n", insn.address()),
                    0xFF => print!("jmp rax      {:#x}\n", insn.address()),
                    0x70 => print!("jo cond      {:#x}\n", insn.address()),
                    0x71 => print!("jno cond     {:#x}\n", insn.address()),
                    0x72 => print!("jb/jc cond   {:#x}\n", insn.address()),
                    0x73 => print!("jae/jnc cond {:#x}\n", insn.address()),
                    0x74 => print!("je/jz cond   {:#x}\n", insn.address()),
                    0x75 => print!("jne/jnz cond {:#x}\n", insn.address()),
                    0x76 => print!("jbe cond     {:#x}\n", insn.address()),
                    0x77 => print!("ja cond      {:#x}\n", insn.address()),
                    0x78 => print!("js cond      {:#x}\n", insn.address()),
                    0x79 => print!("jns cond     {:#x}\n", insn.address()),
                    0x7A => print!("jp cond      {:#x}\n", insn.address()),
                    0x7B => print!("jnp cond     {:#x}\n", insn.address()),
                    0x7C => print!("jl cond      {:#x}\n", insn.address()),
                    0x7D => print!("jge cond     {:#x}\n", insn.address()),
                    0x7E => print!("jle cond     {:#x}\n", insn.address()),
                    0x7F => print!("jg cond      {:#x}\n", insn.address()),

                    0xC3 => print!("ret  {:#x}\n", insn.address()),
                    _=> {}
                }

                //corpus.coverage_bitmap[4].fetch_or(4, Ordering::Relaxed);
                instr.put_callout(|_cpu_context| {});
                instr.keep();
            }
        });

        let blocks_collected: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let mut event_sink = SampleEventSink {
            blocks: Arc::clone(&blocks_collected),
        };

        if tid == 0 {
            stalker.follow_me(&transformer, Some(&mut event_sink));
            //stalker.unfollow_me();
        }



        /*type ParserFn = unsafe extern "C" fn(
                *mut Context,
                *const u8,
                usize,
        );*/

        //let parser: ParserFn = unsafe { std::mem::transmute(parser_addr) };

    }

    fn setup_hook(&self) {
        let mut interceptor = Box::leak(Box::new(Interceptor::obtain(&GUM)));
        interceptor.attach(
            NativePointer(self.target_addr as *mut _),
            Box::leak(Box::new(HookListener { followed: false })),
        );
    }

}

#[ctor]
fn init() {
    let process = frida_gum::Process::obtain(&GUM);
    println!("Process Information");
    println!("-------------------");
    println!(" - ID: {}", process.id());
    println!(" - Platform {:?}", process.platform());
    println!(" - Code signing policy: {:?}", process.code_signing_policy());
    println!(" - Main module: {:x?}", process.main_module());
    println!(" - Current thread ID: {}", process.current_thread_id());
    println!(" - Enumerate modules:");
    let ranges = process.enumerate_modules();
    for module in ranges {
        println!("   - {:?}", module);
    }

    //let module = process.find_module_by_name("test").unwrap();
    //let module_base = module.range().base_address();
    //let off_target = module_base + 0xxx;

    println!("\n");

    let addr: usize = 0x000000000040131a;

    let mut fuzz = Fuzzer::new(addr);
    fuzz.setup_stalker(0);
    //fuzz.setup_hook();
}
