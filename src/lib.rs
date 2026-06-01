use frida_gum as gum;
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, Transformer};
use frida_gum::interceptor::{Interceptor, InvocationContext, InvocationListener};
use frida_gum::{Module, NativePointer};
use lazy_static::lazy_static;
use ctor::ctor;
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

lazy_static! {
    static ref GUM: gum::Gum = unsafe { gum::Gum::obtain() };
}

const MAP_SIZE: usize = 65536;

fn rdtsc() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}

struct Rng(u64);
impl Rng {
    /// Create a new random number generator
    fn new() -> Self {
        Rng(0x342c4d6241337665 ^ rdtsc())
    }

    // Generate a random number
    #[inline]
    fn rand(&mut self) -> usize {
        let val = self.0;
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 43;
        val as usize
    }
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
    is_stalked: bool,
    stalker: Stalker,
}

impl InvocationListener for HookListener {
    fn on_enter(&mut self, _context: InvocationContext) {
        println!("enter");
    }
    fn on_leave(&mut self, _context: InvocationContext) {
        println!("leave");
    }
}


struct Corpus {
    coverage_bitmap: Vec<AtomicU8>,
    prev_loc: AtomicU64,
}
/*
impl Corpus {
    fn get_corpus(self) {
        let mut edges = 0;
        for x in self.coverage_bitmap {
            if x.load(Ordering::Relaxed) != 0 {
                edges += 1;
            }
        }
        print!("edges: {}\n", edges);
    }
}*/

fn worker_stalker(corpus: Arc<Corpus>, tid: usize) {
    let mut stalker = Stalker::new(&GUM);

    let transformer = Transformer::from_callback(&GUM, move |basic_block, _output| {
        let mut begin = true;

        for instr in basic_block {
            let insn = instr.instr();

            if begin {
                let cur_loc = ((insn.address() as u64 >> 4) & 0xffff) as u64;

                //print!("stalk {:x}\n", insn.address());
                let corpus2 = corpus.clone();

                instr.put_callout(move |_cpu_context| {
                    let prev = corpus2.prev_loc.load(Ordering::Relaxed);
                    let idx  = ((prev ^ cur_loc) as usize) & (MAP_SIZE - 1);

                    corpus2.coverage_bitmap[idx].fetch_add(1, Ordering::Relaxed);
                    corpus2.prev_loc.store(cur_loc >> 1, Ordering::Relaxed);
                });
                begin = false;
            }
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
    } else {
        stalker.follow(tid, &transformer, Some(&mut event_sink));
    }
/*
    type ParserFn = unsafe extern "C" fn(
            *mut Context,
            *const u8,
            usize,
    );
    let parser: ParserFn = unsafe { std::mem::transmute(parser_addr) };*/
}

fn worker_monitor(corpus: Arc<Corpus>) {
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed().as_secs_f64();

        let mut edges = 0;
        for x in &corpus.coverage_bitmap {
            if x.load(Ordering::Relaxed) != 0 {
                edges += 1;
            }
        }

        let density = (edges as f64 / MAP_SIZE as f64) * 100.0;

        print!("[{:10.4}] paths: {} | density {:.2}% | \n", elapsed, edges, density);
        std::thread::sleep(Duration::from_millis(1000));
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


    let corpus = Arc::new(Corpus {
        coverage_bitmap: (0..MAP_SIZE).map(|_| AtomicU8::new(0)).collect(),
        prev_loc: 0.into(),
    });

    // stalker worker
    let corpus1 = corpus.clone();
    std::thread::spawn(move|| {
        worker_stalker(corpus1, process.id() as usize);

        println!(" - Stalker thread ID: {} | Attach ID: {}", process.current_thread_id(), process.id());
    });

    // monitor worker
    let corpus2 = corpus.clone();
    std::thread::spawn(move|| {
        worker_monitor(corpus2);
    });

    let addr: usize = 0x000000000040131a;
    //let mut fuzz = Fuzzer::new(addr);
    //fuzz.setup_stalker(0);
    //fuzz.setup_hook();

    let mut input: Vec<u8> = vec![0x41, 0x41, 0x41, 0x41];
    let mut rng = Rng::new();

    type HarnessFn = extern "C" fn(*const u8);
    let harness: HarnessFn = unsafe {
        std::mem::transmute(addr as *const ())
    };
    loop {

        harness(input.as_ptr());

        for _ in 0..rng.rand() % 16 {
           let sel = rng.rand() % &input.len();
           input[sel] = rng.rand() as u8;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }


/*    let mut interceptor = Box::leak(Box::new(Interceptor::obtain(&GUM)));
    interceptor.attach(
        NativePointer(addr as *mut _),
        Box::leak(Box::new(
            HookListener {
                is_stalked: true,
                stalker: Stalker::new(&GUM),
            }
        )),
    );*/
}

