//pub mod instrument;

use frida_gum as gum;
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, Transformer};
use frida_gum::interceptor::{Interceptor, InvocationContext, InvocationListener};
use frida_gum::{Module, NativePointer, MemoryRange};
use lazy_static::lazy_static;
use ctor::ctor;
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::fs::File;
use std::io::Write;
use std::collections::HashSet;

use atomicvec::AtomicVec;
use aht::Aht;
use falkhash::FalkHasher;
//use instrument::Instrument;

lazy_static! {
    static ref GUM: gum::Gum = unsafe { gum::Gum::obtain() };
}

const MAP_SIZE: usize = 65536;
const TARGET_ADDR: usize = 0x000000000040131a;

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

struct SampleEventSink;

impl EventSink for SampleEventSink {
    fn query_mask(&mut self) -> EventMask {
        EventMask::None
    }
    fn start(&mut self) {
        println!("start");
    }
    fn process(&mut self, _event: &Event) {
        println!("process");
    }
    fn flush(&mut self) {
        println!("flush");
    }
    fn stop(&mut self) {
        println!("stop");
    }
}

struct Stats {
    fcps: AtomicU64,
    unique: AtomicU64,
}

struct HookListener {
    is_hit: Arc<Mutex<bool>>,
    stats: Arc<Stats>,
    corpus: Arc<Corpus>,

    fuzz_input: Vec<u8>,
}

impl InvocationListener for HookListener {
    fn on_enter(&mut self, _context: InvocationContext) {
        let mut hit = self.is_hit.lock().unwrap();

        if *hit {
            *hit = false;

            // stalker worker
            let corpus1 = self.corpus.clone();
            std::thread::spawn(move|| {
                worker_stalker(corpus1);
            });

            let cpu = _context.cpu_context();
            let mut rng = Rng::new();

            println!("[+] Target HIT {:#x}", cpu.rip());
            type HarnessFn = extern "C" fn(*const u8);
            let harness: HarnessFn = unsafe {
                std::mem::transmute(TARGET_ADDR as *const ())
            };

            print!("[+] Start fuzzing... {}\n", self.corpus.inputs.len());

            loop {
                // Pick a random file from the corpus as an input
                if self.corpus.inputs.len() > 0 {
                    let sel = rng.rand() % self.corpus.inputs.len();
                    if let Some(input) = self.corpus.inputs.get(sel) {
                        self.fuzz_input.extend_from_slice(input);
                    }
                }
                // The worlds best mutator
                if self.fuzz_input.len() > 0 {
                    for _ in 0..rng.rand() % 16 {
                        let sel = rng.rand() % self.fuzz_input.len();
                        self.fuzz_input[sel] = rng.rand() as u8;
                    }
                }
                // reset bitmap
                //self.corpus.prev_loc.store(0, Ordering::Relaxed);

                harness(self.fuzz_input.as_ptr());

                self.stats.fcps.fetch_add(1, Ordering::Relaxed);
                self.fuzz_input.clear();

                //debug
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    fn on_leave(&mut self, _context: InvocationContext) {
    }
}


struct Corpus {
    /// hanya saat harness dieksekusi, lalu direset
    coverage_bitmap: Box<[u8; MAP_SIZE]>,
    prev_loc: u64,

    /// coverage sebenarnya
    virgin_bitmap: Vec<AtomicU8>,

    /// overwrite data for file log
    last_block: AtomicU64,
    tid_parent: u32,
    coverage_log: Mutex<File>,
    coverage_range: Vec<MemoryRange>,

    /// no duplicate write coverage.txt
    seen_blocks: Mutex<HashSet<u64>>,

    input_hashes: Aht<u128, (), 1048576>,
    inputs: AtomicVec<Vec<u8>, 1048576>,
    hasher: FalkHasher,
}

fn worker_stalker(corpus: Arc<Corpus>) {
    let mut stalker = Stalker::new(&GUM);

    /*
    for range in &corpus.coverage_range {
        print!("[+] Stalking blacklist {}\n", range);
        stalker.exclude(range);
    }*/

    let tid = corpus.tid_parent as usize;

    let transformer = Transformer::from_callback(&GUM, move |basic_block, _output| {
        let mut begin = true;

        for instr in basic_block {
            let insn = instr.instr();

            if begin {
                /* example:
                    0x401230 >> 4    = 0x40123
                    0x40123 & 0xffff = 0x0123 -> ini jadi id block
                */
                let cur_loc = ((insn.address() as u64 >> 4) & 0xffff) as u64;

                //print!("stalk {:x}\n", insn.address());
                let corpus2 = corpus.clone();



                let bitmap_ptr = corpus.coverage_bitmap.as_ptr() as *mut u8;
                let prev_loc_ptr = &corpus.prev_loc as *const u64 as *mut u64;

                instr.put_callout(move |_cpu_context| {
                    corpus2.last_block.store(insn.address() as u64, Ordering::Relaxed);

                    let mut prev = unsafe { *prev_loc_ptr };

                    // example: 0x100 ^ 0x200 = 0x300
                    // cov 0x100 -> 0x200 dipetakan ke bitmap[0x300]
                    let idx  = ((prev ^ cur_loc) as usize) & (MAP_SIZE - 1);

                    // bitmap[0x300] = 0 -> 1
                    // jika edge sama dilewati lagi alias bitmap[0x300] = 2 dst
                    unsafe {
                        let p = bitmap_ptr.add(idx);
                        *p = (*p).wrapping_add(1);

                        // example: cur_loc = 0x200 maka prev_loc = 0x100
                        // tujuan pakai ini supaya A->B tidak sama B->A
                        prev = cur_loc >> 1;
                    }
                });
                begin = false;
            }
            instr.keep();
        }
    });

    let mut event_sink = SampleEventSink {
    };

    if tid == 0 {
        stalker.follow_me(&transformer, Some(&mut event_sink));
        //stalker.unfollow_me();
    } else {
        stalker.follow(tid, &transformer, Some(&mut event_sink));
    }
}

fn worker_monitor(corpus: Arc<Corpus>, stats: Arc<Stats>) {
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed().as_secs_f64();
        let fcps = stats.fcps.load(Ordering::Relaxed) as f64 / elapsed;
        let unique = stats.unique.load(Ordering::Relaxed);

        let mut edges = 0;
        for &x in corpus.coverage_bitmap.iter() {
            // Jika nilai bukan lagi 0xFF, berarti setidaknya ada 1 bucket/jalur
            // yang sudah ditemukan oleh fuzzer di index in.
            if x != 0 {
                edges += 1;
            }
        }

        let density = (edges as f64 / MAP_SIZE as f64) * 100.0;

        print!("[{:10.4}] fcps {:5.0} | path: {} | density {:.2}% | unique {}\n",
            elapsed, fcps, edges, density, unique
        );

        let last = corpus.last_block.load(Ordering::Relaxed);
        let mut seen = corpus.seen_blocks.lock().unwrap();

        if seen.insert(last) {
            let mut cl = corpus.coverage_log.lock().unwrap();
            write!(cl, "{:x},{},{:5.0},{}\n", last, edges, fcps, unique).unwrap();
        }

        std::thread::sleep(Duration::from_millis(1000));
    }
}

#[ctor]
fn init() {
    std::fs::create_dir_all("inputs").expect("Folder inputs gagal dibuat");
    std::fs::create_dir_all("crashes").expect("Folder crashes gagal dibuat");

    let process = frida_gum::Process::obtain(&GUM);
    println!("Process Information");
    println!("-------------------");
    println!(" - ID: {}", process.id());
    println!(" - Platform {:?}", process.platform());
    println!(" - Code signing policy: {:?}", process.code_signing_policy());
    println!(" - Main module: {:x?}", process.main_module());
    println!(" - Current thread ID: {}", process.current_thread_id());
    println!(" - Enumerate modules:");

    let stalker_whitelist = ["test"];
    let mut stalker_range = Vec::new();

    let all_modules = process.enumerate_modules();
    for module in all_modules {
        println!("   - {:?}", module);

        let name = module.name();
        if !stalker_whitelist.contains(&name.as_str()) {
            stalker_range.push(module.range());
        }
    }
    println!("\n");


    let corpus = Arc::new(Corpus {
        //coverage_bitmap: (0..MAP_SIZE).map(|_| AtomicU8::new(0)).collect(),
        coverage_bitmap: Box::new([0; MAP_SIZE]),
        virgin_bitmap:   (0..MAP_SIZE).map(|_| AtomicU8::new(0xFF)).collect(),
        prev_loc:        0u64,
        last_block:      0.into(),
        tid_parent:      process.id(),
        coverage_log:    Mutex::new(File::create("coverage.txt").expect("Failed to create coverage file")),
        seen_blocks:     Mutex::new(HashSet::new()),
        coverage_range:  stalker_range,
        input_hashes: Aht::new(),
        inputs:       AtomicVec::new(),
        hasher:       FalkHasher::new(),
    });


    for filename in std::fs::read_dir("inputs").unwrap() {
        let filename = filename.unwrap().path();
        let data = std::fs::read(filename).unwrap();
        let hash = corpus.hasher.myhash(&data);

        // Save the input and log it in the hash table
        corpus.input_hashes.entry_or_insert(&hash, hash as usize, || {
            corpus.inputs.push(Box::new(data));
            Box::new(())
        });
    }


    // fuzzer worker
    let is_hit = Arc::new(Mutex::new(true));
    let stats = Arc::new(Stats {
        fcps:   AtomicU64::new(0),
        unique: AtomicU64::new(0),
    });

    let corpus_fuzz = corpus.clone();
    let listener = Box::leak(Box::new(
        HookListener {
            is_hit: Arc::clone(&is_hit),
            stats:  Arc::clone(&stats),
            corpus: Arc::clone(&corpus_fuzz),

            fuzz_input:   Vec::new(),
        }
    ));
            
    let interceptor = Box::leak(Box::new(Interceptor::obtain(&GUM)));
    interceptor.attach(
        NativePointer(TARGET_ADDR as *mut _),
        listener,
    ).unwrap();

    // monitor worker
    let corpus2 = corpus.clone();
    let stats2 = Arc::clone(&stats);
    std::thread::spawn(move|| {
        worker_monitor(corpus2, stats2);
    });

}
