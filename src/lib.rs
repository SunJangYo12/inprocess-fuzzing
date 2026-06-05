mod bitmap;
mod mutator;

use frida_gum as gum;
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, Transformer};
use frida_gum::interceptor::{Interceptor, InvocationContext, InvocationListener};
use frida_gum::NativePointer;
use lazy_static::lazy_static;
use ctor::ctor;
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::fs::File;
use std::io::Write;
use std::collections::HashSet;
use rand::Rng;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};

use atomicvec::AtomicVec;
use aht::Aht;
use falkhash::FalkHasher;
use bitmap::Bitmap;
use mutator::HavocMutator;

lazy_static! {
    static ref GUM: gum::Gum = unsafe { gum::Gum::obtain() };
}

pub const MAP_SIZE: usize = 65536;

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
    /// fuzzcases per second
    fcps: AtomicU64,

    /// new edge path
    edge: AtomicU64,

    /// edge for hit count like detect loop or state
    edge_state: AtomicU64,

    /// unique input or hit new edge
    queue: AtomicU64,
}

struct HookListener {
    is_hit: Arc<Mutex<bool>>,
    stats: Arc<Stats>,
    corpus: Arc<Corpus>,

    fuzz_input: Vec<u8>,
    bitmap: Box<Bitmap>,
}

impl InvocationListener for HookListener {
    fn on_enter(&mut self, _context: InvocationContext) {
        let mut hit = self.is_hit.lock().unwrap();

        if *hit {
            *hit = false;

            let bitmap_ptr: *mut Bitmap = self.bitmap.as_mut() as *mut Bitmap;

            // stalker worker
            let corpus1 = self.corpus.clone();
            worker_stalker(corpus1, bitmap_ptr);

            let cpu = _context.cpu_context();

            println!("[+] Target HIT {:#x}", cpu.rip());
            type HarnessFn = extern "C" fn(*const u8);
            let harness: HarnessFn = unsafe {
                std::mem::transmute(self.corpus.target.load(Ordering::Relaxed) as *const ())
            };

            // dry input
            for filename in std::fs::read_dir("inputs").unwrap() {
                let filename = filename.unwrap().path();
                let data = std::fs::read(&filename).unwrap();

                print!("[+] Dry inputs {}\n", filename.display());

                self.bitmap.clear();

                self.fuzz_input.extend_from_slice(&data);
                harness(self.fuzz_input.as_ptr());

                self.bitmap.classify_counts();
                let input_hash = self.corpus.hasher.myhash(&self.fuzz_input);

                match self.bitmap.has_new_bits() {
                    2 => {
                        self.stats.edge.fetch_add(1, Ordering::Relaxed);
                        self.corpus.input_hashes.entry_or_insert(&input_hash, input_hash as usize, || {
                            self.corpus.inputs.push(Box::new(self.fuzz_input.clone()));
                            self.stats.queue.fetch_add(1, Ordering::Relaxed);
                            Box::new(())
                        });
                    }
                    1 => {
                        print!("new hit count\n");
                        self.stats.edge_state.fetch_add(1, Ordering::Relaxed);
                        self.corpus.input_hashes.entry_or_insert(&input_hash, input_hash as usize, || {
                            self.corpus.inputs.push(Box::new(self.fuzz_input.clone()));
                            self.stats.queue.fetch_add(1, Ordering::Relaxed);
                            Box::new(())
                        });
                    }
                    _ => {}
                }
                self.stats.fcps.fetch_add(1, Ordering::Relaxed);
                self.fuzz_input.clear();
            }

            let havoc = HavocMutator::new();
            let mut rng = rand::rng();

            print!("[+] Start fuzzing...\n");
            loop {
                // Pick a random file from the corpus as an input
                if self.corpus.inputs.len() > 0 {
                    //let sel = rng.rand() % self.corpus.inputs.len();
                    let sel = rand::random_range(0..=self.corpus.inputs.len());
                    if let Some(input) = self.corpus.inputs.get(sel) {
                        self.fuzz_input.extend_from_slice(input);
                    }
                }

                havoc.mutate(&mut rng, &mut self.fuzz_input);

                // reset bitmap
                self.bitmap.clear();

                harness(self.fuzz_input.as_ptr());

                self.bitmap.classify_counts();

                match self.bitmap.has_new_bits() {
                    2 => {
                        //print!("new path: {:#x}\n", self.bitmap.last_pc);
                        self.stats.edge.fetch_add(1, Ordering::Relaxed);

                        let input_hash = self.corpus.hasher.myhash(&self.fuzz_input);
                        let input_clone = self.fuzz_input.clone();

                        self.corpus.input_hashes.entry_or_insert(&input_hash, input_hash as usize, || {
                            let input_save = input_clone;

                            let newinput = std::path::Path::new("queue").join(
                                format!("edge({}):{:#x}:{:x?}",
                                    self.stats.edge.load(Ordering::Relaxed),
                                    self.bitmap.last_pc,
                                    input_hash
                                )
                            );
                            let _ = std::fs::write(newinput, &input_save);

                            self.corpus.inputs.push(Box::new(input_save));
                            self.stats.queue.fetch_add(1, Ordering::Relaxed);
                            Box::new(())
                        });
                    }
                    1 => {
                        print!("new hit count: {:#x}\n", self.bitmap.last_pc);
                        self.stats.edge_state.fetch_add(1, Ordering::Relaxed);

                    }
                    _ => {}
                }

                self.stats.fcps.fetch_add(1, Ordering::Relaxed);
                self.fuzz_input.clear();

                //debug
                //std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    fn on_leave(&mut self, _context: InvocationContext) {
    }
}

struct Corpus {
    /// overwrite data for file log
    target: AtomicU64,
    tid_parent: u32,
    coverage_log: Mutex<File>,

    /// no duplicate write coverage.txt
    seen_blocks: Mutex<HashSet<u64>>,

    input_hashes: Aht<u128, (), 1048576>,
    inputs: AtomicVec<Vec<u8>, 1048576>,
    hasher: FalkHasher,
}

fn worker_stalker(corpus: Arc<Corpus>, bitmap_ptr: *mut Bitmap) {
    let mut stalker = Stalker::new(&GUM);
    let process = frida_gum::Process::obtain(&GUM);

    /*
    let stalker_whitelist = ["test"];
    for module in process.enumerate_modules() {
        let name = module.name();
        if stalker_whitelist.contains(&name.as_str()) {
            println!("   - Oke: {:?}", module);
        } else {
            println!("   - Exclude: {:?}", module);
            stalker.exclude(&module.range()); //not work
        }
    }*/
    let target = process.enumerate_modules().into_iter().find(|m| m.name() == "test").unwrap();

    let start = target.range().base_address().0 as u64;
    let end = start + target.range().size() as u64;

    print!("[+] Stalking [{:#X}] range = {:#x} - {:#x}\n",
        corpus.target.load(Ordering::Relaxed), start, end);

    let transformer = Transformer::from_callback(&GUM, move |basic_block, _output| {
        let mut begin = true;

        for instr in basic_block {
            let insn = instr.instr();

            if begin {
                let cur_loc = ((insn.address() as u64 >> 4) & 0xffff) as u64;

                if insn.address() >= start && insn.address() < end {
                    //print!("stalk {:x}\n", insn.address());
                    
                    let bm = bitmap_ptr;
                    unsafe { (*bm).last_pc = insn.address(); }

                    instr.put_callout(move|_cpu_context| {
                        unsafe {
                            //(*bm).hit(cur_loc);
                            let prev = (*bm).prev_loc;
                            let idx = ((prev ^ cur_loc) as usize) & (MAP_SIZE - 1);

                            (*bm).trace_bits[idx] = (*bm).trace_bits[idx].wrapping_add(1);

                            (*bm).prev_loc = cur_loc >> 1;
                        }
                    });
                }
                begin = false;
            }
            instr.keep();
        }
    });

    let mut event_sink = SampleEventSink {
    };

    stalker.set_trust_threshold(0);
    let tid = corpus.tid_parent as usize;
    if tid == 0 {
        stalker.follow_me(&transformer, Some(&mut event_sink));
        //stalker.unfollow_me();
    } else {
        stalker.follow(tid, &transformer, Some(&mut event_sink));
    }
}

fn handle_client(mut stream: TcpStream, corpus: Arc<Corpus>, stats: Arc<Stats>) {
    let reader_stream = stream.try_clone().unwrap();
    let mut reader = BufReader::new(reader_stream);

    writeln!(stream, "\n").unwrap();
    writeln!(stream, "  Welcome to FUZZER PROXY").unwrap();
    writeln!(stream, "              v3.2.1\n").unwrap();

    loop {
        write!(stream, "> ").unwrap();
        stream.flush().unwrap();

        let mut line = String::new();

        match reader.read_line(&mut line) {
            Ok(0) => break, // client disconnect
            Ok(_) => {
                let cmd = line.trim();

                if cmd == "help" {
                    writeln!(stream, "1. target: hook target address").unwrap();
                    writeln!(stream, "2. tracebuf: tracing all function for potential input buffer by user").unwrap();
                    writeln!(stream, "3. stats: show information for fuzzer proces live no promt").unwrap();
                    writeln!(stream, "4. stat: show 10 cases information for fuzzer proces, back to prompt").unwrap();
                    writeln!(stream, "5. help: show help").unwrap();
                }
                else if cmd == "target" {
                    write!(stream, "Example 0x000000000040131a\n").unwrap();
                    write!(stream, "target> ").unwrap();

                    let mut addr = String::new();
                    reader.read_line(&mut addr);

                    // fuzzer worker
                    //let corpus_fuzz = corpus.clone();
                    let is_hit = Arc::new(Mutex::new(true));
                    let listener = Box::leak(Box::new(
                        HookListener {
                            is_hit: Arc::clone(&is_hit),
                            stats:  Arc::clone(&stats),
                            corpus: Arc::clone(&corpus),

                            fuzz_input:   Vec::new(),
                            bitmap: Box::new(Bitmap::new()),
                        }
                    ));

                    let addr = u64::from_str_radix(addr.trim().trim_start_matches("0x"), 16).expect("gagal string to usize");

                    corpus.target.store(addr, Ordering::Relaxed);

                    let interceptor = Box::leak(Box::new(Interceptor::obtain(&GUM)));
                    interceptor.attach(
                        NativePointer(addr as *mut _),
                        listener,
                    ).unwrap();
                    write!(stream, "[+] Attaching: {:#x}\n", addr).unwrap();
                }
                else if cmd == "stat" {
                    let start = Instant::now();
                    for zz in 0..10 {
                        let elapsed = start.elapsed().as_secs_f64();
                        let fcps = stats.fcps.load(Ordering::Relaxed) as f64 / elapsed;
                        let queue = stats.queue.load(Ordering::Relaxed);
                        let edges = stats.edge.load(Ordering::Relaxed);
                        let edge_state = stats.edge_state.load(Ordering::Relaxed);

                        let density = (edges as f64 / MAP_SIZE as f64) * 100.0;

                        write!(stream, "[{:10.4}] fcps {:5.0} | path: {}/{} |\
                                        density {:.2}% | queue {}\n",
                            elapsed, fcps, edges, edge_state, density, queue
                        ).unwrap();
                    }
                }
                else if cmd == "stats" {
                    let start = Instant::now();
                    loop {
                        let elapsed = start.elapsed().as_secs_f64();
                        let fcps = stats.fcps.load(Ordering::Relaxed) as f64 / elapsed;
                        let queue = stats.queue.load(Ordering::Relaxed);
                        let edges = stats.edge.load(Ordering::Relaxed);
                        let edge_state = stats.edge_state.load(Ordering::Relaxed);

                        let density = (edges as f64 / MAP_SIZE as f64) * 100.0;

                        write!(stream, "[{:10.4}] fcps {:5.0} | path: {}/{} |\
                                        density {:.2}% | queue {}\n",
                            elapsed, fcps, edges, edge_state, density, queue
                        ).unwrap();
                        std::thread::sleep(Duration::from_millis(1000));
                    }
                }
                else if cmd == "exit" {
                    writeln!(stream, "bye").unwrap();
                    break;
                }
                else {
                    writeln!(stream, "\n'{}' command not found\n", cmd).unwrap();
                }
            }
            Err(_) => break,
        }
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
    println!("\n");

    std::fs::create_dir_all("inputs").expect("Folder inputs gagal dibuat");
    std::fs::create_dir_all("queue").expect("Folder inputs gagal dibuat");
    std::fs::create_dir_all("crashes").expect("Folder crashes gagal dibuat");

    let stats = Arc::new(Stats {
        fcps:   AtomicU64::new(0),
        queue: AtomicU64::new(0),
        edge: AtomicU64::new(0),
        edge_state: AtomicU64::new(0),
    });

    let corpus = Arc::new(Corpus {
        target:          AtomicU64::new(0),
        tid_parent:      process.id(),
        coverage_log:    Mutex::new(File::create("coverage.txt").expect("Failed to create coverage file")),
        seen_blocks:     Mutex::new(HashSet::new()),
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
            stats.queue.fetch_add(1, Ordering::Relaxed);
            Box::new(())
        });
    }

    let corpus2 = corpus.clone();
    let stats2 = Arc::clone(&stats);
    std::thread::spawn(move|| {
        let listener = TcpListener::bind("0.0.0.0:1212").expect("Failed create server");
        println!("[+] Listening on port 1212");
        println!("[+] Waiting hit for target...");

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let corpus3 = corpus2.clone();
                    let stats3 = Arc::clone(&stats2);

                    std::thread::spawn(move|| {
                        handle_client(stream, corpus3, stats3);
                    });
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    });
}
