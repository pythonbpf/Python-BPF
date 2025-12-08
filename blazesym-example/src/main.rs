// src/main.rs - Fixed imports and error handling
use std::mem;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use blazesym::symbolize::{CodeInfo, Input, Symbolized, Symbolizer};
use blazesym::symbolize::source::{Source, Kernel, Process};
use clap::Parser;
use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder};  // Added MapCore

// Match your Python struct exactly
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ExecEvent {
    pid: i64,
    cpu: i32,
    timestamp: i64,
    comm: [u8; 16],
    kstack_sz: i64,
    ustack_sz: i64,
    kstack: [u8; 128],  // str(128) in Python
    ustack: [u8; 128],  // str(128) in Python
}

unsafe impl plain::Plain for ExecEvent {}

// Define perf_event constants (not in libc on all platforms)
const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

#[repr(C)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    // ... rest can be zeroed
    _padding: [u64; 64],
}

#[derive(Parser, Debug)]
struct Args {
    /// Path to the BPF object file
    #[arg(default_value = "stack_traces.o")]
    object_file: PathBuf,

    /// Sampling frequency
    #[arg(short, long, default_value_t = 50)]
    freq: u64,

    /// Use software events
    #[arg(long)]
    sw_event: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn open_perf_event(cpu: i32, freq: u64, sw_event: bool) -> Result<i32> {
    let mut attr: PerfEventAttr = unsafe { mem::zeroed() };

    attr.size = mem::size_of::<PerfEventAttr>() as u32;
    attr.type_ = if sw_event {
        PERF_TYPE_SOFTWARE
    } else {
        PERF_TYPE_HARDWARE
    };
    attr.config = if sw_event {
        PERF_COUNT_SW_CPU_CLOCK
    } else {
        PERF_COUNT_HW_CPU_CYCLES
    };

    // Use frequency-based sampling
    attr.sample_period_or_freq = freq;
    attr.flags = 1 << 10; // freq = 1, disabled = 1

    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const _,
            -1,      // pid = -1 (all processes)
            cpu,     // cpu
            -1,      // group_fd
            0,       // flags
        )
    };

    if fd < 0 {
        Err(anyhow!("Failed to open perf event on CPU {}: {}", cpu,
                    std::io::Error::last_os_error()))
    } else {
        Ok(fd as i32)
    }
}

fn print_stack_trace(
    addrs: &[u64],
    symbolizer: &Symbolizer,
    pid: u32,
    is_kernel: bool,
) {
    if addrs.is_empty() {
        return;
    }

    let src = if is_kernel {
        Source::Kernel(Kernel::default())
    } else {
        Source::Process(Process::new(pid.into()))
    };

    let syms = match symbolizer.symbolize(&src, Input::AbsAddr(addrs)) {
        Ok(syms) => syms,
        Err(e) => {
            eprintln!("  Failed to symbolize: {}", e);
            for addr in addrs {
                println!("0x{:016x}: <no-symbol>", addr);
            }
            return;
        }
    };

    for (addr, sym) in addrs.iter().zip(syms.iter()) {
        match sym {
            Symbolized::Sym(sym_info) => {
                print!("0x{:016x}: {} @ 0x{:x}+0x{:x}",
                       addr, sym_info.name, sym_info.addr, sym_info.offset);

                if let Some(ref code_info) = sym_info.code_info {
                    print_code_info(code_info);
                }
                println!();

                // Print inlined frames
                for inlined in &sym_info.inlined {
                    print!("                  {} (inlined)", inlined.name);
                    if let Some(ref code_info) = inlined.code_info {
                        print_code_info(code_info);
                    }
                    println!();
                }
            }
            Symbolized::Unknown(..) => {
                println!("0x{:016x}: <no-symbol>", addr);
            }
        }
    }
}

fn print_code_info(code_info: &CodeInfo) {
    let path = code_info.to_path();
    let path_str = path.display();

    match (code_info.line, code_info.column) {
        (Some(line), Some(col)) => print!(" {}:{}:{}", path_str, line, col),
        (Some(line), None) => print!(" {}:{}", path_str, line),
        (None, _) => print!(" {}", path_str),
    }
}

fn handle_event(symbolizer: &Symbolizer, data: &[u8]) -> i32 {
    let event = plain::from_bytes::<ExecEvent>(data).expect("Invalid event data");

    // Extract comm string
    let comm = std::str::from_utf8(&event.comm)
        .unwrap_or("<unknown>")
        .trim_end_matches('\0');

    println!("[{:.9}] COMM: {} (pid={}) @ CPU {}",
             event.timestamp as f64 / 1_000_000_000.0,
             comm,
             event.pid,
             event.cpu);

    // Handle kernel stack
    if event.kstack_sz > 0 {
        println!("Kernel:");
        let num_frames = (event.kstack_sz / 8) as usize;
        let kstack_u64 = unsafe {
            std::slice::from_raw_parts(
                event.kstack.as_ptr() as *const u64,
                num_frames.min(16),
            )
        };

        // Filter out zero addresses
        let kstack: Vec<u64> = kstack_u64.iter()
            .copied()
            .take_while(|&addr| addr != 0)
            .collect();

        print_stack_trace(&kstack, symbolizer, 0, true);
    } else {
        println!("No Kernel Stack");
    }

    // Handle user stack
    if event.ustack_sz > 0 {
        println!("Userspace:");
        let num_frames = (event.ustack_sz / 8) as usize;
        let ustack_u64 = unsafe {
            std::slice::from_raw_parts(
                event.ustack.as_ptr() as *const u64,
                num_frames.min(16),
            )
        };

        // Filter out zero addresses
        let ustack: Vec<u64> = ustack_u64.iter()
            .copied()
            .take_while(|&addr| addr != 0)
            .collect();

        print_stack_trace(&ustack, symbolizer, event.pid as u32, false);
    } else {
        println!("No Userspace Stack");
    }

    println!();
    0
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.object_file.exists() {
        return Err(anyhow!("Object file not found: {:?}", args.object_file));
    }

    println!("Loading BPF object: {:?}", args.object_file);

    // Load BPF object
    let mut obj_builder = ObjectBuilder::default();
    obj_builder.debug(args.verbose);

    let open_obj = obj_builder
        .open_file(&args.object_file)
        .context("Failed to open BPF object")?;

    let mut obj = open_obj.load().context("Failed to load BPF object")?;

    println!("✓ BPF object loaded");

    // Find the program
    let prog = obj
        .progs_mut()
        .find(|p| p.name() == "trace_exec_enter")
        .ok_or_else(|| anyhow!("Program 'trace_exec_enter' not found"))?;

    println!("✓ Found program: trace_exec_enter");

    // Find the map
    let map = obj
        .maps()
        .find(|m| m.name() == "exec_events")
        .ok_or_else(|| anyhow!("Map 'exec_events' not found"))?;

    println!("✓ Found map: exec_events");

    // Get number of CPUs
    let num_cpus = libbpf_rs::num_possible_cpus()?;
    println!("✓ Detected {} CPUs\n", num_cpus);

    // Open perf events and attach BPF program
    println!("Setting up perf events...");
    let mut links = Vec::new();

    for cpu in 0..num_cpus {
        match open_perf_event(cpu as i32, args.freq, args.sw_event) {
            Ok(perf_fd) => {
                match prog.attach_perf_event(perf_fd) {
                    Ok(link) => {
                        links.push(link);
                        if args.verbose {
                            println!("  ✓ Attached to CPU {}", cpu);
                        }
                    }
                    Err(e) => {
                        eprintln!("  ✗ Failed to attach to CPU {}: {}", cpu, e);
                        unsafe { libc::close(perf_fd); }
                    }
                }
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("  ✗ Failed to open perf event on CPU {}: {}", cpu, e);
                }
            }
        }
    }

    println!("✓ Attached to {} CPUs\n", links.len());

    if links.is_empty() {
        return Err(anyhow!("Failed to attach to any CPU"));
    }

    // Initialize symbolizer
    let symbolizer = Symbolizer::new();

    // Set up ring buffer
    let mut builder = RingBufferBuilder::new();

    builder.add(&map, move |data: &[u8]| -> i32 {
        handle_event(&symbolizer, data)
    })?;

    let ringbuf = builder.build()?;

    println!("========================================");
    println!("Profiling started. Press Ctrl+C to stop.");
    println!("========================================\n");

    // Poll for events - just keep polling until error
    loop {
        if let Err(e) = ringbuf.poll(Duration::from_millis(100)) {
            // Any error breaks the loop (including Ctrl+C)
            eprintln!("\nStopping: {}", e);
            break;
        }
    }

    println!("Done.");
    Ok(())
}
