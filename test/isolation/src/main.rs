//! Can we break NetBricks isolation?
//!
//! # Paper's isolation definition
//!
//! From the [paper](https://www.usenix.org/system/files/conference/osdi16/osdi16-panda.pdf):
//!
//! ## Memory Isolation
//!
//! Safe languages and runtime environments provide four guarantees that are crucial for
//! providing memory isolation in software: (a) they disallow pointer arithmetic, and require
//! that any references acquired by a code is either generated due to an allocation or a
//! function call; (b) they check bounds on array accesses, thus preventing stray memory
//! accesses due to buffer overﬂows (and underﬂows); (c) they disallow accesses to null object,
//! thus preventing applications from using undeﬁned behavior to access memory that should be
//! isolated; and (d) they ensure that all type casts are safe (and between compatible objects).
//!
//! ## Packet Isolation
//!
//! NFV requires more than just memory isolation; NFV must preserve the semantics of physical
//! networks in the sense that an NF cannot modify a packet once it has been sent (we call
//! this packet isolation).
//!
//! This is normally implemented by copying packets as they are passed from NF to NF, but this
//! copying incurs a high performance overhead in packet-processing applications. We thus turn
//! to unique types [13] to eliminate the requirement that packets be copied, while preserving
//! packet isolation.
//!
//! # Approach
//!
//! Memory isolation is not interesting to break - we can just do it via `unsafe`. And NetBricks is
//! intended to be used with deny(unsafe) inside NF code. But can we break packet isolation in safe
//! Rust?

use e2d2::common::*;
use e2d2::config::{basic_opts, read_matches};
use e2d2::headers::*;
use e2d2::interface::*;
use e2d2::operators::*;
use e2d2::scheduler::*;
use std::env;
use std::fmt::Display;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[inline]
pub fn isotest<T: 'static + Batch<Header = NullHeader, Metadata = EmptyMetadata>>(parent: T) -> CompositionBatch {
    parent
        .metadata(Box::new(move |_pkt| Box::new(false)))
        .filter(Box::new(move |pkt: &Packet<_, _>| {
            let m = pkt.read_metadata();
            **m
        }))
        .compose()
}

fn test<T, S>(ports: Vec<T>, sched: &mut S)
where
    T: PacketRx + PacketTx + Display + Clone + 'static,
    S: Scheduler + Sized,
{
    println!("Receiving started");
    for port in &ports {
        println!("Receiving port {} on chain", port);
    }

    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| isotest(ReceiveBatch::new(port.clone())).send(port.clone()))
        .collect();
    println!("Running {} pipelines", pipelines.len());
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}

fn main() {
    let opts = basic_opts();
    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string()),
    };
    let configuration = read_matches(&matches, &opts);

    match initialize_system(&configuration) {
        Ok(mut context) => {
            context.start_schedulers();
            context.add_pipeline_to_run(Arc::new(move |p, s: &mut StandaloneScheduler| test(p, s)));
            context.execute();

            let mut pkts_so_far = (0, 0);
            let mut last_printed = Instant::now();
            const MAX_PRINT_INTERVAL: Duration = Duration::from_secs(30);
            const PRINT_DELAY: Duration = Duration::from_secs(15);
            let sleep_time = PRINT_DELAY / 2;
            let mut start = Instant::now();
            println!("0 OVERALL RX 0.00 TX 0.00 CYCLE_PER_DELAY 0 0 0");
            loop {
                thread::sleep(sleep_time); // Sleep for a bit
                let now = Instant::now();
                if (now - start) > PRINT_DELAY {
                    let mut rx = 0;
                    let mut tx = 0;
                    for port in context.ports.values() {
                        for q in 0..port.rxqs() {
                            let (rp, tp) = port.stats(q);
                            rx += rp;
                            tx += tp;
                        }
                    }
                    let pkts = (rx, tx);
                    let rx_pkts = pkts.0 - pkts_so_far.0;
                    if rx_pkts > 0 || (now - last_printed) > MAX_PRINT_INTERVAL {
                        println!(
                            "{:?} OVERALL RX {:.2} TX {:.2}",
                            now - start,
                            rx_pkts as f64 / (now - start).as_secs_f64(),
                            (pkts.1 - pkts_so_far.1) as f64 / (now - start).as_secs_f64()
                        );
                        last_printed = now;
                        start = now;
                        pkts_so_far = pkts;
                    }
                }
            }
        }
        Err(ref e) => {
            println!("Error: {}", e);
            if let Some(backtrace) = e.backtrace() {
                println!("Backtrace: {:?}", backtrace);
            }
            process::exit(1);
        }
    }
}
