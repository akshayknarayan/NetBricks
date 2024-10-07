extern crate e2d2;
extern crate fnv;
extern crate getopts;
extern crate rand;
extern crate time;
use self::nf::*;
use e2d2::allocators::CacheAligned;
use e2d2::config::*;
use e2d2::interface::*;
use e2d2::operators::*;
use e2d2::scheduler::*;
use std::env;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
mod nf;

const CONVERSION_FACTOR: f64 = 1000000000.;

fn test<S: Scheduler + Sized>(ports: Vec<CacheAligned<PortQueue>>, sched: &mut S, delay_arg: u64) {
    for port in &ports {
        println!(
            "Receiving port {} rxq {} txq {} w/ delay {}",
            port.port.mac_address(),
            port.rxq(),
            port.txq(),
            delay_arg
        );
    }

    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| delay(ReceiveBatch::new(port.clone()), delay_arg).send(port.clone()))
        .collect();
    println!("Running {} pipelines", pipelines.len());
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}

fn main() {
    let mut opts = basic_opts();
    opts.optopt("d", "delay", "Delay cycles", "cycles");

    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string()),
    };
    let configuration = read_matches(&matches, &opts);

    let delay_arg = matches
        .opt_str("d")
        .unwrap_or_else(|| String::from("100"))
        .parse()
        .expect("Could not parse delay");

    match initialize_system(&configuration) {
        Ok(mut context) => {
            context.start_schedulers();

            let delay: u64 = delay_arg;
            context.add_pipeline_to_run(Arc::new(move |p, s: &mut StandaloneScheduler| test(p, s, delay)));
            context.execute();

            let mut pkts_so_far = (0, 0);
            let mut last_printed = Instant::now();
            const MAX_PRINT_INTERVAL: Duration = Duration::from_secs(30);
            const PRINT_DELAY: Duration = Duration::from_secs(15);
            const RUN_TIME: Duration = Duration::from_secs(60);
            let sleep_time = PRINT_DELAY / 2;
            let mut start = Instant::now();
            let system_boot = start;
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
                } else if (now - system_boot) > RUN_TIME {
                    context.stop();
                    break;
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
