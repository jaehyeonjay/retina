use retina_core::config::load_config;
use retina_core::subscription::DnsTransaction;
use retina_core::Runtime;
use retina_filtergen::filter;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use anyhow::Result;
use clap::Parser;

use std::net::{IpAddr, Ipv4Addr};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hasher, Hash};

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "dns_censored.jsonl"
    )]
    outfile: PathBuf,
}

fn fake_src_addr(src: IpAddr) -> IpAddr {
    let mut s = DefaultHasher::new();
    src.hash(&mut s);
    let hash64 = s.finish();
    let hash32 = hash64 as u32;
    let one = (hash32 >> 24) as u8;
    let two = (hash32 >> 16) as u8;
    let three = (hash32 >> 8) as u8;
    let four = hash32 as u8;
    let result = IpAddr::V4(Ipv4Addr::new(one, two, three, four));
    return result;
}

#[filter("dns and ipv4.addr != 171.67.70.0/24")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    // Use `BufWriter` to improve the speed of repeated write calls to the same file.
    let file = Mutex::new(BufWriter::new(File::create(&args.outfile)?));
    let cnt = AtomicUsize::new(0);

    let disallowed = vec!["171.64.1.234".parse().unwrap(), "171.67.1.234".parse().unwrap(),
                          "171.66.2.21".parse().unwrap(), "8.8.8.8".parse().unwrap(),
                          "1.1.1.1".parse().unwrap(), "8.8.4.4".parse().unwrap(),
                          "171.67.68.19".parse().unwrap(), "208.67.220.220".parse().unwrap(),
                          "192.33.14.30".parse().unwrap(), "192.42.93.30".parse().unwrap(),
                          "192.5.6.30".parse().unwrap(), "192.12.94.30".parse().unwrap(),
                          "192.48.79.30".parse().unwrap(), "208.67.220.123".parse().unwrap(),
                          "171.67.64.53".parse().unwrap(), "208.67.222.222".parse().unwrap(),
                          "192.54.112.30".parse().unwrap(), "192.35.51.30".parse().unwrap(),
                          "192.41.162.30".parse().unwrap(), "192.26.92.30".parse().unwrap(),
                          "192.31.80.30".parse().unwrap(), "171.64.7.55".parse().unwrap(),
                          "192.43.172.30".parse().unwrap(), "192.52.178.30".parse().unwrap(),
                          "192.55.83.30".parse().unwrap(), "171.67.68.25".parse().unwrap(),
                          "171.67.68.26".parse().unwrap(), "171.64.7.177".parse().unwrap(),
                          "171.64.7.77".parse().unwrap()];

    let callback = |mut dns: DnsTransaction| {
        if disallowed.contains(&(dns.client().ip())) || disallowed.contains(&(dns.server().ip())) {
            return;
        }
        if dns.client().is_ipv6() || dns.server().is_ipv6() {
            return;
        }
        dns.five_tuple.orig.set_ip(fake_src_addr(dns.client().ip()));
        if let Ok(serialized) = serde_json::to_string(&dns) {
            let mut wtr = file.lock().unwrap();
            wtr.write_all(serialized.as_bytes()).unwrap();
            wtr.write_all(b"\n").unwrap();
            cnt.fetch_add(1, Ordering::Relaxed);
        }
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();

    let mut wtr = file.lock().unwrap();
    wtr.flush()?;
    println!(
        "Done. Logged {:?} DNS transactions to {:?}",
        cnt, &args.outfile
    );
    Ok(())
}
