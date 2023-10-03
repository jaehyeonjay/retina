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

use std::net::IpAddr;

extern crate rand;
extern crate ipcrypt;

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
        default_value = "out/dns2.jsonl"
    )]
    outfile: PathBuf,
}

fn encrypt_ip(ip: IpAddr, key: &[u8; 16]) -> Result<IpAddr> {
    match ip {
        IpAddr::V4(ipv4) => {
            let ipv4_enc = ipcrypt::encrypt(ipv4, key);
            Ok(IpAddr::V4(ipv4_enc))
        }
        IpAddr::V6(_) => todo!()
    }
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
                          "171.67.68.19".parse().unwrap(),
                          "192.33.14.30".parse().unwrap(), "192.42.93.30".parse().unwrap(),
                          "192.5.6.30".parse().unwrap(), "192.12.94.30".parse().unwrap(),
                          "192.48.79.30".parse().unwrap(), 
                          "171.67.64.53".parse().unwrap(),
                          "192.54.112.30".parse().unwrap(), "192.35.51.30".parse().unwrap(),
                          "192.41.162.30".parse().unwrap(), "192.26.92.30".parse().unwrap(),
                          "192.31.80.30".parse().unwrap(),
                          "192.43.172.30".parse().unwrap(), "192.52.178.30".parse().unwrap(),
                          "192.55.83.30".parse().unwrap(), "171.67.68.25".parse().unwrap(),
                          "171.67.68.26".parse().unwrap(), "198.41.0.4".parse().unwrap(), 
                          "199.9.14.201".parse().unwrap(), "192.33.4.12".parse().unwrap(), 
                          "199.7.91.13".parse().unwrap(), "192.203.230.10".parse().unwrap(), 
                          "192.5.5.241".parse().unwrap(), "192.112.36.4".parse().unwrap(), 
                          "198.97.190.53".parse().unwrap(), "192.36.148.17".parse().unwrap(), 
                          "192.58.128.30".parse().unwrap(), "193.0.14.129".parse().unwrap(), 
                          "199.7.83.42".parse().unwrap(), "202.12.27.33".parse().unwrap()];
    let key: [u8; 16] = rand::random();

    let callback = |mut dns: DnsTransaction| {
        if disallowed.contains(&(dns.client().ip())) || disallowed.contains(&(dns.server().ip())) {
            return;
        }
        if dns.client().is_ipv6() || dns.server().is_ipv6() {
            return;
        }
        let src_addr_enc = encrypt_ip(dns.client().ip(), &key).expect("Should not log ipv6");
        dns.five_tuple.orig.set_ip(src_addr_enc);
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
