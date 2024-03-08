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

// Added
use std::net::IpAddr;
extern crate rand;
extern crate ipcrypt;

fn encrypt_ip(ip: IpAddr, key: &[u8; 16]) -> Result<IpAddr> {
    match ip {
        IpAddr::V4(ipv4) => {
            let ipv4_enc = ipcrypt::encrypt(ipv4, key);
            Ok(IpAddr::V4(ipv4_enc))
        }
        IpAddr::V6(_) => todo!()
    }
}

// Define command-line arguments.
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "small_flows.pcap",
        default_value = "dns.jsonl"
    )]
    outfile: PathBuf,
}

#[filter("dns and ipv4")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    // Use `BufWriter` to improve the speed of repeated write calls to the same file.
    let file = Mutex::new(BufWriter::new(File::create(&args.outfile)?));
    let cnt = AtomicUsize::new(0);

    // key for encryption
    let key: [u8; 16] = rand::random();

    let callback = |mut dns: DnsTransaction| {
        // encrypt client IP
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
