#![cfg(feature = "std")]

mod ascon;
mod present;
mod speck;

use btp::benchmark_host;

fn main() {
    println!("=== Host Benchmark ===\n");
    let _ = benchmark_host();
}
