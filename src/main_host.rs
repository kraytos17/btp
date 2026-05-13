#![cfg(feature = "std")]

mod ascon;
mod present;
mod speck;

fn main() {
    println!("Run 'cargo bench' to benchmark all ciphers with criterion.");
}
