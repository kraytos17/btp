#![cfg(feature = "std")]

#[test]
fn test_all_ciphers() {
    btp::run_all_tests();
}

#[test]
fn benchmark_host() {
    btp::benchmark_host();
}
