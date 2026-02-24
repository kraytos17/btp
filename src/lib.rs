#![cfg_attr(not(feature = "std"), no_std)]

pub mod ascon;
pub mod present;
pub mod speck;

#[cfg(not(feature = "std"))]
pub mod benchmark;

#[cfg(feature = "std")]
pub mod host_tests {
    use crate::ascon::{AsconAead, AsconHash};
    use crate::present::{Present, modes as present_modes};
    use crate::speck::{Speck64, modes as speck_modes};
    use serde::Serialize;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HEAP_ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
    static HEAP_ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
    static HEAP_DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

    struct TrackingAllocator;

    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            HEAP_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            HEAP_ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            HEAP_DEALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            unsafe { System.dealloc(_ptr, _layout) }
        }
    }

    #[global_allocator]
    static A: TrackingAllocator = TrackingAllocator;

    #[derive(Serialize, Clone)]
    pub struct MemoryMetrics {
        pub heap_allocations: usize,
        pub heap_bytes_allocated: usize,
        pub heap_deallocations: usize,
        pub stack_estimate_bytes: usize,
        pub static_memory_bytes: usize,
    }

    #[derive(Serialize, Clone)]
    pub struct CipherMemory {
        pub name: String,
        pub heap_allocs: usize,
        pub heap_bytes: usize,
        pub stack_bytes: usize,
    }

    #[derive(Serialize)]
    pub struct BenchmarkResults {
        pub block_ciphers: BlockCipherResults,
        pub modes: ModeResults,
        pub ascon_phases: AsconPhaseResults,
        pub scaling: ScalingResults,
        pub memory: MemoryResults,
    }

    #[derive(Serialize)]
    pub struct MemoryResults {
        pub total: MemoryMetrics,
        pub per_cipher: Vec<CipherMemory>,
        pub section_sizes: SectionSizes,
    }

    #[derive(Serialize, Clone)]
    pub struct SectionSizes {
        pub text: usize,
        pub data: usize,
        pub bss: usize,
        pub total: usize,
    }

    #[derive(Serialize)]
    pub struct BlockCipherResults {
        pub present_80: CipherMetric,
        pub present_128: CipherMetric,
        pub speck64_96: CipherMetric,
        pub speck64_128: CipherMetric,
        pub ascon_128: CipherMetric,
    }

    #[derive(Serialize)]
    pub struct CipherMetric {
        pub ns_per_block: u64,
        pub cpb: f64,
        pub mbps: f64,
    }

    #[derive(Serialize)]
    pub struct ModeResults {
        pub present_ecb: CipherMetric,
        pub present_cbc: CipherMetric,
        pub speck_ecb: CipherMetric,
        pub speck_cbc: CipherMetric,
        pub speck_ctr: CipherMetric,
    }

    #[derive(Serialize)]
    pub struct AsconPhaseResults {
        pub init: u64,
        pub absorb: u64,
        pub encrypt: u64,
        pub finalize: u64,
    }

    #[derive(Serialize)]
    pub struct ScalingResults {
        pub present_80: Vec<(String, u64)>,
        pub present_128: Vec<(String, u64)>,
        pub speck64_128: Vec<(String, u64)>,
        pub ascon_128: Vec<(String, u64)>,
    }

    fn reset_memory_stats() {
        HEAP_ALLOC_COUNT.store(0, Ordering::Relaxed);
        HEAP_ALLOC_BYTES.store(0, Ordering::Relaxed);
        HEAP_DEALLOC_COUNT.store(0, Ordering::Relaxed);
    }

    fn get_memory_stats() -> (usize, usize, usize) {
        (
            HEAP_ALLOC_COUNT.load(Ordering::Relaxed),
            HEAP_ALLOC_BYTES.load(Ordering::Relaxed),
            HEAP_DEALLOC_COUNT.load(Ordering::Relaxed),
        )
    }

    fn get_section_sizes() -> SectionSizes {
        use std::process::Command;

        let output = Command::new("size")
            .arg("--format=sysv")
            .arg("--")
            .arg(std::env::current_exe().unwrap_or_default())
            .output();

        if let Ok(output) = output {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("btp") || line.contains("host") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        return SectionSizes {
                            text: parts[1].parse().unwrap_or(0),
                            data: parts[2].parse().unwrap_or(0),
                            bss: parts[3].parse().unwrap_or(0),
                            total: parts[4].parse().unwrap_or(0),
                        };
                    }
                }
            }
        }

        SectionSizes {
            text: 0,
            data: 0,
            bss: 0,
            total: 0,
        }
    }

    fn ns_to_mbps(ns: u64, block_size: usize) -> f64 {
        if ns == 0 {
            return 0.0;
        }
        let ns_per_byte = ns as f64 / block_size as f64;
        1000.0 / ns_per_byte
    }

    fn ns_to_cpb(ns: u64, block_size: usize) -> f64 {
        ns as f64 / block_size as f64
    }

    pub fn run_all_tests() {
        println!("=== Running Host Tests ===\n");

        test_present();
        test_speck();
        test_ascon();

        println!("\n=== All Tests Passed ===");
    }

    fn test_present() {
        println!("Testing PRESENT cipher...");

        let key80 = [0x00u8; 10];
        let cipher = Present::new(&key80).unwrap();
        let plaintext = [0x00u8; 8];
        let ciphertext = cipher.encrypt_block(plaintext);
        let decrypted = cipher.decrypt_block(ciphertext);
        assert_eq!(plaintext, decrypted, "PRESENT-80 encrypt/decrypt mismatch");
        println!("  PRESENT-80: OK");

        let key128 = [0x00u8; 16];
        let cipher = Present::new(&key128).unwrap();
        let ciphertext = cipher.encrypt_block(plaintext);
        let decrypted = cipher.decrypt_block(ciphertext);
        assert_eq!(plaintext, decrypted, "PRESENT-128 encrypt/decrypt mismatch");
        println!("  PRESENT-128: OK");

        assert!(
            crate::present::test_vectors::run_tests(),
            "PRESENT test vectors failed"
        );
        println!("  Test vectors: OK");
    }

    fn test_speck() {
        println!("\nTesting SPECK cipher...");

        let key96 = [0x0302_0100u32, 0x0b0a_0908, 0x1312_1110];
        let cipher = Speck64::new(&key96).unwrap();
        let plaintext = [0x7461_4620u32, 0x736e_6165];
        let ciphertext = cipher.encrypt_block(plaintext);
        let decrypted = cipher.decrypt_block(ciphertext);
        assert_eq!(plaintext, decrypted, "SPECK64/96 encrypt/decrypt mismatch");
        println!("  SPECK64/96: OK");

        let key128 = [0x0302_0100u32, 0x0b0a_0908, 0x1312_1110, 0x1b1a_1918];
        let cipher = Speck64::new(&key128[..3]).unwrap();
        let ciphertext = cipher.encrypt_block(plaintext);
        let decrypted = cipher.decrypt_block(ciphertext);
        assert_eq!(plaintext, decrypted, "SPECK64/128 encrypt/decrypt mismatch");
        println!("  SPECK64/128: OK");

        assert!(
            crate::speck::test_vectors::run_tests(),
            "SPECK test vectors failed"
        );
        println!("  Test vectors: OK");
    }

    fn test_ascon() {
        println!("\nTesting ASCON AEAD...");

        let key = [0x00u8; 16];
        let nonce = [0x00u8; 16];
        let plaintext = [0x00u8; 16];
        let ad = [0x00u8; 8];

        let mut cipher = AsconAead::new(&key, &nonce);
        cipher.absorb_ad(&ad);
        let mut ciphertext = [0u8; 16];
        cipher.encrypt_in_place(&plaintext, &mut ciphertext);
        let tag = cipher.finalize(&key);

        let ct_with_tag = {
            let mut arr = [0u8; 32];
            arr[..16].copy_from_slice(&ciphertext);
            arr[16..].copy_from_slice(&tag);
            arr
        };
        let decrypted = crate::ascon::decrypt_aead(&key, &nonce, &ct_with_tag, &ad);
        assert!(decrypted.is_some(), "ASCON decryption failed");
        assert_eq!(
            decrypted.unwrap()[..plaintext.len()],
            plaintext,
            "ASCON plaintext mismatch"
        );
        println!("  ASCON-128 encrypt/decrypt: OK");

        let mut hasher = AsconHash::new();
        hasher.absorb(b"test message");
        let hash = hasher.finalize();
        assert_ne!(hash, [0u8; 32], "ASCON hash should not be all zeros");
        println!("  ASCON-Hash: OK");

        assert!(
            crate::ascon::test_vectors::run_tests(),
            "ASCON test vectors failed"
        );
        println!("  Test vectors: OK");
    }

    pub fn benchmark_host() -> BenchmarkResults {
        use std::time::Instant;

        const ITERATIONS: u64 = 100_000;
        const BLOCK_SIZE: usize = 8;
        const AEAD_SIZE: usize = 16;

        let present_80_ns = {
            let cipher = Present::new(&[0u8; 10]).unwrap();
            let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
            let start = Instant::now();
            for _ in 0..ITERATIONS {
                let _ = cipher.encrypt_block(pt);
            }
            start.elapsed().as_nanos() as u64 / ITERATIONS
        };

        let present_128_ns = {
            let cipher = Present::new(&[0u8; 16]).unwrap();
            let pt = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
            let start = Instant::now();
            for _ in 0..ITERATIONS {
                let _ = cipher.encrypt_block(pt);
            }
            start.elapsed().as_nanos() as u64 / ITERATIONS
        };

        let speck64_96_ns = {
            let cipher = Speck64::new(&[0x0302_0100u32, 0x0b0a_0908, 0x1312_1110]).unwrap();
            let pt = [0x7461_4620u32, 0x736e_6165];
            let start = Instant::now();
            for _ in 0..ITERATIONS {
                let _ = cipher.encrypt_block(pt);
            }
            start.elapsed().as_nanos() as u64 / ITERATIONS
        };

        let speck64_128_ns = {
            let cipher = Speck64::new(&[0x0302_0100u32, 0x0b0a_0908, 0x1312_1110]).unwrap();
            let pt = [0x7461_4620u32, 0x736e_6165];
            let start = Instant::now();
            for _ in 0..ITERATIONS {
                let _ = cipher.encrypt_block(pt);
            }
            start.elapsed().as_nanos() as u64 / ITERATIONS
        };

        let ascon_128_ns = {
            let key = [0u8; 16];
            let nonce = [0u8; 16];
            let pt = [0u8; 16];
            let ad = [0u8; 8];
            let start = Instant::now();
            for _ in 0..10_000 {
                let _ = crate::ascon::encrypt_aead(&key, &nonce, &pt, &ad);
            }
            start.elapsed().as_nanos() as u64 / 10_000
        };

        let (ascon_init, ascon_absorb, ascon_encrypt, ascon_finalize) = {
            let key = [0u8; 16];
            let nonce = [0u8; 16];
            let pt = [0u8; 16];
            let ad = [0u8; 8];

            let mut init_total = 0u64;
            let mut absorb_total = 0u64;
            let mut encrypt_total = 0u64;
            let mut finalize_total = 0u64;

            for _ in 0..1000 {
                let t0 = Instant::now();
                let mut cipher = AsconAead::new(&key, &nonce);
                let t1 = Instant::now();
                init_total += t1.duration_since(t0).as_nanos() as u64;

                let t2 = Instant::now();
                cipher.absorb_ad(&ad);
                let t3 = Instant::now();
                absorb_total += t3.duration_since(t2).as_nanos() as u64;

                let mut ct = [0u8; 16];
                let t4 = Instant::now();
                cipher.encrypt_in_place(&pt, &mut ct);
                let t5 = Instant::now();
                encrypt_total += t5.duration_since(t4).as_nanos() as u64;

                let t6 = Instant::now();
                let _tag = cipher.finalize(&key);
                let t7 = Instant::now();
                finalize_total += t7.duration_since(t6).as_nanos() as u64;
            }

            (
                init_total / 1000,
                absorb_total / 1000,
                encrypt_total / 1000,
                finalize_total / 1000,
            )
        };

        const MODE_ITERS: u64 = 10_000;
        const MODE_BLOCK_SIZE: usize = 64;

        let present_ecb_ns = {
            let cipher = Present::new(&[0u8; 10]).unwrap();
            let mut pt = [0u8; 64];
            let mut ct = [0u8; 64];
            for (i, b) in pt.iter_mut().enumerate() {
                *b = i as u8;
            }
            let start = Instant::now();
            for _ in 0..MODE_ITERS {
                present_modes::encrypt_ecb(&cipher, &pt, &mut ct);
            }
            start.elapsed().as_nanos() as u64 / MODE_ITERS
        };

        let present_cbc_ns = {
            let cipher = Present::new(&[0u8; 10]).unwrap();
            let iv = [0u8; 8];
            let mut pt = [0u8; 64];
            let mut ct = [0u8; 64];
            for (i, b) in pt.iter_mut().enumerate() {
                *b = i as u8;
            }
            let start = Instant::now();
            for _ in 0..MODE_ITERS {
                present_modes::encrypt_cbc(&cipher, &pt, &mut ct, iv);
            }
            start.elapsed().as_nanos() as u64 / MODE_ITERS
        };

        let speck_ecb_ns = {
            let cipher = Speck64::new(&[0x0302_0100u32, 0x0b0a_0908, 0x1312_1110]).unwrap();
            let mut pt = [0u8; 64];
            let mut ct = [0u8; 64];
            for (i, b) in pt.iter_mut().enumerate() {
                *b = i as u8;
            }
            let start = Instant::now();
            for _ in 0..MODE_ITERS {
                speck_modes::encrypt_ecb(&cipher, &pt, &mut ct);
            }
            start.elapsed().as_nanos() as u64 / MODE_ITERS
        };

        let speck_cbc_ns = {
            let cipher = Speck64::new(&[0x0302_0100u32, 0x0b0a_0908, 0x1312_1110]).unwrap();
            let iv = [0u8; 8];
            let mut pt = [0u8; 64];
            let mut ct = [0u8; 64];
            for (i, b) in pt.iter_mut().enumerate() {
                *b = i as u8;
            }
            let start = Instant::now();
            for _ in 0..MODE_ITERS {
                speck_modes::encrypt_cbc(&cipher, &pt, &mut ct, iv);
            }
            start.elapsed().as_nanos() as u64 / MODE_ITERS
        };

        let speck_ctr_ns = {
            let cipher = Speck64::new(&[0x0302_0100u32, 0x0b0a_0908, 0x1312_1110]).unwrap();
            let nonce = [0u8; 8];
            let mut pt = [0u8; 64];
            let mut ct = [0u8; 64];
            for (i, b) in pt.iter_mut().enumerate() {
                *b = i as u8;
            }
            let start = Instant::now();
            for _ in 0..MODE_ITERS {
                speck_modes::encrypt_ctr(&cipher, &pt, &mut ct, nonce);
            }
            start.elapsed().as_nanos() as u64 / MODE_ITERS
        };

        let mut scaling_present_80 = Vec::new();
        let mut scaling_present_128 = Vec::new();
        let mut scaling_speck64_128 = Vec::new();
        let mut scaling_ascon_128 = Vec::new();

        for size in [8, 16, 32, 64, 128, 256] {
            let cipher = Present::new(&[0u8; 10]).unwrap();
            let mut pt = vec![0u8; size];
            let mut ct = vec![0u8; size];
            for (i, b) in pt.iter_mut().enumerate() {
                *b = i as u8;
            }
            let start = Instant::now();
            for _ in 0..5_000 {
                present_modes::encrypt_ecb(&cipher, &pt, &mut ct);
            }
            let ns = start.elapsed().as_nanos() as u64 / 5_000;
            scaling_present_80.push((size.to_string(), ns));

            let cipher = Present::new(&[0u8; 16]).unwrap();
            let start = Instant::now();
            for _ in 0..5_000 {
                present_modes::encrypt_ecb(&cipher, &pt, &mut ct);
            }
            let ns = start.elapsed().as_nanos() as u64 / 5_000;
            scaling_present_128.push((size.to_string(), ns));

            let cipher = Speck64::new(&[0x0302_0100u32, 0x0b0a_0908, 0x1312_1110]).unwrap();
            let start = Instant::now();
            for _ in 0..5_000 {
                speck_modes::encrypt_ecb(&cipher, &pt, &mut ct);
            }
            let ns = start.elapsed().as_nanos() as u64 / 5_000;
            scaling_speck64_128.push((size.to_string(), ns));

            let key = [0u8; 16];
            let nonce = [0u8; 16];
            let ad = [0u8; 8];
            let mut output = vec![0u8; size + 16];
            let start = Instant::now();
            for _ in 0..1_000 {
                let _ = crate::ascon::encrypt_aead_varlen(&key, &nonce, &pt, &ad, &mut output);
            }
            let ns = start.elapsed().as_nanos() as u64 / 1_000;
            scaling_ascon_128.push((size.to_string(), ns));
        }

        let results = BenchmarkResults {
            block_ciphers: BlockCipherResults {
                present_80: CipherMetric {
                    ns_per_block: present_80_ns,
                    cpb: ns_to_cpb(present_80_ns, BLOCK_SIZE),
                    mbps: ns_to_mbps(present_80_ns, BLOCK_SIZE),
                },
                present_128: CipherMetric {
                    ns_per_block: present_128_ns,
                    cpb: ns_to_cpb(present_128_ns, BLOCK_SIZE),
                    mbps: ns_to_mbps(present_128_ns, BLOCK_SIZE),
                },
                speck64_96: CipherMetric {
                    ns_per_block: speck64_96_ns,
                    cpb: ns_to_cpb(speck64_96_ns, BLOCK_SIZE),
                    mbps: ns_to_mbps(speck64_96_ns, BLOCK_SIZE),
                },
                speck64_128: CipherMetric {
                    ns_per_block: speck64_128_ns,
                    cpb: ns_to_cpb(speck64_128_ns, BLOCK_SIZE),
                    mbps: ns_to_mbps(speck64_128_ns, BLOCK_SIZE),
                },
                ascon_128: CipherMetric {
                    ns_per_block: ascon_128_ns,
                    cpb: ns_to_cpb(ascon_128_ns, AEAD_SIZE),
                    mbps: ns_to_mbps(ascon_128_ns, AEAD_SIZE),
                },
            },
            modes: ModeResults {
                present_ecb: CipherMetric {
                    ns_per_block: present_ecb_ns,
                    cpb: ns_to_cpb(present_ecb_ns, MODE_BLOCK_SIZE),
                    mbps: ns_to_mbps(present_ecb_ns, MODE_BLOCK_SIZE),
                },
                present_cbc: CipherMetric {
                    ns_per_block: present_cbc_ns,
                    cpb: ns_to_cpb(present_cbc_ns, MODE_BLOCK_SIZE),
                    mbps: ns_to_mbps(present_cbc_ns, MODE_BLOCK_SIZE),
                },
                speck_ecb: CipherMetric {
                    ns_per_block: speck_ecb_ns,
                    cpb: ns_to_cpb(speck_ecb_ns, MODE_BLOCK_SIZE),
                    mbps: ns_to_mbps(speck_ecb_ns, MODE_BLOCK_SIZE),
                },
                speck_cbc: CipherMetric {
                    ns_per_block: speck_cbc_ns,
                    cpb: ns_to_cpb(speck_cbc_ns, MODE_BLOCK_SIZE),
                    mbps: ns_to_mbps(speck_cbc_ns, MODE_BLOCK_SIZE),
                },
                speck_ctr: CipherMetric {
                    ns_per_block: speck_ctr_ns,
                    cpb: ns_to_cpb(speck_ctr_ns, MODE_BLOCK_SIZE),
                    mbps: ns_to_mbps(speck_ctr_ns, MODE_BLOCK_SIZE),
                },
            },
            ascon_phases: AsconPhaseResults {
                init: ascon_init,
                absorb: ascon_absorb,
                encrypt: ascon_encrypt,
                finalize: ascon_finalize,
            },
            scaling: ScalingResults {
                present_80: scaling_present_80,
                present_128: scaling_present_128,
                speck64_128: scaling_speck64_128,
                ascon_128: scaling_ascon_128,
            },
            memory: run_memory_benchmark(),
        };

        let json = serde_json::to_string_pretty(&results).unwrap();
        println!("{}", json);

        results
    }

    pub fn run_memory_benchmark() -> MemoryResults {
        reset_memory_stats();

        let mut per_cipher = Vec::new();

        {
            reset_memory_stats();
            let cipher = Present::new(&[0u8; 10]).unwrap();
            let pt = [0u8; 8];
            for _ in 0..1000 {
                let _ = cipher.encrypt_block(pt);
            }
            let (allocs, bytes, _) = get_memory_stats();
            per_cipher.push(CipherMemory {
                name: "PRESENT-80".to_string(),
                heap_allocs: allocs,
                heap_bytes: bytes,
                stack_bytes: std::mem::size_of::<Present>() + std::mem::size_of::<[u8; 8]>(),
            });
        }

        {
            reset_memory_stats();
            let cipher = Present::new(&[0u8; 16]).unwrap();
            let pt = [0u8; 8];
            for _ in 0..1000 {
                let _ = cipher.encrypt_block(pt);
            }
            let (allocs, bytes, _) = get_memory_stats();
            per_cipher.push(CipherMemory {
                name: "PRESENT-128".to_string(),
                heap_allocs: allocs,
                heap_bytes: bytes,
                stack_bytes: std::mem::size_of::<Present>() + std::mem::size_of::<[u8; 8]>(),
            });
        }

        {
            reset_memory_stats();
            let cipher = Speck64::new(&[0x0302_0100u32, 0x0b0a_0908, 0x1312_1110]).unwrap();
            let pt = [0u32; 2];
            for _ in 0..1000 {
                let _ = cipher.encrypt_block(pt);
            }
            let (allocs, bytes, _) = get_memory_stats();
            per_cipher.push(CipherMemory {
                name: "SPECK64/96".to_string(),
                heap_allocs: allocs,
                heap_bytes: bytes,
                stack_bytes: std::mem::size_of::<Speck64>() + std::mem::size_of::<[u32; 2]>(),
            });
        }

        {
            reset_memory_stats();
            let cipher = Speck64::new(&[0x0302_0100u32, 0x0b0a_0908, 0x1312_1110]).unwrap();
            let pt = [0u32; 2];
            for _ in 0..1000 {
                let _ = cipher.encrypt_block(pt);
            }
            let (allocs, bytes, _) = get_memory_stats();
            per_cipher.push(CipherMemory {
                name: "SPECK64/128".to_string(),
                heap_allocs: allocs,
                heap_bytes: bytes,
                stack_bytes: std::mem::size_of::<Speck64>() + std::mem::size_of::<[u32; 2]>(),
            });
        }

        {
            reset_memory_stats();
            let key = [0u8; 16];
            let nonce = [0u8; 16];
            let pt = [0u8; 16];
            let ad = [0u8; 8];
            for _ in 0..1000 {
                let _ = crate::ascon::encrypt_aead(&key, &nonce, &pt, &ad);
            }
            let (allocs, bytes, _) = get_memory_stats();
            per_cipher.push(CipherMemory {
                name: "ASCON-128".to_string(),
                heap_allocs: allocs,
                heap_bytes: bytes,
                stack_bytes: std::mem::size_of::<AsconAead>() * 2 + 32,
            });
        }

        let section_sizes = get_section_sizes();

        let (total_allocs, total_bytes, total_deallocs) = get_memory_stats();

        MemoryResults {
            total: MemoryMetrics {
                heap_allocations: total_allocs,
                heap_bytes_allocated: total_bytes,
                heap_deallocations: total_deallocs,
                stack_estimate_bytes: 0,
                static_memory_bytes: section_sizes.data + section_sizes.bss,
            },
            per_cipher,
            section_sizes,
        }
    }
}

#[cfg(feature = "std")]
pub use host_tests::run_all_tests;

#[cfg(feature = "std")]
pub use host_tests::benchmark_host;
