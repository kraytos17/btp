#![cfg(feature = "embedded")]
#![no_std]
#![no_main]

extern crate panic_halt;

use core::fmt::Write;
use core::ptr::addr_of;
use panic_halt as _;
use rp_pico::entry;
use rp_pico::hal::uart::{DataBits, StopBits, UartConfig};
use rp_pico::hal::{self, Timer, pac};
use rp2040_hal::Clock;
use rp2040_hal::fugit::RateExtU32;

mod ascon;
mod benchmark;
mod present;
mod speck;

#[entry]
fn main() -> ! {
    let mut pac = pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let clocks = hal::clocks::init_clocks_and_plls(
        rp_pico::XOSC_CRYSTAL_FREQ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .ok()
    .unwrap();

    let sio = hal::Sio::new(pac.SIO);
    let mut timer = Timer::new(pac.TIMER, &mut pac.RESETS, &clocks);
    let pins = rp_pico::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    let uart_pins = (
        pins.gpio0.into_function::<hal::gpio::FunctionUart>(),
        pins.gpio1.into_function::<hal::gpio::FunctionUart>(),
    );

    let mut uart = hal::uart::UartPeripheral::new(pac.UART0, uart_pins, &mut pac.RESETS)
        .enable(
            UartConfig::new(115_200_u32.Hz(), DataBits::Eight, None, StopBits::One),
            clocks.peripheral_clock.freq(),
        )
        .unwrap();

    writeln!(uart, "\r\n=== BTP Crypto Benchmark ===\r\n").ok();
    writeln!(uart, "Running tests and benchmarks...\r\n").ok();

    benchmark::run_all(&mut timer);

    unsafe {
        let tests_passed = *addr_of!(benchmark::TESTS_PASSED);
        let present_80_cycles = *addr_of!(benchmark::PRESENT_80_CYCLES);
        let present_80_cpb = *addr_of!(benchmark::PRESENT_80_CPB);
        let present_128_cycles = *addr_of!(benchmark::PRESENT_128_CYCLES);
        let present_128_cpb = *addr_of!(benchmark::PRESENT_128_CPB);
        let speck_64_cycles = *addr_of!(benchmark::SPECK_64_CYCLES);
        let speck_64_cpb = *addr_of!(benchmark::SPECK_64_CPB);
        let speck_128_cycles = *addr_of!(benchmark::SPECK_128_CYCLES);
        let speck_128_cpb = *addr_of!(benchmark::SPECK_128_CPB);
        let ascon_cycles = *addr_of!(benchmark::ASCON_CYCLES);
        let ascon_cpb = *addr_of!(benchmark::ASCON_CPB);
        let ascon_init = *addr_of!(benchmark::ASCON_INIT_CYCLES);
        let ascon_absorb = *addr_of!(benchmark::ASCON_ABSORB_CYCLES);
        let ascon_encrypt = *addr_of!(benchmark::ASCON_ENCRYPT_CYCLES);
        let ascon_finalize = *addr_of!(benchmark::ASCON_FINALIZE_CYCLES);
        let present_ecb = *addr_of!(benchmark::modes::PRESENT_ECB_CPB);
        let present_cbc = *addr_of!(benchmark::modes::PRESENT_CBC_CPB);
        let speck_ecb = *addr_of!(benchmark::modes::SPECK_ECB_CPB);
        let speck_cbc = *addr_of!(benchmark::modes::SPECK_CBC_CPB);
        let speck_ctr = *addr_of!(benchmark::modes::SPECK_CTR_CPB);

        writeln!(uart, "\r\n=== Results ===\r\n").ok();
        writeln!(uart, "Tests passed: {tests_passed}\r\n").ok();
        writeln!(uart, "\r\n").ok();
        writeln!(uart, "Block cipher benchmarks:\r\n").ok();
        writeln!(
            uart,
            "  PRESENT-80:   {} cycles, {} cpb\r\n",
            present_80_cycles, present_80_cpb
        )
        .ok();
        writeln!(
            uart,
            "  PRESENT-128: {} cycles, {} cpb\r\n",
            present_128_cycles, present_128_cpb
        )
        .ok();
        writeln!(
            uart,
            "  SPECK-64/96: {} cycles, {} cpb\r\n",
            speck_64_cycles, speck_64_cpb
        )
        .ok();
        writeln!(
            uart,
            "  SPECK-64/128: {} cycles, {} cpb\r\n",
            speck_128_cycles, speck_128_cpb
        )
        .ok();
        writeln!(
            uart,
            "  ASCON-128:   {} cycles, {} cpb\r\n",
            ascon_cycles, ascon_cpb
        )
        .ok();
        writeln!(uart, "\r\n").ok();
        writeln!(uart, "ASCON phase breakdown (cycles):\r\n").ok();
        writeln!(uart, "  Init:     {ascon_init}\r\n").ok();
        writeln!(uart, "  Absorb:   {ascon_absorb}\r\n").ok();
        writeln!(uart, "  Encrypt:  {ascon_encrypt}\r\n").ok();
        writeln!(uart, "  Finalize: {ascon_finalize}\r\n").ok();
        writeln!(uart, "\r\n").ok();
        writeln!(
            uart,
            "Mode benchmarks (64-byte block, cycles per byte):\r\n"
        )
        .ok();
        writeln!(uart, "  PRESENT ECB: {present_ecb} cpb\r\n").ok();
        writeln!(uart, "  PRESENT CBC: {present_cbc} cpb\r\n").ok();
        writeln!(uart, "  SPECK ECB:   {speck_ecb} cpb\r\n").ok();
        writeln!(uart, "  SPECK CBC:   {speck_cbc} cpb\r\n").ok();
        writeln!(uart, "  SPECK CTR:   {speck_ctr} cpb\r\n").ok();
        writeln!(uart, "\r\n").ok();
        writeln!(uart, "=== Done ===\r\n").ok();
    }

    loop {
        cortex_m::asm::wfi();
    }
}
