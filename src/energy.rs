//! Energy estimation for RP2040 (Cortex-M0+ @ 133 MHz, 3.3V).
//!
//! Model: Energy (J) = Cycles × Voltage × Current / Frequency
//! Based on ARM Cortex-M0+ specifications and RP2040 datasheet.
/// Power configuration for RP2040.
pub struct PowerConfig {
    pub voltage_v: f64,
    pub current_ma: f64,
    pub frequency_hz: u64,
}

impl Default for PowerConfig {
    fn default() -> Self {
        Self {
            voltage_v: 3.3,
            current_ma: 3.5,
            frequency_hz: 133_000_000,
        }
    }
}

impl PowerConfig {
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn cycles_to_nanojoules(&self, cycles: u64) -> f64 {
        let cycles_f = cycles as f64;
        let freq_f = self.frequency_hz as f64;
        let energy_j = cycles_f * self.voltage_v * (self.current_ma / 1000.0) / freq_f;
        energy_j * 1e9
    }

    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn ns_to_nanojoules(&self, ns: u64) -> f64 {
        let ns_f = ns as f64;
        let freq_f = self.frequency_hz as f64;
        let cycles = ns_f * freq_f / 1e9;
        self.cycles_to_nanojoules(cycles as u64)
    }
}

pub const POWER_CONFIG: PowerConfig = PowerConfig {
    voltage_v: 3.3,
    current_ma: 3.5,
    frequency_hz: 133_000_000,
};
