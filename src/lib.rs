#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate alloc;

pub mod ascon;
pub mod present;
pub mod speck;

pub mod energy;

#[cfg(all(not(feature = "std"), feature = "embedded"))]
pub mod benchmark;

#[cfg(feature = "std")]
pub mod stats;
