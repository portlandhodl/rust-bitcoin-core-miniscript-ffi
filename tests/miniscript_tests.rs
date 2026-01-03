//! Miniscript tests ported from Bitcoin Core's `miniscript_tests.cpp`
//!
//! This file contains tests that verify the miniscript implementation
//! matches Bitcoin Core's behavior.
//!
//! Tests are organized into modules for better maintainability.

mod unit;

// Re-export test modules for easy access
pub use unit::*;
