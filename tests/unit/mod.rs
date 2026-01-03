//! Unit tests for miniscript FFI
//!
//! This module organizes tests into logical categories matching Bitcoin Core's test structure.

pub mod common;
pub mod complex_miniscripts;
pub mod descriptor_basic;
pub mod descriptor_bip32;
pub mod descriptor_decode_test;
pub mod edge_cases;
pub mod resource_limits;
pub mod satisfaction_tests;
pub mod tapscript_tests;
pub mod validity_tests;
