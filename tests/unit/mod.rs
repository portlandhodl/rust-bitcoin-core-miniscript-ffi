//! Unit tests for miniscript FFI
//!
//! This module organizes tests into logical categories matching Bitcoin Core's test structure.

pub mod common;
pub mod complex_miniscripts;
pub mod descriptor_basic;
pub mod descriptor_bip32;
pub mod descriptor_complex;
pub mod descriptor_decode_test;
pub mod descriptor_parsing;
pub mod descriptor_timelocks;
pub mod descriptor_validation;
pub mod descriptor_wrappers;
pub mod edge_cases;
pub mod resource_limits;
pub mod satisfaction_tests;
pub mod tapscript_tests;
pub mod validity_tests;
