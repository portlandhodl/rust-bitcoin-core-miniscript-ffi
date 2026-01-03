//! Basic validity tests for miniscript type rules
//!
//! These tests verify that the miniscript type system correctly validates
//! various fragment combinations according to Bitcoin Core's rules.

use super::common::init_testdata;
use miniscript_core_ffi::{Context, Miniscript};

#[test]
fn test_older_validity() {
    init_testdata();

    // older(1): valid
    let ms = Miniscript::from_str("l:older(1)", Context::Wsh);
    assert!(ms.is_ok(), "older(1) should be valid");

    // older(0): k must be at least 1
    let ms = Miniscript::from_str("l:older(0)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "older(0) should be invalid"
    );

    // older(2147483647): valid
    let ms = Miniscript::from_str("l:older(2147483647)", Context::Wsh);
    assert!(ms.is_ok(), "older(2147483647) should be valid");

    // older(2147483648): k must be below 2^31
    let ms = Miniscript::from_str("l:older(2147483648)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "older(2147483648) should be invalid"
    );
}

#[test]
fn test_after_validity() {
    init_testdata();

    // after(1): valid
    let ms = Miniscript::from_str("u:after(1)", Context::Wsh);
    assert!(ms.is_ok(), "after(1) should be valid");

    // after(0): k must be at least 1
    let ms = Miniscript::from_str("u:after(0)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "after(0) should be invalid"
    );

    // after(2147483647): valid
    let ms = Miniscript::from_str("u:after(2147483647)", Context::Wsh);
    assert!(ms.is_ok(), "after(2147483647) should be valid");

    // after(2147483648): k must be below 2^31
    let ms = Miniscript::from_str("u:after(2147483648)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "after(2147483648) should be invalid"
    );
}

#[test]
fn test_andor_validity() {
    init_testdata();

    // andor(Bdu,B,B): valid
    let ms = Miniscript::from_str("andor(0,1,1)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "andor(0,1,1) should be valid"
    );

    // andor(Wdu,B,B): X must be B
    let ms = Miniscript::from_str("andor(a:0,1,1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "andor(a:0,1,1) should be invalid"
    );

    // andor(Bdu,W,W): Y and Z must be B/V/K
    let ms = Miniscript::from_str("andor(0,a:1,a:1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "andor(0,a:1,a:1) should be invalid"
    );

    // andor(Bu,B,B): X must be d
    let ms = Miniscript::from_str("andor(1,1,1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "andor(1,1,1) should be invalid"
    );

    // andor(Bdu,B,B): valid
    let ms = Miniscript::from_str("andor(n:or_i(0,after(1)),1,1)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "andor with or_i should be valid"
    );

    // andor(Bd,B,B): X must be u
    let ms = Miniscript::from_str("andor(or_i(0,after(1)),1,1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "andor without u wrapper should be invalid"
    );
}

#[test]
fn test_and_v_validity() {
    init_testdata();

    // and_v(V,B): valid
    let ms = Miniscript::from_str("and_v(v:1,1)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_v(v:1,1) should be valid"
    );

    // and_v(V,V): valid
    let ms = Miniscript::from_str("t:and_v(v:1,v:1)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_v(V,V) should be valid"
    );

    // and_v(B,B): X must be V
    let ms = Miniscript::from_str("and_v(1,1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "and_v(1,1) should be invalid"
    );

    // and_v(K,W): Y must be B/V/K
    let ms = Miniscript::from_str("and_v(v:1,a:1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "and_v(v:1,a:1) should be invalid"
    );
}

#[test]
fn test_and_b_validity() {
    init_testdata();

    // and_b(B,W): valid
    let ms = Miniscript::from_str("and_b(1,a:1)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_b(1,a:1) should be valid"
    );

    // and_b(B,B): Y must W
    let ms = Miniscript::from_str("and_b(1,1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "and_b(1,1) should be invalid"
    );

    // and_b(V,W): X must be B
    let ms = Miniscript::from_str("and_b(v:1,a:1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "and_b(v:1,a:1) should be invalid"
    );

    // and_b(W,W): X must be B
    let ms = Miniscript::from_str("and_b(a:1,a:1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "and_b(a:1,a:1) should be invalid"
    );
}

#[test]
fn test_or_b_validity() {
    init_testdata();

    // or_b(Bd,Wd): valid
    let ms = Miniscript::from_str("or_b(0,a:0)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_b(0,a:0) should be valid"
    );

    // or_b(B,Wd): X must be d
    let ms = Miniscript::from_str("or_b(1,a:0)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_b(1,a:0) should be invalid"
    );

    // or_b(Bd,W): Y must be d
    let ms = Miniscript::from_str("or_b(0,a:1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_b(0,a:1) should be invalid"
    );

    // or_b(Bd,Bd): Y must W
    let ms = Miniscript::from_str("or_b(0,0)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_b(0,0) should be invalid"
    );
}

#[test]
fn test_or_c_validity() {
    init_testdata();

    // or_c(Bdu,V): valid
    let ms = Miniscript::from_str("t:or_c(0,v:1)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_c(0,v:1) should be valid"
    );

    // or_c(Wdu,V): X must be B
    let ms = Miniscript::from_str("t:or_c(a:0,v:1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_c(a:0,v:1) should be invalid"
    );

    // or_c(Bu,V): X must be d
    let ms = Miniscript::from_str("t:or_c(1,v:1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_c(1,v:1) should be invalid"
    );

    // or_c(Bdu,B): Y must be V
    let ms = Miniscript::from_str("t:or_c(0,1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_c(0,1) should be invalid"
    );
}

#[test]
fn test_or_d_validity() {
    init_testdata();

    // or_d(Bdu,B): valid
    let ms = Miniscript::from_str("or_d(0,1)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_d(0,1) should be valid"
    );

    // or_d(Wdu,B): X must be B
    let ms = Miniscript::from_str("or_d(a:0,1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_d(a:0,1) should be invalid"
    );

    // or_d(Bu,B): X must be d
    let ms = Miniscript::from_str("or_d(1,1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_d(1,1) should be invalid"
    );

    // or_d(Bdu,V): Y must be B
    let ms = Miniscript::from_str("or_d(0,v:1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_d(0,v:1) should be invalid"
    );
}

#[test]
fn test_or_i_validity() {
    init_testdata();

    // or_i(B,B): valid
    let ms = Miniscript::from_str("or_i(1,1)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_i(1,1) should be valid"
    );

    // or_i(V,V): valid
    let ms = Miniscript::from_str("t:or_i(v:1,v:1)", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_i(V,V) should be valid"
    );

    // or_i(W,W): X and Y must be B/V/K
    let ms = Miniscript::from_str("or_i(a:1,a:1)", Context::Wsh);
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "or_i(a:1,a:1) should be invalid"
    );
}

#[test]
fn test_thresh_validity() {
    init_testdata();

    // thresh with k = 2 (equal to number of subs): valid
    let ms = Miniscript::from_str(
        "thresh(2,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),altv:after(100))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "thresh(2,...) with 2 subs should be valid"
    );

    // thresh with k = 1: valid
    let ms = Miniscript::from_str(
        "thresh(1,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "thresh(1,...) should be valid"
    );

    // thresh with k > number of subs: invalid
    let ms = Miniscript::from_str(
        "thresh(3,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        Context::Wsh,
    );
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "thresh with k > subs should be invalid"
    );

    // thresh with k = 0: invalid
    let ms = Miniscript::from_str(
        "thresh(0,c:pk_k(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65),sc:pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
        Context::Wsh,
    );
    assert!(
        ms.is_err() || !ms.unwrap().is_valid(),
        "thresh with k = 0 should be invalid"
    );
}

#[test]
fn test_timelock_mixing() {
    init_testdata();

    // or_b with different timelock types: valid
    let ms = Miniscript::from_str("or_b(l:after(100),al:after(1000000000))", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "or_b with timelock mix should be valid"
    );

    // and_b with different timelock types: valid but has timelock mix
    let ms = Miniscript::from_str("and_b(after(100),a:after(1000000000))", Context::Wsh);
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "and_b with timelock mix should be valid"
    );
}

#[test]
fn test_pk_and_pkh_aliases() {
    init_testdata();

    // pk is an alias to c:pk_k
    let ms = Miniscript::from_str(
        "pk(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)",
        Context::Wsh,
    );
    assert!(ms.is_ok() && ms.unwrap().is_valid(), "pk() should be valid");

    // pkh is an alias to c:pk_h
    let ms = Miniscript::from_str(
        "pkh(03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65)",
        Context::Wsh,
    );
    assert!(
        ms.is_ok() && ms.unwrap().is_valid(),
        "pkh() should be valid"
    );
}

#[test]
fn test_numbers_no_sign_prefix() {
    init_testdata();

    // Numbers can't be prefixed by a sign
    let ms = Miniscript::from_str("after(-1)", Context::Wsh);
    assert!(ms.is_err(), "after(-1) should be invalid");

    let ms = Miniscript::from_str("after(+1)", Context::Wsh);
    assert!(ms.is_err(), "after(+1) should be invalid");

    let ms = Miniscript::from_str(
        "thresh(-1,pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204))",
        Context::Wsh,
    );
    assert!(ms.is_err(), "thresh(-1,...) should be invalid");

    let ms = Miniscript::from_str(
        "multi(+1,03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)",
        Context::Wsh,
    );
    assert!(ms.is_err(), "multi(+1,...) should be invalid");
}
