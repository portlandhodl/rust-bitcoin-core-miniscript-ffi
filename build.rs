use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const BITCOIN_CORE_VERSION: &str = "v30.1";
const BITCOIN_CORE_REPO: &str = "https://github.com/bitcoin/bitcoin.git";

fn main() {
    if env::var("DOCS_RS").is_ok() {
        generate_stub_bindings();
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let bitcoin_src = get_bitcoin_source(&manifest_dir, &out_dir);

    let dst = cmake::Config::new(&manifest_dir)
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("BITCOIN_SRC_DIR", bitcoin_src.to_str().unwrap())
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!(
        "cargo:rustc-link-search=native={}/build/secp256k1/lib",
        dst.display()
    );
    println!("cargo:rustc-link-lib=static=miniscript_wrapper");
    println!("cargo:rustc-link-lib=static=secp256k1");

    #[cfg(target_os = "linux")]
    println!("cargo:rustc-link-lib=stdc++");
    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=c++");

    let bindings = bindgen::Builder::default()
        .header(
            manifest_dir
                .join("cpp/miniscript_wrapper.h")
                .to_str()
                .unwrap(),
        )
        .header(
            manifest_dir
                .join("cpp/descriptor_wrapper.h")
                .to_str()
                .unwrap(),
        )
        .clang_arg(format!("-I{}", bitcoin_src.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Miniscript types
        .allowlist_type("MiniscriptContext")
        .allowlist_type("MiniscriptNode")
        .allowlist_type("MiniscriptResult")
        .allowlist_function("miniscript_.*")
        .allowlist_type("SatisfierCallbacks")
        .allowlist_type("SatisfactionResult")
        .allowlist_type("MiniscriptAvailability")
        // Descriptor types
        .allowlist_type("DescriptorNode")
        .allowlist_type("DescriptorResult")
        .allowlist_type("DescriptorNetwork")
        .allowlist_type("ExpandedScript")
        .allowlist_type("PubKeyInfo")
        .allowlist_function("descriptor_.*")
        // Enums
        .rustified_enum("MiniscriptContext")
        .rustified_enum("MiniscriptAvailability")
        .rustified_enum("DescriptorNetwork")
        .derive_debug(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=cpp/miniscript_wrapper.h");
    println!("cargo:rerun-if-changed=cpp/miniscript_wrapper.cpp");
    println!("cargo:rerun-if-changed=cpp/descriptor_wrapper.h");
    println!("cargo:rerun-if-changed=cpp/descriptor_wrapper.cpp");
    println!("cargo:rerun-if-changed=cpp/stubs.cpp");
    println!("cargo:rerun-if-changed=CMakeLists.txt");
}

fn get_bitcoin_source(manifest_dir: &Path, out_dir: &Path) -> PathBuf {
    let vendor_src = manifest_dir.join("vendor/bitcoin/src");
    if vendor_src.join("script/miniscript.h").exists() {
        println!("cargo:warning=Using Bitcoin Core from vendor/bitcoin");
        return vendor_src;
    }

    if let Ok(src_path) = env::var("BITCOIN_CORE_SRC") {
        let src = PathBuf::from(&src_path);
        if src.join("script/miniscript.h").exists() {
            println!("cargo:warning=Using Bitcoin Core from BITCOIN_CORE_SRC={src_path}");
            return src;
        }
    }

    let bitcoin_dir = out_dir.join("bitcoin");
    let bitcoin_src = bitcoin_dir.join("src");

    if bitcoin_src.join("script/miniscript.h").exists() {
        println!(
            "cargo:warning=Using cached Bitcoin Core from {}",
            bitcoin_dir.display()
        );
        return bitcoin_src;
    }

    println!("cargo:warning=Downloading Bitcoin Core {BITCOIN_CORE_VERSION} ...");

    let status = Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "--branch",
            BITCOIN_CORE_VERSION,
            "--single-branch",
            BITCOIN_CORE_REPO,
            bitcoin_dir.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute git clone. Is git installed?");

    assert!(
        status.success(),
        "Failed to download Bitcoin Core! Please ensure git is installed and you have internet access, \
        or set BITCOIN_CORE_SRC environment variable to point to your Bitcoin Core src directory."
    );

    assert!(
        bitcoin_src.join("script/miniscript.h").exists(),
        "Bitcoin Core downloaded but miniscript.h not found!"
    );

    println!("cargo:warning=Bitcoin Core {BITCOIN_CORE_VERSION} downloaded successfully");
    bitcoin_src
}

#[allow(clippy::too_many_lines)]
fn generate_stub_bindings() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let stub_bindings = r#"
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum MiniscriptContext {
    MINISCRIPT_CONTEXT_WSH = 0,
    MINISCRIPT_CONTEXT_TAPSCRIPT = 1,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum MiniscriptAvailability {
    MINISCRIPT_AVAILABILITY_NO = 0,
    MINISCRIPT_AVAILABILITY_YES = 1,
    MINISCRIPT_AVAILABILITY_MAYBE = 2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MiniscriptNode {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MiniscriptResult {
    pub success: bool,
    pub error_message: *mut ::std::os::raw::c_char,
}

/// Callback function types for the Satisfier
pub type SignCallback = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut ::std::os::raw::c_void,
        key_bytes: *const u8,
        key_len: usize,
        sig_out: *mut *mut u8,
        sig_len_out: *mut usize,
    ) -> MiniscriptAvailability,
>;

pub type CheckAfterCallback = ::std::option::Option<
    unsafe extern "C" fn(context: *mut ::std::os::raw::c_void, value: u32) -> bool,
>;

pub type CheckOlderCallback = ::std::option::Option<
    unsafe extern "C" fn(context: *mut ::std::os::raw::c_void, value: u32) -> bool,
>;

pub type SatHashCallback = ::std::option::Option<
    unsafe extern "C" fn(
        context: *mut ::std::os::raw::c_void,
        hash: *const u8,
        hash_len: usize,
        preimage_out: *mut *mut u8,
        preimage_len_out: *mut usize,
    ) -> MiniscriptAvailability,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SatisfierCallbacks {
    pub rust_context: *mut ::std::os::raw::c_void,
    pub sign_callback: SignCallback,
    pub check_after_callback: CheckAfterCallback,
    pub check_older_callback: CheckOlderCallback,
    pub sat_sha256_callback: SatHashCallback,
    pub sat_ripemd160_callback: SatHashCallback,
    pub sat_hash256_callback: SatHashCallback,
    pub sat_hash160_callback: SatHashCallback,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SatisfactionResult {
    pub availability: MiniscriptAvailability,
    pub stack: *mut *mut u8,
    pub stack_sizes: *mut usize,
    pub stack_count: usize,
    pub error_message: *mut ::std::os::raw::c_char,
}

unsafe extern "C" {
    pub fn miniscript_from_string(
        input: *const ::std::os::raw::c_char,
        ctx: MiniscriptContext,
        out_node: *mut *mut MiniscriptNode,
    ) -> MiniscriptResult;

    pub fn miniscript_to_string(node: *const MiniscriptNode) -> *mut ::std::os::raw::c_char;

    pub fn miniscript_to_script(
        node: *const MiniscriptNode,
        out_script: *mut *mut u8,
        out_len: *mut usize,
    ) -> bool;

    pub fn miniscript_is_valid(node: *const MiniscriptNode) -> bool;

    pub fn miniscript_is_sane(node: *const MiniscriptNode) -> bool;

    pub fn miniscript_get_type(node: *const MiniscriptNode) -> *mut ::std::os::raw::c_char;

    pub fn miniscript_max_satisfaction_size(
        node: *const MiniscriptNode,
        out_size: *mut usize,
    ) -> bool;

    pub fn miniscript_is_non_malleable(node: *const MiniscriptNode) -> bool;
    pub fn miniscript_needs_signature(node: *const MiniscriptNode) -> bool;
    pub fn miniscript_has_timelock_mix(node: *const MiniscriptNode) -> bool;
    pub fn miniscript_is_valid_top_level(node: *const MiniscriptNode) -> bool;
    pub fn miniscript_check_ops_limit(node: *const MiniscriptNode) -> bool;
    pub fn miniscript_check_stack_size(node: *const MiniscriptNode) -> bool;
    pub fn miniscript_check_duplicate_key(node: *const MiniscriptNode) -> bool;

    pub fn miniscript_get_ops(node: *const MiniscriptNode, out_ops: *mut u32) -> bool;
    pub fn miniscript_get_stack_size(node: *const MiniscriptNode, out_size: *mut u32) -> bool;
    pub fn miniscript_get_exec_stack_size(node: *const MiniscriptNode, out_size: *mut u32) -> bool;
    pub fn miniscript_get_script_size(node: *const MiniscriptNode, out_size: *mut usize) -> bool;

    pub fn miniscript_from_script(
        script: *const u8,
        script_len: usize,
        ctx: MiniscriptContext,
        out_node: *mut *mut MiniscriptNode,
    ) -> MiniscriptResult;

    pub fn miniscript_find_insane_sub(node: *const MiniscriptNode) -> *mut MiniscriptNode;
    pub fn miniscript_valid_satisfactions(node: *const MiniscriptNode) -> bool;
    pub fn miniscript_get_static_ops(node: *const MiniscriptNode, out_ops: *mut u32) -> bool;

    pub fn miniscript_satisfy(
        node: *const MiniscriptNode,
        callbacks: *const SatisfierCallbacks,
        nonmalleable: bool,
    ) -> SatisfactionResult;

    pub fn miniscript_satisfaction_result_free(result: *mut SatisfactionResult);

    pub fn miniscript_node_free(node: *mut MiniscriptNode);

    pub fn miniscript_free_string(str_: *mut ::std::os::raw::c_char);

    pub fn miniscript_free_bytes(bytes: *mut u8);

    pub fn miniscript_version() -> *const ::std::os::raw::c_char;
}

// Descriptor types for docs.rs stub bindings

#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum DescriptorNetwork {
    DESCRIPTOR_NETWORK_MAINNET = 0,
    DESCRIPTOR_NETWORK_TESTNET = 1,
    DESCRIPTOR_NETWORK_SIGNET = 2,
    DESCRIPTOR_NETWORK_REGTEST = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DescriptorNode {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DescriptorResult {
    pub success: bool,
    pub error_message: *mut ::std::os::raw::c_char,
}

unsafe extern "C" {
    pub fn descriptor_parse(
        descriptor_str: *const ::std::os::raw::c_char,
        out_node: *mut *mut DescriptorNode,
    ) -> DescriptorResult;

    pub fn descriptor_is_range(node: *const DescriptorNode) -> bool;

    pub fn descriptor_is_solvable(node: *const DescriptorNode) -> bool;

    pub fn descriptor_to_string(node: *const DescriptorNode) -> *mut ::std::os::raw::c_char;

    pub fn descriptor_expand(
        node: *const DescriptorNode,
        pos: ::std::os::raw::c_int,
        out_script: *mut *mut u8,
        out_len: *mut usize,
    ) -> bool;

    pub fn descriptor_get_address(
        node: *const DescriptorNode,
        pos: ::std::os::raw::c_int,
        network: DescriptorNetwork,
    ) -> *mut ::std::os::raw::c_char;

    pub fn descriptor_get_pubkeys(
        node: *const DescriptorNode,
        pos: ::std::os::raw::c_int,
        out_pubkeys: *mut *mut *mut u8,
        out_lens: *mut *mut usize,
        out_count: *mut usize,
    ) -> bool;

    pub fn descriptor_get_script_size(
        node: *const DescriptorNode,
        out_size: *mut i64,
    ) -> bool;

    pub fn descriptor_get_max_satisfaction_weight(
        node: *const DescriptorNode,
        use_max_sig: bool,
        out_weight: *mut i64,
    ) -> bool;

    pub fn descriptor_get_checksum(
        descriptor_str: *const ::std::os::raw::c_char,
    ) -> *mut ::std::os::raw::c_char;

    pub fn descriptor_node_free(node: *mut DescriptorNode);

    pub fn descriptor_free_string(str_: *mut ::std::os::raw::c_char);

    pub fn descriptor_free_bytes(bytes: *mut u8);

    pub fn descriptor_free_pubkeys(pubkeys: *mut *mut u8, lens: *mut usize, count: usize);

    pub fn descriptor_version() -> *const ::std::os::raw::c_char;
}
"#;

    std::fs::write(out_dir.join("bindings.rs"), stub_bindings)
        .expect("Failed to write stub bindings");

    println!("cargo:warning=Building for docs.rs - using stub bindings (no native library)");
}
