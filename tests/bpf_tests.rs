//! BPF Kernel-Side Tests
//!
//! The BPF helper function tests are defined in src/bpf/firebee_test.bpf.c
//! They test kernel-side logic using the CHECK/TEST framework.
//!

use libbpf_rs::{skel::OpenSkel, skel::SkelBuilder, MapCore, MapFlags, ProgramInput};
use std::mem::MaybeUninit;
use std::path::Path;

// Include the generated skeleton (use include! so rustfmt doesn't try to resolve the path)
#[allow(clippy::all, dead_code, non_snake_case, non_camel_case_types)]
mod firebee_test {
    include!("../src/bpf/firebee_test.skel.rs");
}
use firebee_test::*;

/// Test status codes (from test_common.h)
const TEST_PASS: u8 = 101;
const TEST_FAIL: u8 = 102;

/// Protobuf markers
const MKR_TEST_RESULT: u8 = 0x0A;
#[allow(dead_code)]
const MKR_TEST_NAME: u8 = 0x0A;
#[allow(dead_code)]
const MKR_TEST_STATUS: u8 = 0x10;
#[allow(dead_code)]
const MKR_TEST_LOG: u8 = 0x1A;

/// Parse test results from protobuf-encoded data
fn parse_test_results(data: &[u8]) -> Vec<(String, bool, Vec<String>)> {
    let mut results = Vec::new();
    let mut pos = 0;

    while pos < data.len() && data[pos] != 0 {
        if data[pos] == MKR_TEST_RESULT {
            pos += 1;
            if pos >= data.len() {
                break;
            }

            // Read varint length
            let len = if data[pos] & 0x80 != 0 {
                let low = (data[pos] & 0x7F) as usize;
                pos += 1;
                if pos >= data.len() {
                    break;
                }
                let high = (data[pos] as usize) << 7;
                pos += 1;
                high | low
            } else {
                let val = data[pos] as usize;
                pos += 1;
                val
            };

            if pos + len > data.len() {
                break;
            }

            let test_data = &data[pos..pos + len];
            if let Some(result) = parse_single_test(test_data) {
                results.push(result);
            }
            pos += len;
        } else {
            pos += 1;
        }
    }

    results
}

fn parse_single_test(data: &[u8]) -> Option<(String, bool, Vec<String>)> {
    let mut name = String::new();
    let mut status = 0u8;
    let logs = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        if pos >= data.len() {
            break;
        }
        let marker = data[pos];
        pos += 1;

        match marker {
            0x0A => {
                // MKR_TEST_NAME
                if pos >= data.len() {
                    break;
                }
                let name_len = data[pos] as usize;
                pos += 1;
                if pos + name_len > data.len() {
                    break;
                }
                // Skip null terminator
                let end = if name_len > 0 && data[pos + name_len - 1] == 0 {
                    pos + name_len - 1
                } else {
                    pos + name_len
                };
                name = String::from_utf8_lossy(&data[pos..end]).to_string();
                pos += name_len;
            }
            0x10 => {
                // MKR_TEST_STATUS
                if pos >= data.len() {
                    break;
                }
                status = data[pos];
                pos += 1;
            }
            0x1A => {
                // MKR_TEST_LOG
                if pos >= data.len() {
                    break;
                }
                let log_len = data[pos] as usize;
                pos += 1;
                if pos + log_len <= data.len() {
                    // Parse log message (simplified - just skip for now)
                    pos += log_len;
                }
            }
            _ => {
                break;
            }
        }
    }

    if !name.is_empty() {
        Some((name, status == TEST_PASS, logs))
    } else {
        None
    }
}

fn run_test_suite(
    suite_name: &str,
    prog: &mut libbpf_rs::ProgramMut,
    test_result_map: &libbpf_rs::MapMut,
) -> Result<(), String> {
    // Create empty XDP context (tests don't use actual packet data)
    let input = vec![0u8; 64];
    let mut output = vec![0u8; 64];

    // Run the test program using test_run
    let test_input = ProgramInput {
        data_in: Some(&input),
        data_out: Some(&mut output),
        repeat: 1,
        ..Default::default()
    };

    let test_output = prog
        .test_run(test_input)
        .map_err(|e| format!("Failed to run test program: {}", e))?;

    let ret_val = test_output.return_value;
    if ret_val != TEST_PASS as u32 && ret_val != TEST_FAIL as u32 {
        return Err(format!(
            "Unexpected return value: {} (expected {} or {})",
            ret_val, TEST_PASS, TEST_FAIL
        ));
    }

    let key = 0u32.to_ne_bytes();
    let value = test_result_map
        .lookup(&key, MapFlags::ANY)
        .map_err(|e| format!("Failed to lookup test results: {}", e))?
        .ok_or("No test results found in map")?;

    let results = parse_test_results(&value);

    if results.is_empty() {
        return Err("No test results parsed".to_string());
    }

    println!("\n{} ({} tests):", suite_name, results.len());
    let mut all_passed = true;
    for (name, passed, _logs) in &results {
        let status = if *passed { "✓ PASS" } else { "✗ FAIL" };
        println!("  {} ... {}", name, status);
        all_passed = all_passed && *passed;
    }

    if !all_passed {
        Err(format!("Some tests in {} failed", suite_name))
    } else {
        Ok(())
    }
}

#[test]
fn test_bpf_programs_compile() {
    assert!(
        Path::new("src/bpf/firebee_test.skel.rs").exists(),
        "BPF test skeleton should be generated during build"
    );
}

#[test]
#[ignore] // Requires root/CAP_BPF - run with: sudo cargo test --test bpf_tests -- --ignored
fn test_bpf_ip_matches() {
    let skel_builder = FirebeeTestSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();
    let open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open BPF skeleton");
    let mut skel = open_skel.load().expect("Failed to load BPF programs");

    run_test_suite(
        "ip_matches - IPv4 CIDR matching",
        &mut skel.progs.test_ip_matches,
        &skel.maps.test_result_map,
    )
    .expect("IPv4 matching tests failed");
}

#[test]
#[ignore]
fn test_bpf_port_matches() {
    let skel_builder = FirebeeTestSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();
    let open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open BPF skeleton");
    let mut skel = open_skel.load().expect("Failed to load BPF programs");

    run_test_suite(
        "port_matches - Port wildcards",
        &mut skel.progs.test_port_matches,
        &skel.maps.test_result_map,
    )
    .expect("Port matching tests failed");
}

#[test]
#[ignore]
fn test_bpf_protocol_matches() {
    let skel_builder = FirebeeTestSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();
    let open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open BPF skeleton");
    let mut skel = open_skel.load().expect("Failed to load BPF programs");

    run_test_suite(
        "protocol_matches - Protocol matching",
        &mut skel.progs.test_protocol_matches,
        &skel.maps.test_result_map,
    )
    .expect("Protocol matching tests failed");
}

#[test]
#[ignore]
fn test_bpf_ipv6_matches() {
    let skel_builder = FirebeeTestSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();
    let open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open BPF skeleton");
    let mut skel = open_skel.load().expect("Failed to load BPF programs");

    run_test_suite(
        "ipv6_matches - IPv6 prefix matching",
        &mut skel.progs.test_ipv6_matches,
        &skel.maps.test_result_map,
    )
    .expect("IPv6 matching tests failed");
}
