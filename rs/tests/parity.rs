//! Cross-language parity tests for MALT.
//!
//! These tests verify that the Rust implementation produces identical output
//! to the golden test vectors in `testdata/vectors.json`. The Go
//! implementation runs the same assertions against the same file,
//! ensuring both implementations remain in lockstep.

mod common;

use common::{build_log, SimpleHasher};
use malt::{verify_consistency, verify_inclusion, TreeHasher};
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct VectorFile {
    roots: Vec<RootVector>,
    inclusion_proofs: Vec<InclusionVector>,
    consistency_proofs: Vec<ConsistencyVector>,
}

#[derive(Deserialize)]
struct RootVector {
    size: u64,
    root: String,
}

#[derive(Deserialize)]
struct InclusionVector {
    tree_size: u64,
    index: u64,
    leaf_hash: String,
    path: Vec<String>,
}

#[derive(Deserialize)]
struct ConsistencyVector {
    old_size: u64,
    new_size: u64,
    path: Vec<String>,
}

fn hex_digest(d: &[u8; 8]) -> String {
    hex::encode(d)
}

fn load_vectors() -> VectorFile {
    // vectors.json lives at the repo root under testdata/,
    // one level above rs/.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(manifest).join("../testdata/vectors.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("failed to parse vectors.json")
}

#[test]
fn parity_roots() {
    let v = load_vectors();
    for tc in &v.roots {
        let log = build_log(tc.size);
        let got = hex_digest(&log.root());
        assert_eq!(got, tc.root, "root mismatch at size {}", tc.size);
    }
}

#[test]
fn parity_inclusion_proofs() {
    let v = load_vectors();
    for tc in &v.inclusion_proofs {
        let log = build_log(tc.tree_size);
        let root = log.root();
        let proof = log
            .inclusion_proof(tc.index)
            .unwrap_or_else(|e| panic!("size={} index={}: {e}", tc.tree_size, tc.index));

        // Verify path matches golden vector.
        assert_eq!(
            proof.path.len(),
            tc.path.len(),
            "size={} index={}: path length mismatch",
            tc.tree_size,
            tc.index
        );
        for (i, got) in proof.path.iter().enumerate() {
            assert_eq!(
                hex_digest(got),
                tc.path[i],
                "size={} index={}: path[{i}] mismatch",
                tc.tree_size,
                tc.index
            );
        }

        // Verify leaf hash matches.
        let leaf_hash = SimpleHasher.leaf(format!("leaf-{}", tc.index).as_bytes());
        assert_eq!(
            hex_digest(&leaf_hash),
            tc.leaf_hash,
            "size={} index={}: leaf hash mismatch",
            tc.tree_size,
            tc.index
        );

        // Verify the proof itself.
        assert!(
            verify_inclusion(&SimpleHasher, &leaf_hash, &proof, &root),
            "size={} index={}: golden proof failed verification",
            tc.tree_size,
            tc.index
        );
    }
}

#[test]
fn parity_consistency_proofs() {
    let v = load_vectors();
    for tc in &v.consistency_proofs {
        let log = build_log(tc.new_size);
        let new_root = log.root();
        let proof = log
            .consistency_proof(tc.old_size)
            .unwrap_or_else(|e| panic!("old={} new={}: {e}", tc.old_size, tc.new_size));

        // Verify path matches golden vector.
        assert_eq!(
            proof.path.len(),
            tc.path.len(),
            "old={} new={}: path length mismatch",
            tc.old_size,
            tc.new_size
        );
        for (i, got) in proof.path.iter().enumerate() {
            assert_eq!(
                hex_digest(got),
                tc.path[i],
                "old={} new={}: path[{i}] mismatch",
                tc.old_size,
                tc.new_size
            );
        }

        // Verify the proof itself.
        let old_root = build_log(tc.old_size).root();
        assert!(
            verify_consistency(&SimpleHasher, &proof, &old_root, &new_root),
            "old={} new={}: golden proof failed verification",
            tc.old_size,
            tc.new_size
        );
    }
}
