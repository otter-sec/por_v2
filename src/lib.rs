// Re-export existing modules
pub mod circuits;
pub mod config;
pub mod core;
pub mod custom_serializer;
pub mod merkle_tree;
pub mod types;
pub mod utils;

// Re-export commonly used external types that the modules depend on
pub use plonky2::hash::hash_types::HashOut;
pub use plonky2::plonk::circuit_data::VerifierCircuitData;
pub use plonky2::plonk::config::GenericHashOut;
pub use plonky2::plonk::proof::ProofWithPublicInputs;

// Re-export standard library types used in the modules
pub use std::time::Instant;

// Re-export internal types used across modules
pub use circuits::recursive_circuit::RecursiveCircuit;
pub use utils::logger::format_error;

// Re-export utility functions for hashing (useful for external nonce generation)
pub use utils::util::{hash_account, hash_n_subhashes};

// Re-export commonly used types from types module
pub use types::{
    FinalProof, InclusionProof, Ledger, LedgerDecimals, MerkleProof,
};

// Re-export merkle tree types
pub use merkle_tree::{MerkleTree, Node};

// Re-export config constants
pub use config::{BATCH_SIZE, RECURSIVE_SIZE, C, D, F, H};


use anyhow::Result;
use crate::core::prover::*;
pub use crate::core::prover::prove_global_with_nonces;
use crate::core::verifier::{verify_root, verify_user_inclusion};
use crate::merkle_tree::*;
use crate::types::*;
use crate::utils::logger::*;

/// Feature: Prove - Generates a global proof of reserves from a ledger file
pub fn prove_from_file(ledger_file_path: &str, output_dir: Option<&str>) -> Result<(FinalProof, MerkleTree, Vec<u64>)> {
    // log_info!("Reading and deserializing ledger...");
    let ledger = get_ledger_values_from_file(ledger_file_path);
    // log_success!("Ledger read successfully!");

    // log_info!("Starting to prove reserves... This might take some hours depending on the ledger size...");
    let (final_proof, merkle_tree, account_nonces) = prove_global(ledger)?;
    
    if let Some(output_dir) = output_dir {
        std::fs::write(format!("{}/final_proof.json", output_dir), serde_json::to_string(&final_proof)?)?;
        std::fs::write(format!("{}/merkle_tree.json", output_dir), serde_json::to_string(&merkle_tree)?)?;
        std::fs::write(format!("{}/private_nonces.json", output_dir), serde_json::to_string(&account_nonces)?)?;
    }

    Ok((final_proof, merkle_tree, account_nonces))
}

/// Feature: Prove - Generates a global proof of reserves from ledger data
pub fn prove_from_data(ledger: Ledger, output_dir: Option<&str>) -> Result<(FinalProof, MerkleTree, Vec<u64>)> {
    // log_info!("Starting to prove reserves... This might take some hours depending on the ledger size...");
    let (final_proof, merkle_tree, account_nonces) = prove_global(ledger)?;

    if let Some(output_dir) = output_dir {
        std::fs::write(format!("{}/final_proof.json", output_dir), serde_json::to_string(&final_proof)?)?;
        std::fs::write(format!("{}/merkle_tree.json", output_dir), serde_json::to_string(&merkle_tree)?)?;
        std::fs::write(format!("{}/private_nonces.json", output_dir), serde_json::to_string(&account_nonces)?)?;
    }

    Ok((final_proof, merkle_tree, account_nonces))
}

/// Feature: Prove - Like prove_from_data, but with pre-generated nonces for deterministic proof generation.
pub fn prove_from_data_with_nonces(
    ledger: Ledger,
    nonces: Vec<u64>,
    output_dir: Option<&str>,
) -> Result<(FinalProof, MerkleTree, Vec<u64>)> {
    let (final_proof, merkle_tree, _) = prove_global_with_nonces(ledger, Some(nonces.clone()))?;

    if let Some(output_dir) = output_dir {
        std::fs::write(format!("{}/final_proof.json", output_dir), serde_json::to_string(&final_proof)?)?;
        std::fs::write(format!("{}/merkle_tree.json", output_dir), serde_json::to_string(&merkle_tree)?)?;
        std::fs::write(format!("{}/private_nonces.json", output_dir), serde_json::to_string(&nonces)?)?;
    }

    Ok((final_proof, merkle_tree, nonces))
}

/// Build a Poseidon Merkle tree without generating a ZK proof (fast path).
/// Produces the exact same root as prove_global_with_nonces when using the same nonces.
pub fn build_tree_only(ledger: &Ledger, nonces: &[u64]) -> Result<(MerkleTree, Vec<u8>)> {
    use plonky2::hash::hash_types::HashOut;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;

    let mut ledger = ledger.clone();
    let asset_count = ledger.asset_names.len();

    utils::util::pad_accounts(
        &mut ledger.account_balances,
        &mut ledger.hashes,
        asset_count,
        BATCH_SIZE,
    )?;

    // Pad nonces with zeros for padded accounts
    let mut padded_nonces = nonces.to_vec();
    padded_nonces.resize(ledger.hashes.len(), 0u64);

    // Compute leaf hashes
    let leaf_nodes: Vec<Node> = ledger.account_balances.iter()
        .zip(ledger.hashes.iter())
        .enumerate()
        .map(|(i, (balances, user_hash))| {
            let hash = utils::util::hash_account(balances, user_hash.clone(), padded_nonces[i]);
            Node::new(Some(hash.to_bytes()))
        })
        .collect();

    let mut tree = MerkleTree::new_from_leafs(leaf_nodes, 1, true);

    // Compute empty batch hash (matches ZK circuit's prove_empty)
    let zero_hash = HashOut::<F>::default();
    let mut concat_elements = Vec::new();
    for _ in 0..BATCH_SIZE {
        concat_elements.extend_from_slice(&zero_hash.elements);
    }
    let empty_batch_hash = PoseidonHash::hash_no_pad(&concat_elements).to_bytes();

    // Set empty hash for padding batch nodes
    let batch_depth = tree.depth - 1;
    for node in tree.get_nodes_from_depth(batch_depth) {
        if node.children_mut().is_none() && node.hash().is_none() {
            node.set_hash(empty_batch_hash.clone());
        }
    }

    // Compute and set empty hashes for padding recursive nodes (bottom-up)
    let mut current_empty_hash = empty_batch_hash;
    for depth in (1..batch_depth).rev() {
        let children_hashes: Vec<Vec<u8>> = (0..RECURSIVE_SIZE)
            .map(|_| current_empty_hash.clone())
            .collect();
        current_empty_hash = utils::util::hash_n_subhashes::<F, D>(&children_hashes).to_bytes();

        for node in tree.get_nodes_from_depth(depth) {
            if node.children_mut().is_none() && node.hash().is_none() {
                node.set_hash(current_empty_hash.clone());
            }
        }
    }

    // Recursively compute internal node hashes
    fn compute_hashes(node: &mut Node) {
        if let Some(children) = node.children_mut() {
            for child in children.iter_mut() {
                compute_hashes(child);
            }
            let children_hashes: Vec<Vec<u8>> = children.iter()
                .filter_map(|child| child.hash().clone())
                .collect();
            if !children_hashes.is_empty() {
                node.set_hash(utils::util::hash_n_subhashes::<F, D>(&children_hashes).to_bytes());
            }
        }
    }
    compute_hashes(&mut tree.root);

    let root = tree.root.hash().clone()
        .ok_or_else(|| anyhow::anyhow!("Root hash not computed"))?;

    Ok((tree, root))
}

/// Feature: Prove inclusion (single file) - Generates an inclusion proof for a specific user from files
pub fn prove_inclusion_from_files(
    user_hash: &str,
    merkle_tree_file: &str,
    final_proof_file: &str,
    nonces_file: &str,
    ledger_file: &str,
    output_file: Option<&str>,
) -> Result<InclusionProof> {
    let merkle_tree: MerkleTree = serde_json::from_str(&std::fs::read_to_string(merkle_tree_file)?)?;
    let final_proof: FinalProof = serde_json::from_str(&std::fs::read_to_string(final_proof_file)?)?;
    let nonces: Vec<u64> = serde_json::from_str(&std::fs::read_to_string(nonces_file)?)?;
    let ledger = get_ledger_values_from_file(ledger_file);
    
    assert_config(&final_proof);

    let inclusion_proof = prove_user_inclusion_by_hash(user_hash.to_string(), &merkle_tree, &nonces, &ledger)?;

    if let Some(output_file) = output_file {
        std::fs::write(output_file, serde_json::to_string(&inclusion_proof)?)?;
    }

    Ok(inclusion_proof)
}

/// Feature: Prove inclusion (single user) - Generates an inclusion proof for a specific user from data
pub fn prove_inclusion_from_data(
    user_hash: &str,
    merkle_tree: &MerkleTree,
    final_proof: &FinalProof,
    nonces: &[u64],
    ledger: &Ledger,
    output_file: Option<&str>,
) -> Result<InclusionProof> {
    assert_config(final_proof);

    let inclusion_proof = prove_user_inclusion_by_hash(user_hash.to_string(), merkle_tree, nonces, ledger)?;

    if let Some(output_file) = output_file {
        std::fs::write(output_file, serde_json::to_string(&inclusion_proof)?)?;
    }

    Ok(inclusion_proof)
}

/// Feature: Prove inclusion (all files batched) - Generates inclusion proofs for all users in batches from files
pub fn prove_inclusion_batched_from_files(
    merkle_tree_file: &str,
    final_proof_file: &str,
    nonces_file: &str,
    ledger_file: &str,
) -> Result<()> {
    let merkle_tree: MerkleTree = serde_json::from_str(&std::fs::read_to_string(merkle_tree_file)?)?;
    let final_proof: FinalProof = serde_json::from_str(&std::fs::read_to_string(final_proof_file)?)?;
    let nonces: Vec<u64> = serde_json::from_str(&std::fs::read_to_string(nonces_file)?)?;
    let ledger = get_ledger_values_from_file(ledger_file);
    
    assert_config(&final_proof);

    prove_inclusion_all_batched(&ledger, &merkle_tree, nonces)?;
    
    Ok(())
}

/// Feature: Prove inclusion (all users batched) - Generates inclusion proofs for all users in batches from data
pub fn prove_inclusion_batched_from_data(
    merkle_tree: &MerkleTree,
    final_proof: &FinalProof,
    nonces: Vec<u64>,
    ledger: &Ledger,
) -> Result<()> {
    assert_config(final_proof);

    prove_inclusion_all_batched(ledger, merkle_tree, nonces)?;
    
    Ok(())
}

/// Verify a global proof of reserves from files
pub fn verify_from_files(final_proof_file: &str, merkle_tree_file: &str) -> Result<()> {
    let final_proof: FinalProof = serde_json::from_str(&std::fs::read_to_string(final_proof_file)?)?;
    let merkle_tree: MerkleTree = serde_json::from_str(&std::fs::read_to_string(merkle_tree_file)?)?;

    assert_config(&final_proof);
    verify_root(final_proof, merkle_tree);
    Ok(())
}

// Helper function to read ledger from file
pub fn get_ledger_values_from_file(filename: &str) -> Ledger {
    let ledger_file = std::fs::read_to_string(filename).unwrap();
    let ledger_json: serde_json::Value = serde_json::from_str(&ledger_file).unwrap();

    // get decimals from "assets" field
    let assets = ledger_json["assets"].as_object().unwrap();

    let mut asset_names = Vec::new();
    let mut decimals = Vec::new();
    let mut prices = Vec::new();

    for (asset_name, asset) in assets {
        let asset_decimals = asset["usdt_decimals"].as_i64().unwrap();
        let balance_decimals = asset["balance_decimals"].as_i64().unwrap();

        asset_names.push(asset_name.clone());
        prices.push(asset["price"].as_u64().unwrap());

        decimals.push(LedgerDecimals {
            usdt_decimals: asset_decimals,
            balance_decimals,
        });
    }

    // get balances from "accounts" field
    let accounts = ledger_json["accounts"].as_object().unwrap();

    let mut account_balances = Vec::new();
    let mut hashes = Vec::new();

    for (hash, account) in accounts {
        let account = account.as_object().unwrap();
        let mut balances = Vec::new();

        // the order of the assets in the account is the same as in the assets field
        for asset_name in asset_names.iter() {
            let balance = account[asset_name].as_i64().unwrap();
            balances.push(balance);
        }

        // the order of the hashes is the same as in the accounts field
        account_balances.push(balances);
        hashes.push(hash.clone());
    }

    let timestamp = ledger_json["timestamp"].as_u64().unwrap();

    Ledger {
        asset_names,
        hashes,
        account_balances,
        asset_prices: prices,
        asset_decimals: decimals,
        timestamp,
    }
}

// Helper function to assert configuration
pub fn assert_config(final_proof: &FinalProof) {
    if final_proof.batch_size != BATCH_SIZE {
        log_error!(
            "Batch size mismatch! Expected: {}, Found: {}. Consider recompiling the code with the correct config",
            BATCH_SIZE,
            final_proof.batch_size
        );
    }
    if final_proof.recursive_size != RECURSIVE_SIZE {
        log_error!(
            "Batch size mismatch! Expected: {}, Found: {}. Consider recompiling the code with the correct config",
            RECURSIVE_SIZE,
            final_proof.recursive_size
        );
    }
    if final_proof.prover_version != format!("v{}", env!("CARGO_PKG_VERSION")) {
        log_error!(
            "Prover version mismatch! Expected: {}, Found: {}. Consider downloading the correct version from the repository",
            env!("CARGO_PKG_VERSION"),
            final_proof.prover_version
        );
    }
}

#[cfg(test)]
mod build_tree_tests {
    use super::*;

    fn create_test_ledger(num_accounts: usize) -> Ledger {
        let mut hashes = Vec::new();
        let mut balances = Vec::new();

        for i in 0..num_accounts {
            // Create deterministic but unique hashes (64 hex chars, no 0x prefix)
            let hash = format!("{:064x}", i + 1);
            hashes.push(hash);
            balances.push(vec![1_000_000i64 * (i as i64 + 1), 500_000i64 * (i as i64 + 1)]);
        }

        Ledger {
            asset_names: vec![
                "0x0000000000000000000000000000000000000001".to_string(),
                "0x0000000000000000000000000000000000000002".to_string(),
            ],
            hashes,
            account_balances: balances,
            asset_prices: vec![1_000_000_000_000_000_000u64, 2_000_000_000_000_000_000u64],
            asset_decimals: vec![
                LedgerDecimals { usdt_decimals: 18, balance_decimals: 6 },
                LedgerDecimals { usdt_decimals: 18, balance_decimals: 6 },
            ],
            timestamp: 1700000000,
        }
    }

    #[test]
    fn test_build_tree_only_matches_prove_global() {
        // Create a small ledger for testing
        let ledger = create_test_ledger(4);
        let num_accounts = ledger.hashes.len();

        // Generate random nonces
        let nonces: Vec<u64> = (0..num_accounts).map(|_| rand::random()).collect();

        // Build tree using fast method
        let (fast_tree, fast_root) = build_tree_only(&ledger, &nonces).unwrap();

        // Build tree using full proof generation (slow)
        let (_, proof_tree, _) = prove_global_with_nonces(ledger, Some(nonces)).unwrap();
        let proof_root = proof_tree.root.hash().clone().unwrap();

        // CRITICAL: Roots must match exactly
        assert_eq!(
            fast_root, proof_root,
            "build_tree_only root does not match prove_global_with_nonces root!"
        );

        // Verify tree depths match
        assert_eq!(fast_tree.depth, proof_tree.depth, "Tree depths don't match");
    }

    #[test]
    fn test_build_tree_only_deterministic() {
        let ledger = create_test_ledger(8);
        let nonces: Vec<u64> = (0..8).map(|i| i as u64 * 12345).collect();

        let (_, root1) = build_tree_only(&ledger, &nonces).unwrap();
        let (_, root2) = build_tree_only(&ledger, &nonces).unwrap();

        assert_eq!(root1, root2, "build_tree_only should be deterministic");
    }

    #[test]
    fn test_build_tree_only_different_nonces_different_roots() {
        let ledger = create_test_ledger(4);

        let nonces1: Vec<u64> = vec![1, 2, 3, 4];
        let nonces2: Vec<u64> = vec![5, 6, 7, 8];

        let (_, root1) = build_tree_only(&ledger, &nonces1).unwrap();
        let (_, root2) = build_tree_only(&ledger, &nonces2).unwrap();

        assert_ne!(root1, root2, "Different nonces should produce different roots");
    }

    #[test]
    fn test_build_tree_only_fast() {
        use std::time::Instant;

        let ledger = create_test_ledger(100);
        let nonces: Vec<u64> = (0..100).map(|_| rand::random()).collect();

        let start = Instant::now();
        let _ = build_tree_only(&ledger, &nonces).unwrap();
        let elapsed = start.elapsed();

        assert!(elapsed.as_secs() < 1, "build_tree_only should be fast (< 1s for 100 accounts)");
    }
}