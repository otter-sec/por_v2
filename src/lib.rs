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
        std::fs::write(output_dir, serde_json::to_string(&final_proof)?)?;
        std::fs::write(output_dir, serde_json::to_string(&merkle_tree)?)?;
        std::fs::write(output_dir, serde_json::to_string(&account_nonces)?)?;
    }

    Ok((final_proof, merkle_tree, account_nonces))
}

/// Feature: Prove - Generates a global proof of reserves from ledger data
pub fn prove_from_data(ledger: Ledger, output_dir: Option<&str>) -> Result<(FinalProof, MerkleTree, Vec<u64>)> {
    // log_info!("Starting to prove reserves... This might take some hours depending on the ledger size...");
    let (final_proof, merkle_tree, account_nonces) = prove_global(ledger)?;
    
    if let Some(output_dir) = output_dir {
        std::fs::write(output_dir, serde_json::to_string(&final_proof)?)?;
        std::fs::write(output_dir, serde_json::to_string(&merkle_tree)?)?;
        std::fs::write(output_dir, serde_json::to_string(&account_nonces)?)?;
    }

    Ok((final_proof, merkle_tree, account_nonces))
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