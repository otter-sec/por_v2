use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::{Deserialize, Serialize};
use crate::utils::utils::hash_n_subhashes;
use crate::config::*;
use crate::custom_serializer::base64;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerDecimals {
    pub usdt_decimals: i64,
    pub balance_decimals: i64,
}

#[derive(Clone, Debug)]
pub struct Ledger {
    pub asset_names: Vec<String>,
    pub hashes: Vec<String>,
    pub account_balances: Vec<Vec<i64>>,
    pub asset_prices: Vec<u64>,
    pub asset_decimals: Vec<LedgerDecimals>,
    pub timestamp: u64
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalProof{
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub batch_size: usize,
    pub recursive_size: usize,
    pub asset_prices: Vec<u64>,
    pub asset_names: Vec<String>,
    pub asset_decimals: Vec<LedgerDecimals>,
    pub tree_depth: usize,
    pub timestamp: u64,
    // custom serialization --> for whatever reason Serialize and Deserialize traits are not implemented for VerifierCircuitData
    // so we serialize it as a Vec<u8> and deserialize it back in our code
    #[serde(serialize_with = "base64::serialize", deserialize_with = "base64::deserialize")]
    pub root_circuit_verifier_data: Vec<u8> 
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof{
    #[serde(serialize_with = "base64::serialize_vec", deserialize_with = "base64::deserialize_vec")]
    pub left_hashes: Vec<Vec<u8>>,
    #[serde(serialize_with = "base64::serialize_vec", deserialize_with = "base64::deserialize_vec")]
    pub right_hashes: Vec<Vec<u8>>,
    pub parent_hashes: Option<Box<MerkleProof>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof{
    pub user_balances: Vec<i64>,
    pub user_hash: String,
    pub nonce: u64,
    pub merkle_proof: MerkleProof,
    #[serde(serialize_with = "base64::serialize", deserialize_with = "base64::deserialize")]
    pub root_hash: Vec<u8>,
}

impl InclusionProof {
    pub fn calculate_merkle_root_hash(&self, leaf_hash: Vec<u8>) -> Vec<u8>{
        let mut current_hash = leaf_hash;
        let mut current_node = Some(&self.merkle_proof);

        // Traverse the proof to calculate the root hash
        while current_node.is_some(){
            let node = current_node.unwrap();
            let mut hashes = Vec::new();
            let left_hashes = &node.left_hashes;
            let right_hashes = &node.right_hashes;

            hashes.extend(left_hashes.iter().cloned());
            hashes.push(current_hash);
            hashes.extend(right_hashes.iter().cloned());

            // Calculate the hash of the current node
            current_hash = hash_n_subhashes::<F, D>(&hashes).to_bytes();

            // Move to the parent node
            current_node = node.parent_hashes.as_ref().map(|p| p.as_ref());
        }

        current_hash
    }
}