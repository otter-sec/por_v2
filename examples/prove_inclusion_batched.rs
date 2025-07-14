use plonky2_por::{prove_inclusion_batched_from_files, prove_inclusion_batched_from_data, get_ledger_values_from_file};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Example: Generating All Users Inclusion Proofs (Batched) ===");
    
    // Method 1: Generate from files
    println!("Method 1: Generate from files");
    prove_inclusion_batched_from_files(
        "merkle_tree.json",
        "final_proof.json",
        "private_nonces.json",
        "private_ledger.json", 
    )?;
    println!("Batched inclusion proofs generated and saved to files!");
    
    // Method 2: Generate from data
    println!("\nMethod 2: Generate from data");
    let merkle_tree: plonky2_por::MerkleTree = serde_json::from_str(&std::fs::read_to_string("merkle_tree.json")?)?;
    let final_proof: plonky2_por::FinalProof = serde_json::from_str(&std::fs::read_to_string("final_proof.json")?)?;
    let nonces: Vec<u64> = serde_json::from_str(&std::fs::read_to_string("private_nonces.json")?)?;
    let ledger = get_ledger_values_from_file("private_ledger.json");
    
    prove_inclusion_batched_from_data(&merkle_tree, &final_proof, nonces, &ledger)?;
    println!("Batched inclusion proofs generated from data!");
    
    println!("\nSuccessfully generated batched inclusion proofs for all users!");
    Ok(())
} 