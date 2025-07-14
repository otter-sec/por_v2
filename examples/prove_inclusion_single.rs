use plonky2_por::{prove_inclusion_from_data, get_ledger_values_from_file, prove_inclusion_from_files};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Example: Generating Single User Inclusion Proof ===");
    
    // Method 1: Generate from files
    println!("Method 1: Generate from files");
    let inclusion_proof = prove_inclusion_from_files(
        "2f84035610deb9378036cb7a5498b885486cf8e0acfde755081b3484bcff8eed",
        "merkle_tree.json",
        "final_proof.json",
        "private_nonces.json", 
        "private_ledger.json",
        None
    )?;
    println!("Inclusion proof generated and saved to file!");
    
    // Method 2: Generate from data
    println!("\nMethod 2: Generate from data");
    let merkle_tree: plonky2_por::MerkleTree = serde_json::from_str(&std::fs::read_to_string("merkle_tree.json")?)?;
    let final_proof: plonky2_por::FinalProof = serde_json::from_str(&std::fs::read_to_string("final_proof.json")?)?;
    let nonces: Vec<u64> = serde_json::from_str(&std::fs::read_to_string("private_nonces.json")?)?;
    let ledger = get_ledger_values_from_file("private_ledger.json");
    
    let inclusion_proof2 = prove_inclusion_from_data(
        "2f84035610deb9378036cb7a5498b885486cf8e0acfde755081b3484bcff8eed",
        &merkle_tree,
        &final_proof,
        &nonces,
        &ledger,
        None
    )?;
    println!("Inclusion proof generated from data!");
    println!("User hash: {}", inclusion_proof2.user_hash);
    println!("User balances: {:?}", inclusion_proof2.user_balances);
    
    println!("\nInclusion proof generated successfully for user!");
    Ok(())
}