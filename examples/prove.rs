use plonky2_por::{prove_from_data, get_ledger_values_from_file, prove_from_file};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Example: Generating Global Proof ===");
    
    // Method 1: Generate from file
    println!("Method 1: Generate from file");
    let (final_proof, merkle_tree, nonces) = prove_from_file("private_ledger.json", None)?;
    
    // Save to files
    std::fs::write("final_proof.json", serde_json::to_string(&final_proof)?)?;
    std::fs::write("merkle_tree.json", serde_json::to_string(&merkle_tree)?)?;
    std::fs::write("private_nonces.json", serde_json::to_string(&nonces)?)?;
    println!("Files saved: final_proof.json, merkle_tree.json, private_nonces.json");
    
    // Method 2: Generate from data
    println!("\nMethod 2: Generate from data");
    let ledger = get_ledger_values_from_file("private_ledger.json");
    let (final_proof2, merkle_tree2, nonces2) = prove_from_data(ledger, None)?;
    println!("Received data:");
    println!("  - Final proof with {} assets", final_proof2.asset_names.len());
    println!("  - Merkle tree with depth {}", merkle_tree2.depth);
    println!("  - {} nonces generated", nonces2.len());
    
    println!("\nGlobal proof generated successfully!");
    Ok(())
} 