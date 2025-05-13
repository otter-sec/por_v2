use crate::circuits::batch_circuit::BatchCircuit;
use crate::config::*;
use crate::log_warning;
use crate::utils::logger::*;
use crate::merkle_tree::MerkleTree;
use crate::types::*;
use crate::circuits::recursive_circuit::RecursiveCircuit;
use crate::utils::utils::calculate_with_decimals;
use crate::utils::utils::{hash_account, pis_to_hash_bytes, format_timestamp};
use crate::{log_info, log_success};
use plonky2::field::types::PrimeField64;
use plonky2::plonk::config::GenericHashOut;
use plonky2::{
    plonk::circuit_data::{CircuitData, VerifierCircuitData},
    util::serialization::DefaultGateSerializer,
};

fn rebuild_root_circuit(asset_count: usize, depth: usize) -> RecursiveCircuit {
    // create the batch circuit
    let batch_circuit = BatchCircuit::new(asset_count);

    let mut inner_circuit: CircuitData<F, C, D> = batch_circuit.circuit_data;
    let mut root_circuit: Option<RecursiveCircuit> = None;

    // depth - 1 because we already calculated the batch circuit (which is a depth)
    for i in 0..depth - 1 {
        // create the recursive circuit
        let recursive_circuit = RecursiveCircuit::new(&inner_circuit, asset_count);

        // set the root circuit if last depth
        if i == depth - 2 {
            root_circuit = Some(recursive_circuit);
            break;
        }

        // get the inner circuit data
        inner_circuit = recursive_circuit.circuit_data;
    }

    root_circuit.unwrap()
}

fn print_global_information(final_proof: &FinalProof) {
    // print the global information
    log_warning!("The following information was used to generate the proof, please manually verify if they are correct:");
    log_warning!("NOTE: This is not real-time information, verify if the information is correct relative to the time of the proof generation");
    log_warning!("NOTE2: Asset prices was rounded by some decimals, verify if they are close enough to the original price");

    // iterate through the asset names and prices
    println!("======================");
    println!("Proof generation date: {}", format_timestamp(final_proof.timestamp).unwrap());
    println!("Proof generation timestamp (ms): {}", final_proof.timestamp);
    println!("Number of accounted assets: {}", final_proof.asset_names.len());

    println!("\n-----Asset prices-----");
    for (i, asset_name) in final_proof.asset_names.iter().enumerate() {
        let asset_price = calculate_with_decimals(
            final_proof.asset_prices[i].try_into().unwrap(),
            final_proof.asset_decimals[i].usdt_decimals,
        );
        println!("{}: US$ {}", asset_name, asset_price);
    }

    println!("======================");
}

fn print_reserves(final_proof: &FinalProof){
    println!();
    log_info!("The following information is the final needed asset reserves, which was validated by the Zero-Knowledge proof");
    log_warning!("NOTE: This is not real-time information, the information is relative to the time of the proof generation");
    log_warning!("NOTE2: We cannot guarantee that all users were included in the proof, but you can check if you were included by verifying the inclusion proof");

    // iterate through the asset names and final balances
    println!("======================");
    println!("Proof generation date: {}", format_timestamp(final_proof.timestamp).unwrap());
    println!("Proof generation timestamp (ms): {}", final_proof.timestamp);
    println!("Number of accounted assets: {}", final_proof.asset_names.len());

    let asset_count = final_proof.asset_names.len();
    let final_balances_offsets = RecursiveCircuit::get_final_balances_offset(asset_count);
    let asset_reserves = final_proof.proof.public_inputs[final_balances_offsets].to_vec();

    println!("\n-----Asset reserves-----");
    for (i, asset_name) in final_proof.asset_names.iter().enumerate() {
        let asset_price = calculate_with_decimals(
            asset_reserves[i].to_canonical_u64().try_into().unwrap(),
            final_proof.asset_decimals[i].balance_decimals,
        );
        println!("{}: {}", asset_name, asset_price);
    }

    println!("======================\n");
}

pub fn verify_root(final_proof: FinalProof, merkle_tree: MerkleTree) {
    let asset_count = final_proof.asset_names.len();

    // deserialize the verifier data
    let root_verifier_data: VerifierCircuitData<F, C, D> = VerifierCircuitData::from_bytes(
        final_proof.root_circuit_verifier_data.clone(),
        &DefaultGateSerializer,
    )
    .unwrap();

    // print the global information
    print_global_information(&final_proof);

    // START VERIFICATION

    // 1. rebuild the root circuit to verify if the digest is the same as specified in the proof file
    // we use depth - 2 because the last depth are the leaves (no circuit)
    log_info!("Rebuilding root circuit... This might take several minutes...");
    let built_root_circuit = rebuild_root_circuit(asset_count, final_proof.tree_depth - 1);
    log_success!("Root circuit rebuilt successfully!");

    assert!(
        built_root_circuit.circuit_data.verifier_only.circuit_digest
            == root_verifier_data.verifier_only.circuit_digest,
        "{}",
        format_error("Root circuit digest does not match the proof file").as_str(),
    );

    // 2. verify the proof
    log_info!("Verifying final proof...");
    built_root_circuit
        .circuit_data
        .verify(final_proof.proof.clone())
        .expect(format_error("Failed to verify proof").as_str());
    log_success!("Proof is valid!");

    // 3. verify the asset prices with the asset prices in the proof
    log_info!("Verifying asset prices...");
    let prices_offset = RecursiveCircuit::get_asset_prices_offset(asset_count);
    let proof_asset_prices = final_proof.proof.public_inputs[prices_offset].to_vec();
    for (i, proof_asset_price) in proof_asset_prices.iter().enumerate() {
        let asset_name = &final_proof.asset_names[i];

        assert!(
            proof_asset_price.to_canonical_u64() == final_proof.asset_prices[i],
            "{}",
            format_error(
                format!("Asset price for {} does not match the ZK proof", asset_name).as_str()
            ),
        );
    }
    log_success!("Asset prices are valid!");


    // 4. verify if the decimals are valid
    log_info!("Verifying asset decimals...");

    // we need to verify if the sum of the usdt_decimals and balance_decimals is equal for every asset
    let summed_decimals = final_proof.asset_decimals[0].balance_decimals + final_proof.asset_decimals[0].usdt_decimals;
    for (i, asset_name) in final_proof.asset_names.iter().enumerate() {
        let asset_decimals = &final_proof.asset_decimals[i];
        let usdt_decimals = asset_decimals.usdt_decimals;
        let balance_decimals = asset_decimals.balance_decimals;

        assert!(
            usdt_decimals + balance_decimals == summed_decimals,
            "{}",
            format_error(
                format!("Asset {} decimals are not valid", asset_name).as_str()
            ),
        );
    }
    
    log_success!("Asset decimals are valid!");

    // 5. verify the merkle tree root hash with the root hash in the proofs
    log_info!("Verifying merkle tree root hash...");
    let hash_offset = RecursiveCircuit::get_root_hash_offset(asset_count);
    let proof_hash = final_proof.proof.public_inputs[hash_offset].to_vec();
    let proof_hash_bytes = pis_to_hash_bytes::<F, D>(&proof_hash);

    assert!(
        merkle_tree.root.hash().clone().unwrap() == proof_hash_bytes,
        "{}",
        format_error("Merkle tree root hash does not match the proof file")
    );
    log_success!("Merkle tree root hash is valid!");

    // 6. verify the merkle tree
    log_info!("Verifying merkle tree...");
    assert!(
        merkle_tree.verify(),
        "{}",
        format_error("Merkle tree verification failed")
    );
    log_success!("Merkle tree is valid!");

    // all proofs are valid, print the reserves information
    print_reserves(&final_proof);


    log_success!("All proofs are valid!");

}

fn print_account_information(final_proof: &FinalProof, inclusion_proof: &InclusionProof) {
    // print the global information
    log_warning!("The following information was used to generate the proof, please manually verify if they are correct:");
    log_warning!("NOTE: This is not real-time information, verify if the information is correct relative to the time of the proof generation");
    log_warning!("NOTE2: Some asset balances was rounded by some decimals, verify if they are close enough to the original balance");

    // iterate through the asset names and balances
    println!("======================");
    println!("Proof generation date: {}", format_timestamp(final_proof.timestamp).unwrap());
    println!("Proof generation timestamp (ms): {}", final_proof.timestamp);
    println!("Number of accounted assets: {}", final_proof.asset_names.len());

    println!("\n-----Asset balances-----");
    for (i, asset_name) in final_proof.asset_names.iter().enumerate() {
        let asset_balance = calculate_with_decimals(
            inclusion_proof.user_balances[i].try_into().unwrap(),
            final_proof.asset_decimals[i].balance_decimals,
        );
        println!("{}: {}", asset_name, asset_balance);
    }

    println!("======================");
}

pub fn verify_user_inclusion(final_proof: FinalProof, inclusion_proof: InclusionProof) {
    let asset_count = final_proof.asset_names.len();

    // print the account information
    print_account_information(&final_proof, &inclusion_proof);

    // TODO: create a CLI flag to rebuild the circuit in user inclusions
    // 1. verify the proof

    log_info!("Verifying global proof (trusting circuit data inside the file)...");
    let root_verifier_data: VerifierCircuitData<F, C, D> = VerifierCircuitData::from_bytes(
        final_proof.root_circuit_verifier_data,
        &DefaultGateSerializer,
    )
    .unwrap();

    root_verifier_data
        .verify(final_proof.proof.clone())
        .expect(format_error("Failed to verify proof").as_str());
    log_success!("Global proof is valid!");

    // 2. verify if the user is included in the merkle tree
    log_info!("Verifying inclusion proof...");

    let hash_offset = RecursiveCircuit::get_root_hash_offset(asset_count);
    let proof_hash = final_proof.proof.public_inputs[hash_offset].to_vec();
    let proof_hash_bytes = pis_to_hash_bytes::<F, D>(&proof_hash);

    // first, calculate the node hash of the account
    let account_hash = hash_account(
        &inclusion_proof.user_balances,
        inclusion_proof.user_hash.clone(),
        inclusion_proof.nonce
    )
    .to_bytes();

    // then, calculate the root hash of the merkle tree using the inclusion proof and the calculated hash
    let calculated_root_hash = inclusion_proof.calculate_merkle_root_hash(account_hash);

    // finally, verify the calculated root hash with the proof root hash
    assert!(
        calculated_root_hash == proof_hash_bytes,
        "{}",
        format_error("Inclusion proof root hash does not match the calculated root hash")
    );

    log_success!("Inclusion proof root hash is valid! The user is included in the merkle tree!");
}
