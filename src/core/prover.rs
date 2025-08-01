use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use crate::types::*;
use crate::utils::logger::*;
use crate::{
    circuits::batch_circuit::BatchCircuit,
    circuits::circuit_registry::CircuitRegistry,
    circuits::recursive_circuit::RecursiveCircuit,
    merkle_tree::{MerkleTree, Node},
    utils::util::*,
    config::{BATCH_SIZE, RECURSIVE_SIZE, F, C, D},
    *,
};
use anyhow::Result;
use plonky2::util::serialization::DefaultGateSerializer;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::GenericHashOut;
use zstd;

fn prove_recursively(
    inner_circuit_digest: Option<HashOut<F>>,
    asset_count: usize,
    mut inner_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    mut merkle_tree: MerkleTree,
    mut merkle_depth: Option<usize>,
    circuit_registry: &mut CircuitRegistry,
    progress: &mut ProveProgress,
) -> (ProofWithPublicInputs<F, C, D>, MerkleTree) {
    // show the progress bar
    progress.print_progress_bar();

    // get the inner circuit
    let inner_circuit;
    if let Some(inner_circuit_digest) = inner_circuit_digest {
        // inner circuit is a recursive circuit if the digest is not None
        inner_circuit = &circuit_registry
            .get_recursive_circuit(inner_circuit_digest)
            .unwrap()
            .circuit
            .circuit_data;
    } else {
        // otherwise it is the batch circuit
        inner_circuit = &circuit_registry.get_batch_circuit().circuit_data;
    }

    if merkle_depth.is_none() {
        merkle_depth = Some(merkle_tree.depth - 2); // last depth are the leafs (account hashes) and second to last are batch circuit hashes
    }

    let build_circuit_time = Instant::now();
    // build the recursive circuit
    let recursive_circuit = RecursiveCircuit::new(inner_circuit, asset_count);
    progress.update_recursive_circuit_progress();

    // BENCHMARK DEBUG
    if cfg!(debug_assertions) {
        let elapsed = build_circuit_time.elapsed();
        progress.clear_bar();
        log_warning!(
            "Recursive circuit at depth {} build time: {:?}",
            merkle_depth.unwrap(),
            elapsed
        );
        progress.print_progress_bar();
    }

    // pad the inner proofs to have a multiple of RECURSIVE_SIZE
    let empty_proof = circuit_registry
        .get_empty_proof(inner_circuit.verifier_only.circuit_digest)
        .unwrap();
    pad_recursive_proofs(&mut inner_proofs, empty_proof);

    // add the padded ones to the merkle tree (in the last depth)
    let mut count = 0;
    for node in merkle_tree.get_nodes_from_depth(merkle_depth.unwrap() + 1) {
        if node.hash().is_some() {
            count += 1;
            continue; // already populated
        }

        // get the hashes elements from the proof
        let hash_offset = RecursiveCircuit::get_root_hash_offset(asset_count);
        let hash_elements = inner_proofs[count].public_inputs[hash_offset].to_vec();

        // get and set hash bytes
        let hash_bytes = pis_to_hash_bytes::<F, D>(&hash_elements);

        node.set_hash(hash_bytes.clone());

        count += 1;
    }

    // chunk inner circuits in groups of RECURSIVE_SIZE
    let subproofs = inner_proofs.chunks(RECURSIVE_SIZE);

    // prove all chunks
    let mut recursive_proofs = Vec::new();

    for chunk in subproofs {
        let timer = Instant::now();

        let proof = recursive_circuit.prove_recursive_circuit(chunk.to_vec());
        recursive_proofs.push(proof);

        if cfg!(debug_assertions) {
            // BENCHMARK DEBUG
            let elapsed = timer.elapsed();
            progress.clear_bar();
            log_warning!("Recursive proof time: {:?}", elapsed);
            progress.print_progress_bar();
        }

        // update progress
        progress.update_recursive_progress();
    }

    // add the recursive circuit to the registry (only if it is not the root circuit)
    let inner_circuit_digest = recursive_circuit.circuit_data.verifier_only.circuit_digest;
    circuit_registry.add_recursive_circuit(recursive_circuit, merkle_depth.unwrap());

    // get the nodes from the merkle tree at the current depth
    let nodes = &mut merkle_tree.get_nodes_from_depth(merkle_depth.unwrap());

    // set the nodes hashes and proofs
    let mut count = 0;
    for node in nodes {
        if count >= recursive_proofs.len() {
            break; // padding is added later (in the next recursion)
        }

        // get the hashes elements from the proof
        let hash_offset = RecursiveCircuit::get_root_hash_offset(asset_count);
        let hash_elements = recursive_proofs[count].public_inputs[hash_offset].to_vec();

        // get and set hash bytes
        let hash_bytes = pis_to_hash_bytes::<F, D>(&hash_elements);

        node.set_hash(hash_bytes.clone());

        count += 1;
    }

    if recursive_proofs.len() > 1 {
        // prove the recursive circuit with the recursive proofs
        prove_recursively(
            Some(inner_circuit_digest),
            asset_count,
            recursive_proofs,
            merkle_tree,
            Some(merkle_depth.unwrap() - 1),
            circuit_registry,
            progress,
        )
    } else {
        (recursive_proofs[0].clone(), merkle_tree)
    }
}

pub fn prove_global(mut ledger: Ledger) -> Result<(FinalProof, MerkleTree, Vec<u64>)> {
    let asset_count = ledger.asset_names.len();

    // pad accounts to have a multiple of BATCH_SIZE
    pad_accounts(
        &mut ledger.account_balances,
        &mut ledger.hashes,
        asset_count,
        BATCH_SIZE,
    )?;

    let mut progress = ProveProgress::new(ledger.account_balances.len() / BATCH_SIZE);

    // create the batch circuit
    log_info!("Creating batch circuit and proving all accounts...");
    progress.print_progress_bar();

    let batch_circuit = BatchCircuit::new(asset_count);
    let mut batch_proofs = Vec::new();

    let mut merkle_leafs = Vec::new();
    let mut account_nonces = Vec::new();

    // split the account into chunks of BATCH_SIZE and prove all chunks
    let mut count = 0;
    for chunk in ledger.account_balances.chunks(BATCH_SIZE) {
        let circuit_ref = &batch_circuit;
        let batch_time = Instant::now();

        // calculate each account hash (leafs)
        let mut leaf_hashes = Vec::new();
        for i in 0..chunk.len() {
            let userhash = ledger.hashes[count * BATCH_SIZE + i].clone();
            let balances = chunk[i].clone();

            // generate a random nonce as security against brute force attacks to discover user balances
            // MAKE SURE THIS ITERATION IS NOT PARALLELIZED, OTHERWISE THE NONCES VECTOR
            // WILL NOT BE ORDERED CORRECTLY
            let nonce = rand::random::<u64>();
            account_nonces.push(nonce);

            let hash = hash_account(&balances, userhash, nonce);
            leaf_hashes.push(hash);
        }

        let proof = circuit_ref
            .prove_batch_circuit(&ledger.asset_prices, chunk, &leaf_hashes)
            .unwrap();

        // add to the merkle tree leafs
        merkle_leafs.push(leaf_hashes);

        // update progress
        progress.update_batch_progress();

        if cfg!(debug_assertions) {
            let elapsed = batch_time.elapsed();
            progress.clear_bar();
            log_warning!("Batch {} took {:?}", count, elapsed);
            progress.print_progress_bar();
        }

        batch_proofs.push(proof);
        count += 1;
    }
    progress.clear_bar(); // need to clear the progress bar to print information
    log_success!("Proved all batch circuits successfully!");
    progress.print_progress_bar();

    // create the merkle tree leaf nodes
    let mut leaf_nodes = Vec::new();
    for leaf_hashes in merkle_leafs {
        for hash in leaf_hashes {
            let node = Node::new(Some(hash.to_bytes()));
            leaf_nodes.push(node);
        }
    }

    // create all the merkle tree structure (and populate the leafs)
    let mut merkle_tree = MerkleTree::new_from_leafs(leaf_nodes, 1, true);

    // create the circuit registry
    let batch_circuit_digest = batch_circuit.circuit_data.verifier_only.circuit_digest;
    let mut circuit_registry = CircuitRegistry::new(batch_circuit, &ledger.asset_prices);

    // populate the batch nodes
    let batch_nodes = merkle_tree.get_nodes_from_depth(merkle_tree.depth - 1);
    let mut count = 0;
    let batch_proofs_length = batch_proofs.len();

    for node in batch_nodes {
        let proof = {
            // check if it is a padding node
            if count >= batch_proofs_length {
                // get empty proof if so
                circuit_registry
                    .get_empty_proof(batch_circuit_digest)
                    .unwrap()
            } else {
                // otherwise get the proof from the batch proofs
                &batch_proofs[count]
            }
        };

        // get the hashes elements from the proof
        let hash_offset = BatchCircuit::get_root_hash_offset(asset_count);
        let hash_elements = proof.public_inputs[hash_offset.clone()].to_vec();

        // get and set hash bytes
        let hash_bytes = pis_to_hash_bytes::<F, D>(&hash_elements);
        node.set_hash(hash_bytes.clone());

        count += 1;
    }
    progress.clear_bar();
    log_success!(
        "Created merkle tree structure with {} levels (1 accounts, 1 batch, {} recursive)",
        merkle_tree.depth,
        merkle_tree.depth - 2
    );
    progress.print_progress_bar();

    // prove batch circuit recursively and populate the rest of the merkle tree
    progress.clear_bar();
    log_info!("Starting the recursive proving...");

    progress.print_progress_bar();
    let (root_proof, merkle_tree) = prove_recursively(
        None,
        asset_count,
        batch_proofs,
        merkle_tree,
        None,
        &mut circuit_registry,
        &mut progress,
    );

    progress.clear_bar();
    log_success!("Proved all recursive circuits successfully!");
    log_info!("Creating final proof...");

    // convert asset prices to F
    let asset_prices = ledger.asset_prices;

    // serialize final proof and merkle tree using serde_json
    let root_circuit_verifier_data: VerifierCircuitData<F, C, D> = circuit_registry
        .get_recursive_circuit_by_depth(1)
        .unwrap()
        .circuit
        .circuit_data
        .verifier_data()
        .clone();

    let final_proof = FinalProof {
        proof: root_proof,
        batch_size: BATCH_SIZE,
        recursive_size: RECURSIVE_SIZE,
        asset_prices: asset_prices.clone(),
        asset_names: ledger.asset_names.clone(),
        asset_decimals: ledger.asset_decimals.clone(),
        tree_depth: merkle_tree.depth,
        root_circuit_verifier_data: root_circuit_verifier_data
            .to_bytes(&DefaultGateSerializer)
            .unwrap(),
        timestamp: ledger.timestamp,
        prover_version: format!("v{}", env!("CARGO_PKG_VERSION")),
    };

    log_success!("Created final proof successfully!");

    Ok((final_proof, merkle_tree, account_nonces))
}

pub fn prove_user_inclusion(
    user_index: usize,
    user_hash: String,
    nonce: u64,
    merkle_tree: &MerkleTree,
    ledger: &Ledger,
) -> Result<InclusionProof> {
    let user_balances = ledger.account_balances[user_index].clone();

    let user_node_path = merkle_tree.get_nth_leaf_path(user_index).unwrap();

    let merkle_proof = merkle_tree.prove_inclusion(user_node_path);

    let inclusion_proof = InclusionProof {
        user_hash,
        user_balances: user_balances.clone(),
        merkle_proof,
        root_hash: merkle_tree.root.hash().clone().unwrap(),
        nonce,
    };

    Ok(inclusion_proof)
}

pub fn prove_user_inclusion_by_hash(
    user_hash: String,
    merkle_tree: &MerkleTree,
    nonces: &[u64],
    ledger: &Ledger,
) -> Result<InclusionProof> {
    // get the user index from the hash
    let user_index = ledger.hashes.iter().position(|x| *x == user_hash);
    if user_index.is_none() {
        return Err(anyhow::anyhow!("User hash not found in ledger"));
    }
    let user_index = user_index.unwrap();

    let user_nonce = nonces[user_index];

    prove_user_inclusion(user_index, user_hash, user_nonce, merkle_tree, ledger)
}

// Create inclusion proofs for all users using parallel processing
// Process hashes in batches by their first 3 characters to reduce memory usage
pub fn prove_inclusion_all_batched(
    ledger: &Ledger,
    merkle_tree: &MerkleTree,
    nonces: Vec<u64>,
) -> Result<()> {
    let total_hashes = ledger.hashes.len();
    let num_cpus = rayon::current_num_threads();

    log_info!(
        "Processing {} hashes in batches grouped by first 3 characters using {} threads...",
        total_hashes,
        num_cpus
    );

    // Group hashes by their first 3 characters (keeping original approach)
    let mut groups: HashMap<String, Vec<(usize, &String)>> = HashMap::new();
    for (index, userhash) in ledger.hashes.iter().enumerate() {
        let prefix = userhash.chars().take(3).collect::<String>();
        groups
            .entry(prefix)
            .or_insert_with(Vec::new)
            .push((index, userhash));
    }

    let total_groups = groups.len();
    let processed_groups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let processed_hashes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    log_info!(
        "Created {} groups based on first 3 characters",
        total_groups
    );

    // Create inclusion_proofs directory if it doesn't exist
    std::fs::create_dir_all("inclusion_proofs")?;

    // Process groups in parallel with optimized performance
    let processing_result: Result<()> = groups.par_iter().try_for_each(
        |(prefix, group)| -> Result<()> {
            // Process this group's hashes in parallel and collect as HashMap<hash, proof>
            let group_result: Result<HashMap<String, InclusionProof>> = group
                .par_iter()
                .map(|(index, userhash)| -> Result<(String, InclusionProof)> {
                    let inclusion_proof = prove_user_inclusion(
                        *index,
                        (*userhash).clone(),
                        nonces[*index],
                        merkle_tree,
                        ledger,
                    )?;

                    Ok(((*userhash).clone(), inclusion_proof))
                })
                .collect();

            // Handle the group result
            match group_result {
                Ok(inclusion_proofs_map) => {
                    // Write the group to file immediately as a compressed object
                    let bundle_filename =
                        format!("inclusion_proofs/inclusion_proofs_{prefix}.json.zst");
                    let bundle_json = serde_json::to_string(&inclusion_proofs_map)?;

                    // Compress the JSON data using zstd with optimal settings for speed
                    let compressed_data = zstd::encode_all(bundle_json.as_bytes(), 3)?; // Level 3 = good speed/compression balance
                    std::fs::write(&bundle_filename, compressed_data)?;

                    // Update counters atomically (much faster than mutex)
                    let completed_groups =
                        processed_groups.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    let completed_hashes = processed_hashes
                        .fetch_add(group.len(), std::sync::atomic::Ordering::Relaxed)
                        + group.len();

                    // Only log progress every 10 groups or at completion to reduce I/O overhead
                    if completed_groups % 10 == 0 || completed_groups == total_groups {
                        log_success!(
                            "Completed group '{}' ({}/{} groups, {}/{} hashes) - compressed to {}",
                            prefix,
                            completed_groups,
                            total_groups,
                            completed_hashes,
                            total_hashes,
                            bundle_filename
                        );
                    }

                    Ok(())
                }
                Err(e) => Err(e),
            }
        },
    );

    processing_result?;

    log_success!(
        "Successfully processed all {} groups with {} total inclusion proofs!",
        total_groups,
        total_hashes
    );
    Ok(())
}

// Create inclusion proofs for all users using parallel processing
pub fn prove_inclusion_all(
    ledger: &Ledger,
    merkle_tree: &MerkleTree,
    nonces: Vec<u64>,
) -> Result<()> {
    let total_hashes = ledger.hashes.len();

    // Wrap the mutable progress state in Arc<Mutex> to allow safe shared access
    // across multiple threads. Arc allows multiple threads to own a reference,
    // and Mutex ensures only one thread can access the inner data at a time.
    let progress = Arc::new(Mutex::new(ProveInclusionProgress::new(total_hashes)));

    {
        let prog = progress.lock().unwrap(); // Acquire the lock to access progress
        prog.print_progress_bar();
    } // Lock is automatically released when `prog` goes out of scope

    // Use rayon's parallel iterator `par_iter()`
    // `try_for_each` is used because the closure returns a Result.
    // If any iteration returns an Err, try_for_each stops and returns that Err.
    let processing_result: Result<()> = ledger
        .hashes
        .par_iter() // Convert the iterator into a parallel iterator
        .enumerate()
        .try_for_each(|(index, userhash)| {
            // The closure executed for each item in parallel
            let inclusion_proof =
                prove_user_inclusion(index, userhash.clone(), nonces[index], merkle_tree, ledger)?;

            let inclusion_filename = format!("inclusion_proofs/inclusion_proof_{userhash}.json");
            let inclusion_proof_json = serde_json::to_string(&inclusion_proof)?; // Propagate serialization errors
            std::fs::write(inclusion_filename, inclusion_proof_json)?; // Propagate file writing errors

            // Update the progress bar: Safely access the shared progress object
            {
                let mut prog = progress.lock().unwrap(); // Acquire the lock
                prog.update_progress(1);
            }

            Ok(())
        }); // try_for_each returns the first error encountered, or Ok(()) if all succeed

    // After all parallel tasks are complete (either finished or one errored)
    {
        let prog = progress.lock().unwrap(); // Acquire the lock
        prog.clear_bar();
    }

    processing_result
}
