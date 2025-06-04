pub mod circuits;
pub mod config;
pub mod core;
pub mod custom_serializer;
pub mod merkle_tree;
pub mod types;
pub mod utils;

use anyhow::{Context, Result};
use circuits::recursive_circuit::RecursiveCircuit;
use clap::{Args, Parser, Subcommand};
use config::*;
use core::prover::*;
use core::verifier::{verify_root, verify_user_inclusion};
use merkle_tree::*;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::proof::ProofWithPublicInputs;
use regex::Regex;
use std::fs::File;
use std::time::Instant;
use types::*;
use utils::logger::*;

#[cfg(target_family = "unix")]
use core::server::*;
#[cfg(target_family = "unix")]
use daemonize::Daemonize;
#[cfg(target_family = "unix")]
use signal_hook::{
    consts::{SIGHUP, SIGINT},
    iterator::Signals,
};

#[cfg(target_family = "unix")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn get_ledger_values_from_file(filename: &str) -> Ledger {
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

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Generates a global proof
    Prove,
    /// Generates an inclusion proof for a specific user or for all users
    ProveInclusion(ProveInclusionArgs),
    /// Verifies the global proof
    Verify,
    /// Verifies an inclusion proof
    VerifyInclusion,
}

// Define a separate struct for the ProveInclusion subcommand arguments
#[derive(Args, Debug, Clone)]
#[clap(group = clap::ArgGroup::new("inclusion_target").required(true))]
struct ProveInclusionArgs {
    // daemonize the process to be a server
    #[clap(long, short, group = "inclusion_target")]
    daemon: bool,

    /// The hash of the user to prove inclusion for
    #[clap(long, group = "inclusion_target")]
    userhash: Option<String>,

    /// Prove inclusion for all users
    #[clap(long, group = "inclusion_target")]
    all: bool,

    /// Prove inclusion for all users in batches (grouped by first 3 characters)
    #[clap(long, group = "inclusion_target")]
    all_batched: bool,
}

fn assert_config(final_proof: &FinalProof) {
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
}

fn main() -> Result<()> {
    env_logger::init();
    let global_timer = Instant::now();

    let cli = Cli::parse();

    print_header();

    match &cli.command {
        Commands::Prove => {
            log_info!("Reading and deserializing ledger...");
            let ledger = get_ledger_values_from_file("private_ledger.json");
            log_success!("Ledger read successfully!");

            log_info!(
                "Starting to prove reserves... This might take some hours depending on the ledger size..."
            );
            prove_global(ledger)?;
        }
        Commands::ProveInclusion(args) => {
            // create the inclusion_proofs directory
            let _ = std::fs::create_dir_all("inclusion_proofs");

            // if userhash and socket exists, just send the hash to the server (only on unix)
            #[cfg(target_family = "unix")]
            if args.userhash.is_some() && std::fs::exists(SOCKET_PATH)? {
                log_info!("Prover server is running, sending hash to the server...");
                send_hash_to_server(args.userhash.as_ref().unwrap())?;

                return Ok(());
            }

            // otherwise, we will need to deserialize all files
            log_info!(
                "Reading and deserializing proof, merkle tree, ledger and nonces... This might take a while"
            );
            let merkle_tree_file = std::fs::read_to_string("merkle_tree.json")?;
            let merkle_tree: MerkleTree = serde_json::from_str(&merkle_tree_file)?;

            let final_proof_file = std::fs::read_to_string("final_proof.json")?;
            let final_proof: FinalProof = serde_json::from_str(&final_proof_file)?;

            // Assert the configuration of the final proof
            assert_config(&final_proof);

            // deserialize nonces
            let nonces_file = std::fs::read_to_string("private_nonces.json")?;
            let nonces: Vec<u64> = serde_json::from_str(&nonces_file)?;

            let ledger = get_ledger_values_from_file("private_ledger.json");
            log_success!("Reading and deserializing completed!");

            // create the server if daemon is true (only on unix)
            #[cfg(target_family = "unix")]
            if args.daemon {
                let stdout = File::create("/tmp/por_daemon.out").unwrap();
                let stderr = File::create("/tmp/por_daemon.err").unwrap();

                let cwd = std::env::current_dir().unwrap();

                let daemonize = Daemonize::new()
                    .pid_file("/tmp/por.pid") // Every method except `new` and `start`
                    .working_directory(cwd) // Set the working directory
                    .stdout(stdout) // Redirect stdout
                    .stderr(stderr); // Redirect stderr

                log_info!("Starting the prover server in the background...");
                match daemonize.start() {
                    Ok(_) => {
                        let mut signals = Signals::new([SIGINT, SIGHUP])?;

                        std::thread::spawn(move || {
                            for sig in signals.forever() {
                                // remove the socket and pid file if the process is killed
                                if sig == SIGINT || sig == SIGHUP {
                                    log_info!("Daemon process killed, removing socket file...");
                                    let _ = std::fs::remove_file(SOCKET_PATH);
                                    let _ = std::fs::remove_file("/tmp/por.pid");

                                    // Exit the process
                                    std::process::exit(0);
                                }
                            }
                        });

                        create_local_server(merkle_tree, nonces, ledger)?
                    }
                    Err(_) => log_error!(
                        "Error while starting daemon process. Check if there are other process already being executed."
                    ),
                }

                return Ok(());
            }

            if args.all {
                log_info!("Proving inclusion for all users...");
                prove_inclusion_all(&ledger, &merkle_tree, nonces)?;
                log_success!("Successfully generated inclusion proofs for all users!");
            } else if args.all_batched {
                log_info!("Proving inclusion for all users in batches...");
                prove_inclusion_all_batched(&ledger, &merkle_tree, nonces)?;
                log_success!("Successfully generated batched inclusion proofs for all users!");
            } else if let Some(userhash) = &args.userhash {
                log_info!("Proving inclusion for user hash: {}", userhash);
                let inclusion_proof =
                    prove_user_inclusion_by_hash(userhash.clone(), &merkle_tree, &nonces, &ledger)?;

                let inclusion_filename =
                    format!("inclusion_proofs/inclusion_proof_{userhash}.json");
                let inclusion_proof_json = serde_json::to_string(&inclusion_proof)?;
                std::fs::write(inclusion_filename, inclusion_proof_json)?;
            } else {
                log_error!("No user hash provided for inclusion proof.");
                return Ok(());
            }
        }
        Commands::Verify => {
            log_info!("Verifying the proof of reserves...");
            let final_proof_file = std::fs::read_to_string("final_proof.json")?;
            let final_proof: FinalProof = serde_json::from_str(&final_proof_file)?;

            let merkle_tree_file = std::fs::read_to_string("merkle_tree.json")?;
            let merkle_tree: MerkleTree = serde_json::from_str(&merkle_tree_file)?;

            assert_config(&final_proof);

            verify_root(final_proof, merkle_tree);
        }
        Commands::VerifyInclusion => {
            println!("Verifying inclusion proofs with a predefined pattern...");
            let final_proof_file = std::fs::read_to_string("final_proof.json")
                .context(format_error("Failed to read final_proof.json"))?;
            let final_proof: FinalProof = serde_json::from_str(&final_proof_file)
                .context(format_error("Failed to deserialize final_proof.json"))?;

            assert_config(&final_proof);

            let pattern = r"^inclusion_proof_.*\.json$";
            let re = Regex::new(pattern).context(format_error("Failed to create regex"))?;

            let entries =
                std::fs::read_dir(".").context(format_error("Failed to read current directory"))?;

            // iterate over the entries in the current directory
            for entry in entries.flatten() {
                // check the filename against the regex
                let filename = entry.file_name().to_string_lossy().to_string();

                if re.is_match(&filename) {
                    log_info!("Found and verifying inclusion proof file: {}", filename);

                    // Read and deserialize the inclusion proof file
                    let inclusion_proof_file: String = std::fs::read_to_string(entry.path())
                        .context(format_error(&format!(
                            "Failed to read inclusion proof file: {filename}"
                        )))?;

                    let inclusion_proof: InclusionProof =
                        serde_json::from_str(&inclusion_proof_file).context(format_error(
                            &format!("Failed to deserialize inclusion proof file: {filename}"),
                        ))?;

                    // Verify the inclusion proof
                    verify_user_inclusion(final_proof.clone(), inclusion_proof);

                    log_success!(
                        "Successfully verified inclusion proof for file: {}",
                        filename
                    );
                }
            }
            println!();
            log_success!("All inclusion proofs are valid!");
        }
    }

    log_success!("Finished in {:?}!", global_timer.elapsed());

    Ok(())
}
