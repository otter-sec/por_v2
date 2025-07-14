# OtterSec PoRv2

This repository implements a zero-knowledge proof of reserve algorithm to prove user balances sum. It uses [Plonky2](https://github.com/0xPolygonZero/plonky2) recursive SNARK zk algorithm to add efficiency to the proving system.

## Installation

## Usage

```bash
Usage: plonky2_por <COMMAND>

Commands:
  prove             Generates a global proof
  prove-inclusion   Generates an inclusion proof for a specific user
  verify            Verifies the global proof
  verify-inclusion  Verifies an inclusion proof
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Subcommands

There are 4 subcommands implemented in this code:
- prove --> Create zk proofs for non-negativity and total balance of all assets
- verify --> Verify the proofs of non-negativity and total balance of all assets
- prove-inclusion --> Create a merkle inclusion proof of a certain user
- verify-inclusion --> Verify merkle inclusion proofs (users can verify if they were included in the PoR)

### Prove

This command should be executed by the CEX since it is the only party that have all the needed information for proving user balances.

#### Input
To execute it, first you need to generate the input file (`private_ledger.json`), which has the following format:

```json
{
    "timestamp": 1746488437000, 
    "assets": {
        "ETH": {
            "usdt_decimals": 2, 
            "balance_decimals": 4, 
            "price": 200040
        },
        [...]
    }, 
    "accounts": {
        "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b": {
            "BTC": 534054,
            "ETH": 4761,
            "XRP": 772994,
            "LTC": 961378,
            "BCH": 854524,
            "EOS": 634571,
            "SOL": 550540
        },
        [...]
    }
}
```

**Assets**
We have a limitation in the circuit that all the numbers are represented in 64-bit integers (actually it must be inside the Goldilocks Field). That means that the final user USD balance and the final asset balances must be represented in 64-bit integers. This is why we must round the asset prices and asset balances. The rounding can be made different depending on the asset (e.g: You can't round BTC to only 2 balance decimals --> 0.01 BTC is substantial amount of money), this is why you must provide the `usdt_decimals` and the `balance_decimals` for each asset:

- `usdt_decimals` --> decimals of the USD price of the asset (e.g: $200040 and 2 decimals --> $2000.40)
- `balance_decimals` --> decimals of the asset user balance (e.g 4761 ETH and 4 decimals --> 0.4761 ETH)

> WARNING: The sum of `usdt_decimals` and `balance_decimals` must be the same for all assets. Otherwise we will be comparing different USD decimals in the circuit and the non-negativity proof will be wrong. (e.g: `usdt_decimals = 2`; `balance_decimals = 4`; all `usdt_decimals + balance_decimals` must be 6)

Asset prices are used to verify non-negativity of each user. We verify if the USD balance of the user is not negative.

**Accounts**

`accounts` field contains the asset balance of all users. It is organized by the user hash (user identifier hashed in any algorithm --> e.g sha256(username)), so the format is:

```json
{
    "<user_hash>": {
        "<asset1>": "<user_asset1_balance>",
        "<asset2>": "<user_asset2_balance>",
        [...]
    }
}
```

The balance should follow the decimals standard explained above (e.g: 12000 BTC and 4 decimals --> 1.2000 BTC). Also, it is possible for the asset balance be negative (when user is borrowing that asset or whatever), however, the final USD balance must be positive (ensured by non-negativity proof).


#### Output

The `prove` subcommand will generate the final proof and the merkle tree necessary for verifications and inclusion proving. The output files are:

- final_proof.json --> zk recursive final proof
- merkle_tree.json --> the merkle tree
- private_nonces.json --> nonces that were used during the hash of the merkle tree leaves to prevent brute force attacks

> WARNING: DO NOT DISCLOSE PRIVATE_NONCES.JSON PUBLICLY SINCE IT IS A MEASURE OF DEFENSE AGAINST BRUTE FORCE AND WILL BE BYPASSABLE IF PUBLICLY AVAILABLE

### Verify

The `verify` subcommand validates the global proof, which is the combination of the merkle tree and the final zk proof. The verification follow these steps:

1. Rebuild the root recursive circuit 
2. Verify the final proof using the rebuilt circuit
3. Verify the asset prices (if they are the same as used to generate the proof)
4. Verify if the decimals are valid (if the sum of usdt_decimals and balance_decimals are the same for all assets)
5. Verify the merkle tree root hash with the hash inside the final proof (in other words, checks if that merkle tree belongs to that zk proof)
6. Verify the entire merkle tree (if the parent nodes are the hashes of their childs)

To execute it, the global proof files (`merkle_tree.json` and `final_proof.json`) must be in the current directory. Then, it is simple as executing `./plonky2_por verify`.

### Prove inclusion

The `prove-inclusion` subcommand should be run by the CEX party since it requires the `private_ledger.json` file in the current directory. This command can be run in two different ways:

1. Proving inclusion of a certain user --> it can be used to generate the proof on-demand.
2. Proving inclusion of all users --> it can be used to generate the proofs all-at-once and only serve static files to the user

This subcommand generates an inclusion proof of the specified users. It bundles all the necessary information to verify if the user were included in the merkle tree: all sibling and parent hashes + account balances (used to calculate the leaf hash).

**Proving on-demand**

Since the `private_ledger.json` and `merkle_tree.json` are usually big files, it is not optimal to deserialize it every time we need to prove a user inclusion. So we have two methods to prove users on-demand:

1. The optimal way --> creates a server based on a UNIX socket, receives the user hashes via this socket and generates the proof. Since it is a server, it deserializes the ledger and the merkle tree once and keep them in memory.
2. The easy way --> reads and deserializes the merkle tree and the ledger every time that you need to prove an inlcusion. This may be usable when the ledger/merkle tree is not big and/or during testing.

To start the server you just need to run `./plonky2_por prove-inclusion -d`, that will run the server in daemon mode.

To prove inclusion of a specific user, you can use the `--userhash <hash>` flag. It will check if the prover server is running and send the hash to it, which will generate the proof (method 1). If it is not running, it will deserialize the files, find the user by its hash and generate the proof (method 2).

> NOTE: The server method will only work in UNIX-like systems. It is not available for Windows or other OS family.

**Proving all users**

To prove all users at one-shot, simply put the `--all` flag. It will create all proofs inside the `inclusion_proofs/` directory, which may consume a lot of disk space depending on the amount of users. If you want a less-disk consuming approach you can use `--all-batched` flag. It will group users by the first 3 chars of the `userhash` and bundle all the proofs of a group into a compressed file.


> **WARNING: THE INCLUSION PROOF SHOULD NOT BE PUBLIC. EACH PROOF MUST BE SHARED WITH THE RELATED USER ONLY. THE FILE CONTAINS THE USER ACCOUNT BALANCE INFORMATION, WHICH MUST BE KEPT SECRET.**

To run this command, the `merkle_tree.json`, `final_proof.json`, `private_ledger.json` and `private_nonces.json` must be in the current directory.

### Verify inclusion

This subcommand searches for all files in the current directory with the `inclusion_proof_*.json` pattern and verifies the inclusion proof. The verification steps are the following:

1. Verify the final proof
2. Verify if the user is included in the merkle tree (calculates the merkle tree root hash and verify if it is the same as the one in the verified proof)

> WARNING: It doesn't rebuild the root zk circuit for improving performance. It simply trusts the circuit provided in the `final_proof.json` file. If you want to fully verificate it, consider running the `verify` subcommand also. 

Note that the `final_proof.json` file must be present in the current directory since it is used to verify merkle tree root hash validity.

## Library API

This crate can be used as a library to integrate zero-knowledge proof of reserve functionality into your applications. The library provides both file-based and data-based APIs for maximum flexibility.

### Core Functions

#### Global Proof Generation

**`prove_from_file(ledger_file_path: &str, output_dir: Option<&str>) -> Result<(FinalProof, MerkleTree, Vec<u64>)>`**

Generates a global proof from a JSON file containing the private ledger data.

```rust
use plonky2_por::prove_from_file;

let (final_proof, merkle_tree, account_nonces) = prove_from_file(
    "private_ledger.json",
    Some("output/")
)?;
```

If None is passed to `output_dir`, no files are created and the returned data should be handled manually.

**`prove_from_data(ledger: Ledger, output_dir: Option<&str>) -> Result<(FinalProof, MerkleTree, Vec<u64>)>`**

Generates a global proof from already-deserialized `Ledger` data.

```rust
use plonky2_por::{prove_from_data, Ledger};

let ledger_data = Ledger { /* ... */ };
let (final_proof, merkle_tree, account_nonces) = prove_from_data(
    ledger_data,
    Some("output/")
)?;
```

If None is passed to `output_dir`, no files are created and the returned data should be handled manually.

#### Single User Inclusion Proof

**`prove_inclusion_from_files(user_hash: &str, merkle_tree_file: &str, final_proof_file: &str, nonces_file: &str, ledger_file: &str, output_file: Option<&str>) -> Result<InclusionProof>`**

Generates an inclusion proof for a specific user from files on disk.

```rust
use plonky2_por::prove_inclusion_from_files;

let inclusion_proof = prove_inclusion_from_files(
    "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
    "merkle_tree.json",
    "final_proof.json",
    "private_nonces.json",
    "private_ledger.json",
    Some("inclusion_proof.json")
)?;
```

If None is passed to `output_file`, no file is created and the returned data should be handled manually.

**`prove_inclusion_from_data(user_hash: &str, merkle_tree: &MerkleTree, final_proof: &FinalProof, nonces: &[u64], ledger: &Ledger, output_file: Option<&str>) -> Result<InclusionProof>`**

Generates an inclusion proof for a specific user from already-deserialized data.

```rust
use plonky2_por::{prove_inclusion_from_data, MerkleTree, FinalProof, Ledger};

let inclusion_proof = prove_inclusion_from_data(
    "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
    &merkle_tree,
    &final_proof,
    &nonces,
    &ledger,
    Some("inclusion_proof.json")
)?;
```

If None is passed to `output_file`, no file is created and the returned data should be handled manually.

#### Batched Inclusion Proofs

**`prove_inclusion_batched_from_files(merkle_tree_file: &str, final_proof_file: &str, nonces_file: &str, ledger_file: &str) -> Result<()>`**

Generates zstd-compressed inclusion proofs for all users from files on disk. The output files are stored in `./inclusion_proofs` directory.

```rust
use plonky2_por::prove_inclusion_batched_from_files;

prove_inclusion_batched_from_files(
    "merkle_tree.json",
    "final_proof.json",
    "private_nonces.json",
    "private_ledger.json"
)?;
```

**`prove_inclusion_batched_from_data(merkle_tree: &MerkleTree, final_proof: &FinalProof, nonces: Vec<u64>, ledger: &Ledger) -> Result<()>`**

Generates inclusion proofs for all users using zstd compression from already-deserialized data. The output files are stored in `./inclusion_proofs` directory.

```rust
use plonky2_por::prove_inclusion_batched_from_data;

prove_inclusion_batched_from_data(
    &merkle_tree,
    &final_proof,
    nonces,
    &ledger
)?;
```

### Data Structures

The library uses several key data structures:

- **`Ledger`**: Contains timestamp, assets configuration, and user account balances
- **`FinalProof`**: The zero-knowledge proof data
- **`MerkleTree`**: The merkle tree structure for inclusion proofs
- **`InclusionProof`**: Individual user inclusion proof data

### Error Handling

All functions return `Result<T, anyhow::Error>` to handle various error conditions including:
- File I/O errors
- JSON parsing errors
- Cryptographic errors
- Invalid data format errors

### Examples

See the `examples/` directory for complete working examples:
- `examples/global_proof.rs` - Global proof generation
- `examples/single_inclusion.rs` - Single user inclusion proof
- `examples/batched_inclusion.rs` - Batched inclusion proofs
- `examples/overview.rs` - Combined usage example

## Building

The file `config.rs` contains some configurations that can be changed to improve performance and/or make proof sizes smaller. The `BATCH_SIZE` and `RECURSIVE_SIZE` constants are the most important fields since it defines how deep will be the merkle tree and how many subproofs each recursive circuit has to prove (which is the most time-consuming operation).

> WARNING: Proceed with caution when changing configurations. Make sure you understand what you are doing.

### Compiling the code

Plonky2 uses some hardware acceleration features that are only available in the nightly build of rust. To build the code, you should change the rust version to nightly and then build the code:

```bash
rustup override set nightly
cargo build --release
```

## Benchmark

We ran benchmark tests with a ledger containing 750k users and 53 assets using this configuration in `config.rs`:

```rs
pub const BATCH_SIZE: usize = 512;
pub const RECURSIVE_SIZE: usize = 8;
```

**Execution timing**

The tests were executed in a Mac M3 Pro (12 cores) and here are the results:

- `prove` --> took 470s (~8 minutes)
- `prove-inclusion --all-batched` --> took 13s
- `verify` --> took 6s with low RAM consumption
- `verify-inclusion` --> took 20ms with low RAM consumption

**Proof sizes**

After proving global proof and all user inclusion proofs, these are the proof file sizes:

- `final_proof.json` --> 448KB
- `merkle_tree.json` --> 52MB
- `private_nonces.json` --> 15MB
- Single inclusion proof --> 52KB
- All inclusion proofs (batched/compressed) --> 335MB


> NOTE: since storing all inclusion proofs is disk-consuming, another option is to create user inclusion proofs on-demand using --userhash CLI parameter in `prove-inclusion` subcommand.

## Testing

We provide a `generate_test.py` script to generate a testing `private_ledger.json` file. You can configure the number of users and assets that will be generated and then run the script. 

Once the file is generated, you can simply put that file in the same directory of the executable and run `./plonky2_por prove`.

## Security

If you find any security bugs or suggestions for enhancing security/privacy, send an e-mail with your report to contact@osec.io!
