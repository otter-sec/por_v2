use crate::config::*;
use anyhow::Result;
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::{
        config::{GenericHashOut, Hasher},
        proof::ProofWithPublicInputs,
    },
};

// NEED TO ADD PADDING TO RECURSIVE TREES

// pad accounts to have a multiple of BATCH_SIZE
pub fn pad_accounts(
    accounts: &mut Vec<Vec<i64>>,
    hashes: &mut Vec<String>,
    asset_count: usize,
    batch_size: usize,
) -> Result<()> {
    let mut padded_accounts = Vec::new();
    let mut padded_hashes = Vec::new();

    let hash_nibbles = hashes[0].len();

    // only pad if the number of accounts is not a multiple of batch_size
    if accounts.len() % batch_size != 0 {
        let padding = batch_size - (accounts.len() % batch_size);
        for _ in 0..padding {
            padded_accounts.push(vec![0; asset_count]); // pad with zero balances
            padded_hashes.push("0".repeat(hash_nibbles)); // pad with zero hash
        }
    }

    accounts.extend(padded_accounts);
    hashes.extend(padded_hashes);

    Ok(())
}

pub fn pad_recursive_proofs(
    proofs: &mut Vec<ProofWithPublicInputs<GoldilocksField, C, D>>,
    empty_proof: &ProofWithPublicInputs<GoldilocksField, C, D>,
) {
    // only pad if the number of proofs is not a multiple of RECURSIVE_SIZE
    if proofs.len() % RECURSIVE_SIZE != 0 {
        let padding = RECURSIVE_SIZE - (proofs.len() % RECURSIVE_SIZE);
        for _ in 0..padding {
            proofs.push(empty_proof.clone());
        }
    }
}

// hash n subhashes
pub fn hash_n_subhashes<F: RichField + Extendable<D>, const D: usize>(
    hashes: &[Vec<u8>],
) -> HashOut<F> {
    // convert the u8 vector to HashOut then to GoldilocksField
    let hashout_inputs = hashes
        .iter()
        .map(|h| HashOut::<F>::from_bytes(h))
        .collect::<Vec<HashOut<F>>>();

    let inputs: Vec<F> = hashout_inputs
        .iter()
        .flat_map(|h| h.elements.to_vec())
        .collect();

    PoseidonHash::hash_no_pad(inputs.as_slice())
}

// hash account balances and userhash
pub fn hash_account(balances: &Vec<i64>, userhash: String, nonce: u64) -> HashOut<GoldilocksField> {
    // convert everything to GoldilocksField
    let mut hash_input = Vec::new();
    for balance in balances {
        hash_input.push(GoldilocksField::from_noncanonical_i64(*balance));
    }

    // convert hex hash to vec of u64
    let mut hash_input_hex = Vec::new();
    for i in (0..userhash.len()).step_by(16) {
        let hex = &userhash[i..i + 16];
        let num = u64::from_str_radix(hex, 16).unwrap();
        hash_input_hex.push(GoldilocksField::from_canonical_u64(num));
    }

    // convert nonce to GoldilocksField
    let nonce_field = GoldilocksField::from_canonical_u64(nonce);
    hash_input.push(nonce_field);

    PoseidonHash::hash_no_pad(hash_input.as_slice())
}

// convert HashOut elements to hash bytes
pub fn pis_to_hash_bytes<F: RichField + Extendable<D>, const D: usize>(pis: &[F]) -> Vec<u8> {
    HashOut::from_partial(pis).to_bytes()
}

pub fn calculate_with_decimals(value: i64, decimals: i64) -> BigDecimal {
    BigDecimal::new(value.into(), decimals)
}

pub fn format_timestamp(timestamp_milliseconds: u64) -> Result<String, &'static str> {
    // Convert u64 to i64. chrono::DateTime::from_timestamp_opt requires i64.
    let timestamp_i64: i64 = timestamp_milliseconds
        .try_into()
        .map_err(|_| "Timestamp value out of range for i64")?;

    // Create a NaiveDateTime object from the timestamp (seconds) assuming UTC.
    // `from_timestamp_opt` returns None if the timestamp is out of the representable range.
    let naive_datetime =
        DateTime::from_timestamp_millis(timestamp_i64).ok_or("Invalid timestamp value")?;

    // Convert the NaiveDateTime (UTC) to a DateTime<Utc>
    let datetime_utc = DateTime::<Utc>::from_naive_utc_and_offset(naive_datetime.naive_utc(), Utc);

    // Format the local DateTime into a human-readable string.
    // Format codes: %Y=Year, %m=Month, %d=Day, %H=Hour(24h), %M=Minute, %S=Second, %Z=Timezone offset
    let formatted_string = datetime_utc.format("%Y-%m-%d %H:%M:%S %Z").to_string();

    Ok(formatted_string)
}
