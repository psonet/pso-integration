# pso-nft

Domain-specific NFT types with `OwnableNFT` and `HashableNFT` trait implementations.

## NFT Types

### TributeDraft

Represents a tribute draft with settlement data and spending unit references.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `Fr` | Entity ID: `Poseidon2(owner, worldwide_day_count)` |
| `owner` | `Fr` | Ownership hash: `Poseidon5(pk_x_lo, pk_x_hi, pk_y_lo, pk_y_hi, nonce)` |
| `settlement_currency` | `Currency` | ISO 4217 currency |
| `settlement_amount_base` | `u64` | Settlement amount integer part |
| `settlement_amount_atto` | `u64` | Settlement amount fractional part |
| `worldwide_day` | `NaiveDate` | Date for worldwide day computation |
| `su_ids` | `Vec<Fr>` | Spending unit IDs included in this tribute draft |

### SpendingUnit

Represents a spending unit with record fingerprints.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `Fr` | Random unique identifier |
| `owner` | `Fr` | Ownership hash: `Poseidon5(pk_x_lo, pk_x_hi, pk_y_lo, pk_y_hi, nonce)` |
| `settlement_currency` | `Currency` | ISO 4217 currency |
| `settlement_amount_base` | `u64` | Settlement amount integer part |
| `settlement_amount_atto` | `u64` | Settlement amount fractional part |
| `worldwide_day` | `NaiveDate` | Date for worldwide day computation |
| `spending_records_fingerprints` | `Vec<Fr>` | Fingerprints of spending records |
| `amendment_records_fingerprints` | `Vec<Fr>` | Fingerprints of amendment records |

## Hash Algorithms

All hashes use Poseidon2 (arity=2, Circom-compatible) over the BN254 scalar field.

### TributeDraft ID

```text
id = Poseidon2(owner, worldwide_day_count)
```

Where `worldwide_day_count` is the number of days since 2021-01-01.

### TributeDraft Hash (HashableNFT)

```text
result = Poseidon2(id, currency_numeric)
result = Poseidon2(result, settlement_amount_base)
result = Poseidon2(result, settlement_amount_atto)
for each su_id in su_ids:
    result = Poseidon2(result, su_id)
```

Where `currency_numeric` is the ISO 4217 numeric code (e.g., EUR = 978).

### SpendingUnit Hash (HashableNFT)

```text
result = Poseidon2(id, owner)
result = Poseidon2(result, worldwide_day_count)
result = Poseidon2(result, currency_numeric)
result = Poseidon2(result, settlement_amount_base)
result = Poseidon2(result, settlement_amount_atto)
for each sr in spending_records_fingerprints:
    result = Poseidon2(result, sr)
for each ar in amendment_records_fingerprints:
    result = Poseidon2(result, ar)
```

### Ownership Hash

Both NFT types use the same ownership formula:

```text
owner = Poseidon5(pk_x_lo, pk_x_hi, pk_y_lo, pk_y_hi, nonce)
```

Where `pk_x_lo/hi` and `pk_y_lo/hi` are 128-bit limbs of the secp256k1 public key coordinates, and `nonce` is a random field element. The nonce is privacy-sensitive and is not stored in the NFT.

## Serialization

Both NFT types implement custom `Serialize` / `Deserialize` with specific field mappings:

### Field Format

| Struct field | JSON field | Format |
|-------------|-----------|--------|
| `id: Fr` | `id` | Base58 of little-endian bytes |
| `owner: Fr` | `ownership` | Base58 of little-endian bytes |
| `settlement_currency` | `settlement_currency` | ISO 4217 3-letter code (e.g., `"EUR"`) |
| `settlement_amount_base` | `settlement_base` | String (e.g., `"1234"`) |
| `settlement_amount_atto` | `settlement_atto` | String (e.g., `"0"`) |
| `worldwide_day` | `worldwide_day` | YYYYMMDD numeric (e.g., `20260305`) |
| `su_ids: Vec<Fr>` | `su_ids` | Array of Base58 strings |
| `spending_records_fingerprints` | `spending_records_fingerprints` | Array of Base58 strings |
| `amendment_records_fingerprints` | `amendment_records_fingerprints` | Array of Base58 strings |

### TributeDraft JSON Example

```json
{
  "id": "<base58>",
  "ownership": "<base58>",
  "settlement_currency": "EUR",
  "settlement_base": "1234",
  "settlement_atto": "0",
  "worldwide_day": 20260305,
  "su_ids": ["<base58>", "..."]
}
```

### SpendingUnit JSON Example

```json
{
  "id": "<base58>",
  "ownership": "<base58>",
  "settlement_currency": "EUR",
  "settlement_base": "100",
  "settlement_atto": "0",
  "worldwide_day": 20260305,
  "spending_records_fingerprints": ["<base58>", "..."],
  "amendment_records_fingerprints": ["<base58>", "..."]
}
```

## Contents

- **`TributeDraft`** -- tribute draft NFT with settlement data and spending unit IDs
- **`SpendingUnit`** -- spending unit NFT with record fingerprints
- **`Owner`** -- wrapper around secp256k1 key pair
- **`GeneratedNFTData<T>`** -- bundles an NFT with auxiliary test data (owner keys, nonce)
- **`Generated` / `OwnerGenerated`** -- traits for random test data generation
- **`generate_test_merkle_path()`** -- helper for generating random Merkle paths in tests

## Usage

```rust
use pso_nft::{Generated, TributeDraft, generate_test_merkle_path};
use pso_zk_core::{GenerateWitness, FullProofWitnessCtx};

let mut rng = rand::rngs::OsRng;
let data = TributeDraft::generate(&mut rng);
let merkle_path = generate_test_merkle_path(&mut rng);

let witness = data.nft.generate_witness(FullProofWitnessCtx {
    secret_key: &data.owner_keys.secret_key,
    nonce: data.nonce,
    merkle_path: &merkle_path,
})?;
```

## Dependencies

- `pso-zk-core` -- core traits and witness generation
- `pso-poseidon` -- Poseidon hash for entity ID and NFT hash computation
- `k256` -- secp256k1 key types
- `chrono` -- date handling for worldwide day computation
- `iso_currency` -- ISO 4217 currency types
