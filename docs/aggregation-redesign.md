# SU-Ownership Aggregation: Spec-Correct Redesign

**Status:** open. Captures the architectural correction after review
against `Privacy-Preserving L2 Architecture.pdf` (rev as of session
2026-05). Implementation lands in stages across three repos.

## Why the current aggregation circuit is wrong

The current `pso-circuit-core::aggregation::verify` (in
`psonet/pso-zk-circuits`) checks:

```text
for i in 0..N:
    assert Poseidon5(pk_x, pk_y, nonces[i]) == derived_owners[i]
assert ECDSA_verify((pk_x, pk_y), signature, binding_hash)
```

— one keypair signing across all N SUs, one signature over a
`(sender, tdid, chainid)` binding hash.

The spec (§4.1, §4.2, App. A) requires per-SU shared keys:

```text
shared_sk_i = HKDF(ECDH(consent_sk, pk_cu_i).x, su_nonce_i) mod q
shared_pk_i = shared_sk_i · G
owner_i     = Poseidon5(shared_pk_x_i, shared_pk_y_i, su_nonce_i)
signature_i = ECDSA(Poseidon(su_hash_i || su_nonce_i), shared_sk_i)
```

— each SU has its own ephemeral keypair derived per-SU; each SU has
its own signature over `Poseidon(su_hash_i || su_nonce_i)`.

The current circuit's "one key, N nonces" shape cannot be reshaped to
match this. It must be replaced.

## Corrected architecture

### Per-SU ownership proof (leaf)

One Noir circuit, called once per SU. Matches §4.2:

```text
Private inputs:
  shared_pk_x_bytes : [u8; 32]      // x-coord of per-SU shared_pk
  shared_pk_y_bytes : [u8; 32]      // y-coord of per-SU shared_pk
  signature         : [u8; 64]      // ECDSA over Poseidon(su_hash || su_nonce)
  su_nonce          : Field          // per-SU nonce

Public inputs:
  owner             : Field          // Poseidon5(shared_pk_x, shared_pk_y, su_nonce)
  su_hash           : Field          // off-chain-computed SU entity hash

Constraints:
  computed_owner = Poseidon5(decompose(shared_pk_x), decompose(shared_pk_y), su_nonce)
  pre_hash       = Poseidon2(su_hash, su_nonce)
  assert computed_owner == owner
  assert ecdsa_verify((shared_pk_x, shared_pk_y), signature, pre_hash.to_le_bytes())
```

The signing key (`shared_sk`) is never exposed to the circuit — only
the public key, the signature, and the nonce. The circuit re-derives
the owner from the public key and asserts equality with the public
input. The on-chain verifier supplies `owner` from the SU's on-chain
`derivedOwner` field and reconstructs `su_hash` from the rest of the
SU data.

### Recursive aggregation proof (fold)

A separate Noir circuit, called once per aggregation, that verifies N
inner SU-ownership proofs in-circuit using
`std::verify_proof` / `verify_honk_proof_non_zk`:

```text
Private inputs:
  proofs        : [Proof; N]         // N inner SU-ownership proofs
  // verification_key + key_hash are compile-time constants

Public inputs:
  per_su_public_inputs : pub [(Field, Field); N]   // [(owner_i, su_hash_i)] for i in 0..N
```

Inner-VK is pinned at compile time because every SU ownership proof
uses the same circuit. Padding works the same way as the current
implementation: unused slots set `owner_i == 0` (which the inner
circuit will refuse to verify because Poseidon5 collision with zero
is negligible) — wait, in this design padding is harder. Two options:

1. **Strict tier sizing.** Wallet pads to the smallest tier ≥ N by
   re-proving a "null SU" via the inner circuit with sentinel inputs.
   Cost: an extra prove per padding slot.
2. **Tier-exact aggregation.** Don't pad — ship exact tiers
   1, 2, 3, 4, 5, 6, 8, 10, 16, 32, 64. Wallet picks an exact match
   if available; otherwise rounds up and pads. Cost: more compiled
   circuits, smaller padding waste.

Pick (2) — the canonical-VK table is already a fixed set; adding a
few more entries is cheaper than per-aggregation padding proofs.

The recursive proof's public inputs (per-slot owner + su_hash pairs)
are what the on-chain contract reconstructs and matches.

### TD ownership proof (post-mint, off-chain artifact for L1 redemption)

Per the spec, the wallet **also** generates an ownership proof for
the TributeDraft itself using a freshly-generated keypair (NOT the
consent key). But this proof is **not** consumed by `TributeDraft.submit`
on L2 — it's produced after the TD is minted and retained by the
wallet for later use when preparing an inclusion proof for L1
redemption.

The circuit shape is identical to the SU ownership circuit (one
keypair, one signature, one nonce, one data hash), just with:

- `td_hash` instead of `su_hash`
- `tribute_draft_nonce` instead of `su_nonce`
- The signature is over `Poseidon(td_hash || tribute_draft_nonce)`
  signed with the TD-specific keypair

Same circuit, different inputs — reuse the ownership circuit for both
layers.

This artifact is what was loosely called "FullProof" in the
pre-redesign code. It stays as a wallet-local file that gets fed into
the L1 inclusion-proof flow later. **It does not flow through the L2
submit path.**

## On-chain shape (no contract signature change)

`TributeDraft.submit` keeps essentially the existing shape — only the
**meaning** of `aggregationProof` changes (it's now the recursive
proof folding N inner SU ownership proofs).

```solidity
function submit(
    uint256 tributeDraftId,
    bytes32 derivedOwner,
    uint256[] calldata suIds,
    bytes calldata aggregationProof    // now the recursive proof
) external;
```

The contract:

1. Loads each SU on-chain by id, reconstructs `su_hash_i` from its
   fields via `pso_protocol::nft::compute_spending_unit_hash`.
2. Computes the expected per-slot public inputs:
   `[(suEntities[i].derivedOwner, su_hash_i)] for i in 0..N`.
3. Pads to the recursive aggregation tier with `(0, 0)` per padded slot.
4. Calls `zk_verify(recursive_circuit_hash, aggregationProof, expectedInputs)`.
5. Mints the TD NFT.

Drops the current `_bindingHash` plumbing entirely — the signature is
no longer over a single global binding hash, it's per-SU inside each
inner proof.

The TD ownership proof is produced separately by the wallet **after**
submission and kept locally; the L2 contract never sees it. L1
redemption tooling consumes it when preparing inclusion proofs.

## Wallet-side flow (Rust library shape)

Two phases — submission and post-mint L1-prep.

### Phase 1 — Submit TributeDraft on L2

Steps in `pso-l2-client::wallet`:

1. **Setup (one-time per wallet):** generate `consent_sk`, send
   `consent_pk` to the SRA. Persist `consent_sk` in keystore.

2. **Receive SU receipt from SRA** for each minted SU (off-chain
   delivery — out of scope for this crate). Receipt contains
   `(pk_cu, report_nonce, encrypted_report)`.

3. **Decrypt receipt** → `(su_id, su_nonce, tx_details)`.
   `decrypt_su_receipt(consent_sk, pk_cu, report_nonce, encrypted_report)`.

4. **Derive shared key** via App. A:
   `derive_shared_key(consent_sk, pk_cu, su_nonce) -> SharedKey { secret, public }`.

5. **Sanity check** the SRA produced the same owner:
   `compute_ownership(shared_pk, su_nonce) == su.derivedOwner`.

6. **Prove SU ownership:**
   `prove_su_ownership(shared_key, su_nonce, su_hash) -> SuOwnershipProof`.

7. **Repeat 2–6** for each SU the wallet wants to include.

8. **Aggregate via recursion:**
   `aggregate_su_proofs(&proofs) -> RecursiveAggregationProof`.

9. **Pick TD-level keypair + nonce.** Generate a fresh secp256k1
   keypair `(td_sk, td_pk)` specifically for this TD, and roll
   `td_nonce`. The TD's `derivedOwner` is
   `Poseidon5(td_pk_x, td_pk_y, td_nonce)`. Wallet persists
   `(td_sk, td_nonce)` locally — needed in Phase 2.

10. **Submit:** `submit_tribute_draft(client, td_id, td_derived_owner,
    su_ids, recursive_proof)`. The contract's signature is unchanged
    from today — the only difference is the proof content.

### Phase 2 — Post-mint TD ownership proof (for L1 redemption)

Run after the TD is minted on L2. Produces a wallet-local artifact
the L1 inclusion-proof preparation pipeline consumes later.

11. **Compute TD hash** per §3.3.3 from the on-chain TD fields +
    `td_derived_owner`. Uses
    `pso_protocol::nft::compute_tribute_draft_hash`.

12. **Prove TD ownership:**
    `prove_td_ownership(td_sk, td_nonce, td_hash) -> TdOwnershipProof`.
    Same circuit as `prove_su_ownership`; just different inputs (the
    TD keypair instead of an SU shared key, and `td_hash` /
    `td_nonce` instead of `su_hash` / `su_nonce`).

13. **Store** the resulting bundle on disk. L1 redemption tooling
    picks it up later — out of scope for this repo.

## What we can deliver where, in what order

| Repo | Work | Blocking |
| --- | --- | --- |
| **pso-integration** (this repo) | Spec-correct primitives (App. A key derivation), redesigned function signatures, error variants. Prover calls error with `CircuitNotAvailable` until the circuit work lands. CLI + e2e test reshape. | self-contained — can land now |
| **pso-zk-circuits** | Rewrite `pso-ownership-circuit` per §4.2 (signature over `Poseidon(su_hash \|\| su_nonce)`, with `su_hash` and `owner` as public inputs). Delete the 8 `pso-su-ownership-aggregation-circuit-n*` tiers. Add a `pso-recursive-aggregation-circuit-n*` family (tier sizes TBD per discussion above). Regenerate `pso-zk-canonical` via `xtask regenerate-canonical`. | needs Noir toolchain + barretenberg-rs build to compile + regenerate canonical descriptors. Best done in a dedicated session with the circuit author. |
| **pso-chain** | Rewrite `TributeDraft.submit` to add the `tdOwnershipProof` calldata field and the on-chain reconstruction logic (per-SU `su_hash` derivation from `pso-protocol::nft::compute_spending_unit_hash`, `td_hash` derivation per §3.3.3, two `zk_verify` calls). Drop the `_bindingHash` plumbing entirely. | depends on circuit work above (canonical VKs + circuit_hashes) |

## Open design questions

1. **Tier set for the recursive aggregation circuit.** Current SU
   aggregation tiers (1, 2, 4, 6, 8, 16, 32, 64) were sized for the
   one-key-N-nonces layout. The recursive shape costs more per slot
   (verifying an inner proof is much more expensive than a Poseidon
   check), so the tier set should probably be re-sized empirically.
   Recommendation: regen-canonical run with a few candidate sets,
   pick whatever balances proof time vs. tier waste.

2. **Should the inner circuit also be used for the TD proof?**
   Same shape (one keypair, one signature, one nonce, one data hash)
   — yes, reuse. Saves a circuit and matches the user-experience of
   "one ownership-circuit, used both for SUs and TDs."

3. **Recursive proof public-input ordering.** The on-chain contract
   reads `[owner_0, su_hash_0, owner_1, su_hash_1, ...]` vs.
   `[owner_0, owner_1, ..., su_hash_0, su_hash_1, ...]`. Doesn't
   functionally matter; the interleaved layout is easier to extend
   if a tier needs more fields per slot (e.g. a future bound-spend
   commitment). Recommendation: interleaved.

4. **TD `tribute_draft_id` derivation.** Per §3.3.3 the TD id is
   `Poseidon2(owner, worldwide_day)`. That formula already lives in
   `pso_protocol::nft::compute_tribute_draft_id` — wallet computes
   `td_id` from `td_derived_owner + worldwide_day` and submits it to
   the contract, which can re-derive on its side. Same as today.
