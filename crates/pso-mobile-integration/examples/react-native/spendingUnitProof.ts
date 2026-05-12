/**
 * SpendingUnit Ownership Proof Example
 *
 * Demonstrates the simplest proof flow: receiving a SpendingUnit from the
 * SRA server and generating an ownership ZK proof for it.
 *
 * This is typically the first proof a mobile client generates after
 * receiving spending data from the SRA.
 */

import type { ProofResult, SpendingUnitInput } from "./types";

declare const PsoMobileIntegration: import("./types").PsoMobileIntegrationInterface;

// ---------------------------------------------------------------------------
// Example: Prove ownership of a single SpendingUnit
// ---------------------------------------------------------------------------

/**
 * Generate an ownership proof for a SpendingUnit received from the SRA.
 *
 * @param secretKey - The wallet's secp256k1 secret key (32 bytes).
 *                    Retrieved from secure storage (e.g., expo-secure-store).
 * @param su        - SpendingUnit data received from the SRA server.
 * @returns           The ownership proof to submit to the smart contract.
 *
 * @example
 * ```ts
 * import * as SecureStore from 'expo-secure-store';
 *
 * const skHex = await SecureStore.getItemAsync('wallet_secret_key');
 * const secretKey = hexToBytes(skHex!);
 *
 * const suData = await fetchSpendingUnitFromSRA();
 * const proof = proveSpendingUnitOwnership(secretKey, suData);
 *
 * // Submit proof to smart contract
 * await contract.verifyOwnership(suData.id, proof.proof, proof.publicInputs);
 * ```
 */
export function proveSpendingUnitOwnership(
  secretKey: Uint8Array,
  su: SpendingUnitInput,
): ProofResult {
  // The native call is synchronous. It will:
  // 1. Parse the secret key (secp256k1)
  // 2. Compute ownership = Poseidon5(pk_x_lo, pk_x_hi, pk_y_lo, pk_y_hi, nonce)
  // 3. Build the SpendingUnit struct with all fields
  // 4. Generate the witness (private + public inputs)
  // 5. Run the Noir circuit prover (Barretenberg UltraHonk)
  // 6. Return the proof bytes and public inputs
  return PsoMobileIntegration.proveSpendingUnitOwnership(secretKey, su);
}

// ---------------------------------------------------------------------------
// Example: Batch prove multiple SpendingUnits
// ---------------------------------------------------------------------------

interface SpendingUnitProofBatch {
  results: Array<{
    suId: Uint8Array;
    proof: ProofResult;
    durationMs: number;
  }>;
  totalDurationMs: number;
}

/**
 * Prove ownership for a batch of SpendingUnits sequentially.
 *
 * Barretenberg does not support parallel proof generation in a single
 * process, so proofs must be generated one at a time.
 *
 * @param secretKey     - The wallet's secp256k1 secret key (32 bytes).
 * @param spendingUnits - Array of SpendingUnit inputs from the SRA.
 * @param onProgress    - Optional callback for UI progress updates.
 * @returns               All proofs with timing information.
 */
export function proveBatchOwnership(
  secretKey: Uint8Array,
  spendingUnits: SpendingUnitInput[],
  onProgress?: (completed: number, total: number) => void,
): SpendingUnitProofBatch {
  const totalStart = Date.now();
  const results: SpendingUnitProofBatch["results"] = [];

  for (let i = 0; i < spendingUnits.length; i++) {
    const su = spendingUnits[i];
    const start = Date.now();

    const proof = PsoMobileIntegration.proveSpendingUnitOwnership(secretKey, su);

    results.push({
      suId: su.id,
      proof,
      durationMs: Date.now() - start,
    });

    onProgress?.(i + 1, spendingUnits.length);
  }

  return {
    results,
    totalDurationMs: Date.now() - totalStart,
  };
}

// ---------------------------------------------------------------------------
// Example: Full SpendingUnit proof (ownership + Merkle inclusion)
// ---------------------------------------------------------------------------

/**
 * Generate a full proof for a SpendingUnit, including Merkle inclusion.
 *
 * Used when submitting the SpendingUnit to a destination chain that
 * requires proof of both ownership and Merkle tree membership.
 *
 * @param secretKey  - The wallet's secp256k1 secret key (32 bytes).
 * @param su         - SpendingUnit data from the SRA server.
 * @param merklePath - Merkle inclusion path from the blockchain.
 * @returns            The full proof (ownership + Merkle).
 */
export function proveSpendingUnitFull(
  secretKey: Uint8Array,
  su: SpendingUnitInput,
  merklePath: import("./types").MerklePathElementInput[],
): ProofResult {
  return PsoMobileIntegration.proveSpendingUnitFull(secretKey, su, merklePath);
}
