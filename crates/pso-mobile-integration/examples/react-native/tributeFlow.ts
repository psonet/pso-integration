/**
 * Full Tribute Flow Example
 *
 * Demonstrates the complete 6-step client workflow:
 *   1. Receive SpendingUnits from SRA server
 *   2. Prove SU ownership (for each SU)
 *   3. Compute tribute ownership (nonce + hash + ID)
 *   4. Submit to smart contract (SU proofs + tribute ownership)
 *   5. Receive Merkle path (from committed block)
 *   6. Generate full tribute proof → send to destination chain
 *
 * Prerequisites:
 *   - pso-mobile-integration compiled as a React Native Turbo Module
 *   - uniffi-bindgen-react-native bindings generated
 *   - The app's secret key stored in secure storage
 */

import type {
  MerklePathElementInput,
  ProofResult,
  SpendingUnitInput,
  TributeInput,
  TributeOwnership,
} from "./types";

// -- Import the native module --
// The actual import depends on your uniffi-bindgen-react-native setup.
// Typically:
//   import { PsoMobileIntegration } from 'pso-mobile-integration';
//
// For this example we use a placeholder:
declare const PsoMobileIntegration: import("./types").PsoMobileIntegrationInterface;

// ---------------------------------------------------------------------------
// Step 1 — Receive SpendingUnits from SRA server
// ---------------------------------------------------------------------------

interface SraSpendingUnitResponse {
  id: string; // hex-encoded 32 bytes
  nonce: string; // hex-encoded 32 bytes
  currency: number;
  amountBase: number;
  amountAtto: number;
  worldwideDay: number;
  spendingRecordsFingerprints: string[];
  amendmentRecordsFingerprints: string[];
}

/** Convert hex string to Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Convert Uint8Array to hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Map SRA server response to the native SpendingUnitInput. */
function mapSraResponse(resp: SraSpendingUnitResponse): SpendingUnitInput {
  return {
    id: hexToBytes(resp.id),
    nonce: hexToBytes(resp.nonce),
    currency: resp.currency,
    amountBase: resp.amountBase,
    amountAtto: resp.amountAtto,
    worldwideDay: resp.worldwideDay,
    spendingRecordsFingerprints: resp.spendingRecordsFingerprints.map(hexToBytes),
    amendmentRecordsFingerprints: resp.amendmentRecordsFingerprints.map(hexToBytes),
  };
}

// ---------------------------------------------------------------------------
// Step 2 — Prove SpendingUnit ownership
// ---------------------------------------------------------------------------

/** Prove ownership for each SpendingUnit. Returns (suId, proof) pairs. */
function proveAllSuOwnership(
  secretKey: Uint8Array,
  spendingUnits: SpendingUnitInput[],
): Array<{ suId: Uint8Array; proof: ProofResult }> {
  // NOTE: Proofs must be generated sequentially — Barretenberg does not
  // support parallel proof generation in a single process.
  return spendingUnits.map((su) => {
    console.log(`Proving ownership for SU ${bytesToHex(su.id).slice(0, 8)}...`);
    const proof = PsoMobileIntegration.proveSpendingUnitOwnership(secretKey, su);
    return { suId: su.id, proof };
  });
}

// ---------------------------------------------------------------------------
// Step 3 — Compute tribute ownership
// ---------------------------------------------------------------------------

/** Compute tribute ownership hash and nonce. */
function computeTribute(
  secretKey: Uint8Array,
  worldwideDay: number,
): TributeOwnership {
  console.log(`Computing tribute ownership for ${worldwideDay}...`);
  const ownership = PsoMobileIntegration.computeTributeOwnership(secretKey, worldwideDay);
  console.log(`Tribute draft ID: ${bytesToHex(ownership.tributeDraftId).slice(0, 16)}...`);
  // IMPORTANT: Store ownership.nonce securely — you'll need it in step 6.
  return ownership;
}

// ---------------------------------------------------------------------------
// Step 4 — Submit to smart contract
// ---------------------------------------------------------------------------

interface SmartContractSubmission {
  suIds: Uint8Array[];
  suOwnershipProofs: ProofResult[];
  tributeOwnership: Uint8Array;
  tributeDraftId: Uint8Array;
}

/** Build the submission payload for the smart contract. */
function buildSmartContractPayload(
  suProofs: Array<{ suId: Uint8Array; proof: ProofResult }>,
  tributeOwnership: TributeOwnership,
): SmartContractSubmission {
  return {
    suIds: suProofs.map((p) => p.suId),
    suOwnershipProofs: suProofs.map((p) => p.proof),
    tributeOwnership: tributeOwnership.ownership,
    tributeDraftId: tributeOwnership.tributeDraftId,
  };
}

// In your actual app, submit `payload` to the smart contract via your
// blockchain SDK (ethers.js, viem, etc.):
//
//   const tx = await contract.submitTribute(
//     payload.suIds,
//     payload.suOwnershipProofs.map(p => p.proof),
//     payload.suOwnershipProofs.map(p => p.publicInputs),
//     payload.tributeOwnership,
//     payload.tributeDraftId,
//   );
//   await tx.wait();

// ---------------------------------------------------------------------------
// Step 5 — Receive Merkle path
// ---------------------------------------------------------------------------

/** Fetch Merkle path from the blockchain after the block is committed. */
async function fetchMerklePath(
  tributeDraftId: Uint8Array,
): Promise<MerklePathElementInput[]> {
  // In production, query the blockchain for the Merkle inclusion proof:
  //
  //   const response = await fetch(`${API_URL}/merkle-path/${bytesToHex(tributeDraftId)}`);
  //   const data = await response.json();
  //   return data.path.map(elem => ({
  //     nodeHash: hexToBytes(elem.hash),
  //     index: elem.index,  // 0=Skip, 1=Left, 2=Right
  //   }));

  // In dev mode, use the built-in random generator:
  if (PsoMobileIntegration.generateRandomMerklePath) {
    console.log("DEV MODE: generating random Merkle path");
    return PsoMobileIntegration.generateRandomMerklePath();
  }

  throw new Error("Production Merkle path fetch not implemented in example");
}

// ---------------------------------------------------------------------------
// Step 6 — Generate full tribute proof
// ---------------------------------------------------------------------------

/** Generate the full proof (ownership + Merkle inclusion) for the tribute. */
function generateFullTributeProof(
  secretKey: Uint8Array,
  storedNonce: Uint8Array,
  tribute: TributeInput,
  merklePath: MerklePathElementInput[],
): ProofResult {
  console.log("Generating full tribute proof...");
  const proof = PsoMobileIntegration.proveTributeFull(
    secretKey,
    storedNonce,
    tribute,
    merklePath,
  );
  console.log(`Full proof generated: ${proof.proof.length} bytes`);
  return proof;
}

// ---------------------------------------------------------------------------
// Complete flow orchestrator
// ---------------------------------------------------------------------------

export async function runFullTributeFlow(
  secretKey: Uint8Array,
  sraSpendingUnits: SraSpendingUnitResponse[],
  worldwideDay: number,
  currency: number,
  amountBase: number,
  amountAtto: number,
): Promise<{ tributeDraftId: Uint8Array; fullProof: ProofResult }> {
  // Step 1: Map SRA responses to native inputs
  const spendingUnits = sraSpendingUnits.map(mapSraResponse);

  // Step 2: Prove SU ownership for each SpendingUnit
  const suProofs = proveAllSuOwnership(secretKey, spendingUnits);

  // Step 3: Compute tribute ownership (generates random nonce)
  const tributeOwnership = computeTribute(secretKey, worldwideDay);

  // Step 4: Submit to smart contract
  const payload = buildSmartContractPayload(suProofs, tributeOwnership);
  console.log("Ready to submit to smart contract:", {
    numSUs: payload.suIds.length,
    tributeDraftId: bytesToHex(payload.tributeDraftId).slice(0, 16) + "...",
  });
  // await submitToSmartContract(payload);

  // Step 5: Get Merkle path (after block is committed)
  const merklePath = await fetchMerklePath(tributeOwnership.tributeDraftId);

  // Step 6: Generate full proof
  const tributeInput: TributeInput = {
    currency,
    amountBase,
    amountAtto,
    worldwideDay,
    suIds: spendingUnits.map((su) => su.id),
  };

  const fullProof = generateFullTributeProof(
    secretKey,
    tributeOwnership.nonce, // The stored nonce from step 3
    tributeInput,
    merklePath,
  );

  return {
    tributeDraftId: tributeOwnership.tributeDraftId,
    fullProof,
  };
}
