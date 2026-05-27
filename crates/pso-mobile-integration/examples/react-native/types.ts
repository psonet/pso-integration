/**
 * TypeScript type definitions matching the UniFFI-generated bindings.
 *
 * These mirror the Rust `uniffi::Record` and `uniffi::Error` types exported
 * by `pso-mobile-integration`. When you run `uniffi-bindgen-react-native`, the
 * generated module will export these exact types — this file is provided
 * as a reference so the examples are self-contained and readable.
 */

// -- Input types --

/** A single element in a Merkle inclusion path. */
export interface MerklePathElementInput {
  /** Sibling node hash (32 bytes, little-endian BN254 Fr). */
  nodeHash: Uint8Array;
  /** Position index: 0 = Skip, 1 = Left, 2 = Right. */
  index: number;
}

/** Input data for a SpendingUnit (received from the SRA server). */
export interface SpendingUnitInput {
  /** Spending unit ID (32 bytes). Server-generated. */
  id: Uint8Array;
  /** Nonce for this SU's ownership (32 bytes). Server-provided. */
  nonce: Uint8Array;
  /** ISO 4217 currency numeric code (e.g., 978 for EUR). */
  currency: number;
  /** Amount integer part. */
  amountBase: number;
  /** Amount fractional part (atto). */
  amountAtto: number;
  /** Worldwide day as YYYYMMDD number (e.g., 20260305). */
  worldwideDay: number;
  /** Spending record fingerprints, each 32 bytes. */
  spendingRecordsFingerprints: Uint8Array[];
  /** Amendment record fingerprints, each 32 bytes. */
  amendmentRecordsFingerprints: Uint8Array[];
}

/** Input data for a TributeDraft (client-constructed). */
export interface TributeInput {
  /** ISO 4217 currency numeric code. */
  currency: number;
  /** Amount integer part. */
  amountBase: number;
  /** Amount fractional part (atto). */
  amountAtto: number;
  /** Worldwide day as YYYYMMDD number. */
  worldwideDay: number;
  /** Spending unit IDs included in this tribute, each 32 bytes. */
  suIds: Uint8Array[];
}

// -- Output types --

/** Result of computing tribute ownership (no proof). */
export interface TributeOwnership {
  /** Random nonce (32 bytes). Store this for later proof generation. */
  nonce: Uint8Array;
  /** Ownership hash (32 bytes). */
  ownership: Uint8Array;
  /** TributeDraft ID: Poseidon2(ownership, worldwide_day_count) (32 bytes). */
  tributeDraftId: Uint8Array;
}

/** Derived NFT keypair from ECDH + KDF. */
export interface NftKeypair {
  /** Raw secret key bytes (32 bytes). */
  sk: Uint8Array;
  /** SEC1-encoded public key in compressed form (33 bytes). */
  pk: Uint8Array;
}

/** Result of generating a ZK proof. */
export interface ProofResult {
  /** The proof bytes (Barretenberg UltraHonk format). */
  proof: Uint8Array;
  /** Public inputs, each as raw bytes. */
  publicInputs: Uint8Array[];
}

// -- Error type --

/** Error thrown by the native proof API. */
export type MobileErrorVariant =
  | { type: "InvalidSecretKey"; detail: string }
  | { type: "InvalidPublicKey"; detail: string }
  | { type: "InvalidDate"; detail: string }
  | { type: "InvalidCurrency"; detail: string }
  | { type: "InvalidFieldElement"; detail: string }
  | { type: "InvalidMerkleIndex"; detail: string }
  | { type: "WitnessGenerationFailed"; detail: string }
  | { type: "ProofFailed"; detail: string }
  | { type: "CircuitInitFailed"; detail: string }
  | { type: "Internal"; detail: string };

export class MobileError extends Error {
  variant: MobileErrorVariant;
  constructor(variant: MobileErrorVariant) {
    super(`${variant.type}: ${variant.detail}`);
    this.variant = variant;
  }
}

// -- Native module interface --

/**
 * The native module interface exported by UniFFI.
 *
 * Import in your app as:
 * ```ts
 * import { PsoMobileIntegration } from 'pso-mobile-integration';
 * ```
 */
export interface PsoMobileIntegrationInterface {
  deriveNftKeypair(
    consentSk: Uint8Array,
    sraPk: Uint8Array,
    nftNonce: Uint8Array,
  ): NftKeypair;

  computeTributeOwnership(
    secretKey: Uint8Array,
    worldwideDay: number,
  ): TributeOwnership;

  proveSpendingUnitOwnership(
    secretKey: Uint8Array,
    spendingUnit: SpendingUnitInput,
  ): ProofResult;

  proveTributeOwnership(
    secretKey: Uint8Array,
    nonce: Uint8Array,
    tribute: TributeInput,
  ): ProofResult;

  proveSpendingUnitFull(
    secretKey: Uint8Array,
    spendingUnit: SpendingUnitInput,
    merklePath: MerklePathElementInput[],
  ): ProofResult;

  proveTributeFull(
    secretKey: Uint8Array,
    nonce: Uint8Array,
    tribute: TributeInput,
    merklePath: MerklePathElementInput[],
  ): ProofResult;

  /** Dev-tools only — not available in production builds. */
  generateRandomMerklePath?(): MerklePathElementInput[];
}
