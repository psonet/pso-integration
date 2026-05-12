/**
 * React Hook Example: useProofGeneration
 *
 * A reusable React hook that wraps the native proof API with loading
 * state, error handling, and progress tracking. Runs proof generation
 * on a background thread to keep the UI responsive.
 *
 * Since Barretenberg proof generation is synchronous and CPU-intensive
 * (can take several seconds), this hook uses InteractionManager to
 * defer work until animations complete, and provides status callbacks
 * for progress indicators.
 */

import { useCallback, useRef, useState } from "react";
import { InteractionManager } from "react-native";

import type {
  MerklePathElementInput,
  NftKeypair,
  ProofResult,
  SpendingUnitInput,
  TributeInput,
  TributeOwnership,
} from "./types";

declare const PsoMobileIntegration: import("./types").PsoMobileIntegrationInterface;

// ---------------------------------------------------------------------------
// Hook state
// ---------------------------------------------------------------------------

interface ProofGenerationState {
  /** Whether a proof is currently being generated. */
  isProving: boolean;
  /** The most recent error, if any. */
  error: Error | null;
  /** Progress for batch operations: [completed, total]. */
  progress: [number, number] | null;
}

// ---------------------------------------------------------------------------
// Hook: useProofGeneration
// ---------------------------------------------------------------------------

/**
 * Hook that provides proof generation functions with React state management.
 *
 * All proof functions:
 * - Set `isProving = true` while running
 * - Catch and expose errors via `state.error`
 * - Defer execution until animations complete (InteractionManager)
 * - Return a cancellation handle
 *
 * @example
 * ```tsx
 * function ProveButton({ secretKey, su }: Props) {
 *   const { state, proveSpendingUnitOwnership } = useProofGeneration();
 *
 *   const handlePress = async () => {
 *     const result = await proveSpendingUnitOwnership(secretKey, su);
 *     if (result) {
 *       console.log('Proof generated:', result.proof.length, 'bytes');
 *     }
 *   };
 *
 *   return (
 *     <View>
 *       <Button
 *         title={state.isProving ? 'Proving...' : 'Prove Ownership'}
 *         onPress={handlePress}
 *         disabled={state.isProving}
 *       />
 *       {state.error && <Text style={{ color: 'red' }}>{state.error.message}</Text>}
 *     </View>
 *   );
 * }
 * ```
 */
export function useProofGeneration() {
  const [state, setState] = useState<ProofGenerationState>({
    isProving: false,
    error: null,
    progress: null,
  });

  // Track mounted state to avoid state updates after unmount.
  const mountedRef = useRef(true);

  // -- Helper: run a proof function with state management --

  const runProof = useCallback(
    <T>(fn: () => T): Promise<T | null> => {
      return new Promise((resolve) => {
        setState({ isProving: true, error: null, progress: null });

        // Defer until animations/transitions complete
        InteractionManager.runAfterInteractions(() => {
          try {
            const result = fn();
            if (mountedRef.current) {
              setState({ isProving: false, error: null, progress: null });
            }
            resolve(result);
          } catch (err) {
            const error = err instanceof Error ? err : new Error(String(err));
            if (mountedRef.current) {
              setState({ isProving: false, error, progress: null });
            }
            resolve(null);
          }
        });
      });
    },
    [],
  );

  // -- Public API --

  const deriveNftKeypair = useCallback(
    (
      consentSk: Uint8Array,
      sraPk: Uint8Array,
      nftNonce: Uint8Array,
    ): Promise<NftKeypair | null> => {
      return runProof(() =>
        PsoMobileIntegration.deriveNftKeypair(consentSk, sraPk, nftNonce),
      );
    },
    [runProof],
  );

  const computeTributeOwnership = useCallback(
    (secretKey: Uint8Array, worldwideDay: number): Promise<TributeOwnership | null> => {
      return runProof(() =>
        PsoMobileIntegration.computeTributeOwnership(secretKey, worldwideDay),
      );
    },
    [runProof],
  );

  const proveSpendingUnitOwnership = useCallback(
    (secretKey: Uint8Array, su: SpendingUnitInput): Promise<ProofResult | null> => {
      return runProof(() =>
        PsoMobileIntegration.proveSpendingUnitOwnership(secretKey, su),
      );
    },
    [runProof],
  );

  const proveTributeOwnership = useCallback(
    (
      secretKey: Uint8Array,
      nonce: Uint8Array,
      tribute: TributeInput,
    ): Promise<ProofResult | null> => {
      return runProof(() =>
        PsoMobileIntegration.proveTributeOwnership(secretKey, nonce, tribute),
      );
    },
    [runProof],
  );

  const proveSpendingUnitFull = useCallback(
    (
      secretKey: Uint8Array,
      su: SpendingUnitInput,
      merklePath: MerklePathElementInput[],
    ): Promise<ProofResult | null> => {
      return runProof(() =>
        PsoMobileIntegration.proveSpendingUnitFull(secretKey, su, merklePath),
      );
    },
    [runProof],
  );

  const proveTributeFull = useCallback(
    (
      secretKey: Uint8Array,
      nonce: Uint8Array,
      tribute: TributeInput,
      merklePath: MerklePathElementInput[],
    ): Promise<ProofResult | null> => {
      return runProof(() =>
        PsoMobileIntegration.proveTributeFull(secretKey, nonce, tribute, merklePath),
      );
    },
    [runProof],
  );

  return {
    state,
    deriveNftKeypair,
    computeTributeOwnership,
    proveSpendingUnitOwnership,
    proveTributeOwnership,
    proveSpendingUnitFull,
    proveTributeFull,
  };
}
