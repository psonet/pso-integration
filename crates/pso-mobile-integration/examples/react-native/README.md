# React Native Examples

TypeScript examples showing how to use the `pso-mobile-integration` UniFFI bindings
in a React Native (Expo) application.

## Files

| File | Description |
|------|-------------|
| `types.ts` | TypeScript type definitions mirroring the UniFFI-generated bindings |
| `tributeFlow.ts` | Complete 6-step tribute flow (SRA → ownership → contract → full proof) |
| `spendingUnitProof.ts` | SpendingUnit ownership proof with batch support |
| `useProofGeneration.ts` | React hook wrapping the native API with loading/error state |

## Setup

These examples assume you have:

1. Compiled the `pso-mobile-integration` crate for your target platform
2. Generated UniFFI bindings via `uniffi-bindgen-react-native`
3. Linked the native module in your React Native project

```sh
# Build for iOS
cargo build --release --target aarch64-apple-ios

# Generate TypeScript bindings
cargo run --bin uniffi-bindgen-mobile -- generate \
    --library target/aarch64-apple-ios/release/libpso_mobile_integration.a \
    --language swift \
    --out-dir ./bindings/swift
```

## Notes

- **Synchronous API**: All native calls are synchronous. The React hook
  example uses `InteractionManager` to avoid blocking UI animations.
- **Sequential proofs**: Barretenberg does not support parallel proof
  generation. Always generate proofs one at a time.
- **Nonce storage**: The nonce from `computeTributeOwnership` must be
  persisted (e.g., in `expo-secure-store`) for later use in
  `proveTributeFull`.
- **Dev mode**: In development builds (compiled with `--features dev-tools`),
  `generateRandomMerklePath()` is available for testing without a real
  blockchain.
