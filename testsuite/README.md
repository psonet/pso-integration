# pso-e2e-testsuite

End-to-end test harness for the PSO L2. Ships as a single binary
(`pso-e2e`) that drives the full SRA + Wallet round-trip plus 40+
scenarios (negative-path invariants, envelope/VDF tampering, and the
wallet-direct lifecycle) against a running pso-chain devnet.

The binary is the CI artifact: pso-chain wraps it in a Docker image
and runs it against a freshly-spun-up devnet container.

## Build

```bash
# Native binary.
cargo build -p pso-e2e-testsuite --release

# Docker image. Build from the workspace root so the build context
# includes every path dependency the binary needs.
docker build -t pso-e2e:dev -f testsuite/Dockerfile .
```

## Usage

The CLI is the single source of truth for endpoints + keys — there
are NO env-var fallbacks for the network parameters by design.

```bash
pso-e2e \
  --rpc-url       http://127.0.0.1:19545 \
  --actor-rpc-url http://127.0.0.1:8546  \
  --chain-id      19280501               \
  --admin-key     0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --sra-key       0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
```

Flags:

| flag                | type            | required | notes                                                                |
| ------------------- | --------------- | -------- | -------------------------------------------------------------------- |
| `--rpc-url`         | URL             | no       | Agents-pool RPC, default `http://127.0.0.1:19545`.                   |
| `--actor-rpc-url`   | URL             | no       | Actor-pool RPC, default `http://127.0.0.1:8546`.                     |
| `--chain-id`        | u64             | no       | Default `19_280_501` (devnet `--dev` genesis).                       |
| `--admin-key`       | 32B hex         | yes      | SRARegistry admin secret key.                                        |
| `--sra-key`         | 32B hex         | yes      | Primary SRA secret key.                                              |
| `--wallet-key`      | 32B hex         | no       | Optional wallet (actor-pool) signer; rolled at runtime otherwise.    |
| `--only`            | csv             | no       | Substring filter on scenario id, e.g. `--only S001,S009`.            |
| `--skip`            | csv             | no       | Substring filter excluding the listed ids.                           |
| `--report`          | `markdown\|json`| no       | stdout report format (default markdown).                             |
| `--json-output`     | path            | no       | Additionally write the report as JSON to this path.                  |
| `-v`, `-vv`, `-vvv` | flag            | no       | Verbosity: info / debug / trace.                                     |

Hex inputs accept either `0x`-prefixed or bare 64-hex-char strings.

## Scenarios

`pso-e2e --list` prints the live count + every scenario's id and
description (without touching the chain). At the time of this
README:

Each scenario is a single `testsuite/src/scenarios/sNNN_*.rs`
file with a module-level doc-comment explaining the chain-side
guard it exercises.

| id    | invariant                                                                                |
| ----- | ---------------------------------------------------------------------------------------- |
| S001  | Full SR/AR → SU via bridge → wallet TD prove + submit; `derivedOwner` round-trip.        |
| S002  | SRA-signed `TributeDraft.submit` through agents pool is refused (pool or contract).      |
| S003  | Non-SRA wallet cannot submit a SpendingRecord through the actor pool.                    |
| S004  | Non-SRA wallet cannot submit a SpendingRecordAmendment through the actor pool.           |
| S005  | Non-SRA wallet cannot mint a SpendingUnit through the actor pool.                        |
| S006  | SRA-signed actor-pool submission: assert the inner-call outcome (no SR landed).          |
| S007  | Registering the same SR id twice reverts with `AlreadyExists`.                           |
| S008  | `SR.submit(id=0, ...)` reverts with `InvalidTokenId`.                                    |
| S009  | `SU.submit` referencing another SRA's SR reverts with `InvalidSpendingRecords` (bad-owner SR). |
| S010  | Second SU sharing an SR fingerprint reverts with `InvalidSpendingRecords` (duplicate SR). |
| S011  | `SU.submit` with never-registered SR ids reverts with `InvalidSpendingRecords` (bad-owner SR). |
| S012  | `TributeDraft.submit` with empty `suIds` reverts with `EmptyArray`.                      |
| S013  | Actor RPC rejects envelope with zeroed magic prefix.                                     |
| S014  | Actor RPC rejects envelope replaying a previously-seen nullifier.                        |
| S015  | Actor RPC rejects envelope with stale `submitted_block`.                                 |
| S016  | Actor RPC rejects envelope with bit-flipped VDF proof bytes.                             |
| S017  | Actor RPC rejects envelope with bit-flipped VDF output bytes.                            |
| S018  | `TributeDraft.submit` with empty proof reverts `MalformedAggregationProof`.              |
| S019  | `TributeDraft.submit` with mismatched public inputs reverts `InvalidAggregationProof`.   |
| S020  | `SU.submit` referencing another SRA's AR reverts with `InvalidSpendingRecords` (bad-owner AR). |
| S021  | `TributeDraft.submit` with non-existent `suId` reverts `NotFound`.                       |
| S022  | `TributeDraft.submit` with SUs on different worldwide_days reverts `NotSameWorldwideDay`.|
| S023  | `TributeDraft.submit` with SUs in different currencies reverts `NotSameCurrency`. |
| S025  | `SR.submit` with mismatched key/value lengths reverts `InvalidMetadata`.                 |
| S026  | `SU.submit` with `amount_atto >= 1e18` reverts `InvalidAmount`.               |
| S027  | `SRARegistry.register` from a non-admin reverts `NotAdmin`.                              |
| S028  | `SRARegistry.register(address(0), ...)` reverts `ZeroAddress`.                           |
| S029  | `SRARegistry.register(addr, 0, ...)` reverts `InvalidMask`.                              |
| S030  | `SR.submit` from a never-registered SRA reverts `SRANotActive`.                          |
| S031  | Actor RPC rejects envelope with VDF computed at `T` outside current ∪ previous epoch's. |
| S032  | Actor RPC accepts envelope with VDF computed at the **previous** epoch's `T` after rollover. |
| S033  | Revoked SRA's `SR.submit` reverts `SRANotActive` (lifecycle).                            |
| S035  | `admin.update_mask` round-trips through `getRecord`.                                     |
| S036  | `admin.set_rotation_candidate` round-trips through `getRecord`.                          |
| S037  | `admin.revoke_sra` on never-registered address reverts `NotRegistered(addr)`.            |
| S038  | `SequencerEpoch` view round-trip: constants + `currentEpoch` + `leaderForEpoch` ↔ `rankedLeadersForEpoch[0]`. |
| S039  | `SlashingVerifier.proveEquivocation` happy path: two same-height signatures emit `EquivocationProven` + `Slashed`. |
| S040  | `SlashingVerifier.proveInvalidVDF` happy path: zero-bytes proof against non-zero input emits `InvalidVDFProven` + `Slashed`. |
| S041  | Users-pool envelope from a never-registered wallet key clears pool admission (no SRA gate on the actor lane). |
| S042  | Mobile-API wallet flow: uniffi VDF + self-assembled envelope tx executes end-to-end through the `PsoEnvelopeDispatcher` (`status == 1`). |
| S043  | Envelope aged ~20 blocks (inside `PSO_PROOF_MAX_AGE`) is admitted and executes — positive counterpart to S015. |
| S044  | Sequential wallet txs (nonce 0, 1) execute with per-nonce VDF recompute; nonce-0 VDF binding replayed at nonce 2 rejects `BadVdfInputBinding`. |

S032 needs the chain spawned with `PSO_DEV_RPC=1` (gates
`pso_dev_advanceEpoch`); the CI workflow sets it on the dev node.

Intentional gaps in the numbering:

- **S024 (`AggregationTierUnavailable`)** — the contract's
  `_selectTier(n)` rounds n upward, so only n > 64 triggers the
  revert, which would need 65 SU mints per scenario run. Drop
  until we have a cheaper path.
- **S034 (`AlreadyRegistered`)** — initial premise was that
  re-registering an active SRA reverts. The contract is actually
  idempotent (`register` is the canonical way to UPDATE an
  existing record's mask / rate-limit / rotation flag in one
  call); the `AlreadyRegistered` error variant exists in the
  ABI but is dead code. Scenario dropped.

## Exit codes

- `0` — all (filtered) scenarios passed.
- `1` — at least one scenario failed; consult the markdown / JSON
  report on stdout.
- `2` — bootstrap or arg-parse error (clap / connect / SRA-register).

## Wiring into pso-chain CI

```yaml
- name: PSO L2 e2e suite
  run: |
    docker run --rm --network host pso-e2e:dev \
      --rpc-url       http://127.0.0.1:19545 \
      --actor-rpc-url http://127.0.0.1:8546  \
      --chain-id      "$PSO_CHAIN_ID"        \
      --admin-key     "$ADMIN_KEY"           \
      --sra-key       "$SRA_KEY"
```

`--network host` so the container can reach the devnet RPCs on
loopback. If the devnet is itself containerised, wire the two onto
the same compose network and pass the service DNS names instead.

## Dev workflow

```bash
# Unit tests — don't need a running L2.
cargo test -p pso-e2e-testsuite --lib
cargo test -p pso-e2e-testsuite --test framework

# Run the full suite against a local pso-chain --dev node.
pso-chain --dev &
pso-e2e \
  --admin-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --sra-key   0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

# Run a single scenario.
pso-e2e --admin-key ... --sra-key ... --only S001 -vv
```

The canonical Hardhat keys for `--dev` are pinned in
[`src/hardhat.rs`](src/hardhat.rs) as a local-dev fixture; they are
NOT wired into the binary's default code path — pass them via
`--admin-key` / `--sra-key` explicitly.
