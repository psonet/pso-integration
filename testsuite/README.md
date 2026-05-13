# pso-e2e-testsuite

End-to-end test harness for the PSO L2. Ships as a single binary
(`pso-e2e`) that drives the full SRA + Wallet round-trip plus 11
negative-path invariants against a running pso-chain devnet.

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

| id    | invariant                                                                                |
| ----- | ---------------------------------------------------------------------------------------- |
| S001  | Full SR/AR → SU via bridge → wallet TD prove + submit; derivedOwner round-trip.          |
| S002  | SRA-signed `TributeDraft.submit` through agents pool is refused (pool or contract).      |
| S003  | Non-SRA wallet cannot submit a SpendingRecord through the actor pool.                    |
| S004  | Non-SRA wallet cannot submit a SpendingRecordAmendment through the actor pool.           |
| S005  | Non-SRA wallet cannot mint a SpendingUnit through the actor pool.                        |
| S006  | SRA-signed actor-pool submission: assert the inner-call outcome (no SR landed).          |
| S007  | Registering the same SR id twice reverts with `AlreadyExists`.                           |
| S008  | `SR.submit(id=0, ...)` reverts with `InvalidTokenId`.                                    |
| S009  | SU.submit referencing another SRA's SR reverts with `SpendingRecordsNotOwnedBySender`.   |
| S010  | Second SU sharing an SR fingerprint reverts with `SpendingRecordsAlreadyExist`.          |
| S011  | SU.submit with never-registered SR ids reverts with `SpendingRecordsNotOwnedBySender`.   |
| S012  | `TributeDraft.submit` with empty `suIds` reverts with `EmptyArray`.                      |

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
