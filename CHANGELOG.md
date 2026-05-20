# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## v0.3.5 - 2026-05-20
#### Bug Fixes
- (**ci**) drop uniffiEnsureInitialized from SmokeTest (internal symbol) - (d2c62c6) - Anton Velichko

- - -

## v0.3.4 - 2026-05-20
#### Bug Fixes
- (**ci**) drop redundant assertNotNull from SmokeTest - (930f2b7) - Anton Velichko

- - -

## v0.3.3 - 2026-05-20
#### Bug Fixes
- (**release**) JAR native libs dynamic (.dylib/.so), darwin built natively - (00a2514) - Anton Velichko

- - -

## v0.3.2 - 2026-05-20
#### Bug Fixes
- (**release**) attach mobile slices, uniffi-bindgen-mobile, and Kotlin JAR - (0a130b9) - Anton Velichko

- - -

## v0.3.1 - 2026-05-20
#### Bug Fixes
- bump version to capture dep-graph cleanup - (00ddbb2) - Anton Velichko
#### Miscellaneous Chores
- (**deps**) bump pso-poseidon "0.2" → "0.3" - (c3152c0) - Anton Velichko
- (**deps**) replace direct noir_rs deps with pso-zk-circuit-noir re-exports - (9f843ec) - Anton Velichko
- (**deps**) switch pso-protocol + pso-zk-canonical to crates.io; tag-pin pso-zk-circuit-noir; bump pso-vdf - (34786a7) - Anton Velichko
#### Style
- cargo fmt after noir_rs → pso_zk_circuit_noir rename - (0fbacbe) - Anton Velichko

- - -

## v0.3.0 - 2026-05-15
#### Features
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>(**l2-client**) sync ISlashingVerifier ABI with pso-chain Phase 5 - (0d20f6e) - Anton Velichko

- - -

## v0.2.2 - 2026-05-15
#### Bug Fixes
- (**testsuite**) route tracing-subscriber to stderr - (709f05d) - Anton Velichko

- - -

## v0.2.1 - 2026-05-15
#### Bug Fixes
- (**testsuite**) make S039/S040 proofHash unique per run - (c07b784) - Anton Velichko

- - -

## v0.2.0 - 2026-05-15
#### Features
- (**testsuite**) S032 cross-epoch positive + Tier C slashing/rotation - (f77e794) - Anton Velichko
#### Style
- rustfmt PR3e scenarios + env helper - (75843e5) - Anton Velichko

- - -

## v0.1.2 - 2026-05-14
#### Bug Fixes
- (**testsuite**) correct SRARecord field layout + drop S034 + add --list - (89b84f4) - Anton Velichko

- - -

## v0.1.1 - 2026-05-14
#### Bug Fixes
- (**ci**) make cog bump rewrite every crate version, not just CHANGELOG - (a397246) - Anton Velichko
#### Continuous Integration
- support manual tag pushes + workflow_dispatch + skip check on release-only paths - (c4e2eb4) - Anton Velichko

- - -

## v0.1.0 - 2026-05-14
#### Features
- (**client**) force max_fee = max_priority_fee = 0 on agent / wallet txs - (15459f2) - Anton Velichko
- (**e2e**) scenario-driven suite with Actor / SRA client split - (98ce123) - Anton Velichko
- (**e2e**) full SRA -> Wallet -> TributeDraft flow against pso-chain - (ef1bd42) - Anton Velichko
- (**integration**) wire Schnorr/Grumpkin + flat aggregation - (5856a32) - Anton Velichko
- (**l2**) SRA + Wallet CLIs + L2 RPC client + e2e test crate - (36c6110) - Anton Velichko
- (**mobile**) MinRoot VDF FFI for Users-pool tx gating - (82ff64b) - Anton Velichko
- (**testsuite**) --junit-output + GHCR publish + PR CI - (d436c8e) - Anton Velichko
- (**testsuite**) rehome e2e as standalone `pso-e2e` CLI binary - (51575f2) - Anton Velichko
- (**wallet**) single-call flat aggregation prove + e2e wire-up - (5f3787d) - Anton Velichko
- reorganize systems crates layout. - (13b729b) - Anton Velichko
#### Bug Fixes
- (**aggregation**) stub mobile + CLI paths pending recursive wrapper - (406a2ce) - Anton Velichko
- (**aggregation**) redesign per privacy-preserving L2 spec - (b565f6b) - Anton Velichko
- (**l2-client**) use pso-zk-circuit-noir's flat_aggregation_json API - (2c43060) - Anton Velichko
- (**mobile-integration**) drop sibling-path include_str! for circuit JSONs - (6876215) - Anton Velichko
- (**sra-integration**) reduce nft_sk mod q_Grumpkin before bb FFI - (2e8df47) - Anton Velichko
#### Continuous Integration
- (**composite**) drop \${{ secrets.* }} expression from action description - (2de089d) - Anton Velichko
- (**image**) build the binary on the runner, dockerize only the runtime - (abe61af) - Anton Velichko
- (**image**) resolve PAT login on the runner, pass as build-arg - (fbeeed4) - Anton Velichko
- (**testsuite**) swap MUSL for zigbuild against glibc 2.31 + distroless - (71d0c53) - Anton Velichko
- (**testsuite**) port build to bank-data-provider pattern (zigbuild MUSL + scratch image) - (1d275bf) - Anton Velichko
- (**testsuite**) scope rust-cache to ubuntu-22.04 - (e83e1a2) - Anton Velichko
- (**testsuite**) pin builder to ubuntu-22.04 to match bookworm glibc - (c2cc73f) - Anton Velichko
- (**testsuite-image**) trigger on configure-private-git changes too - (4f1a175) - Anton Velichko
- gate testsuite-image on ci + add cocogitto release pipeline - (4b35fc8) - Anton Velichko
- extract composite actions (configure-private-git, rust-check, rust-test) - (c47f504) - Anton Velichko
- add libc++-dev libc++abi-dev to C++ toolchain install - (0fc30f3) - Anton Velichko
- persist-credentials: false on `unit` checkout too - (2ddfcfa) - Anton Velichko
- re-trigger with recreated PSONET_REPO_TOKEN - (fe37628) - Anton Velichko
- switch to credential.helper + Basic Auth with PAT issuer's login - (065017f) - Anton Velichko
- drop actions/checkout credentials so our PAT header is the only one - (4d03eb2) - Anton Velichko
- verbose GIT_CURL probe + title-case Authorization header - (536eedf) - Anton Velichko
- authenticate git via http.extraheader (Bearer), not URL Basic Auth - (6f94376) - Anton Velichko
- drop `x-access-token:` username from PAT auth URL - (33183d5) - Anton Velichko
- API-level diagnostic for PSONET_REPO_TOKEN access - (bcbca73) - Anton Velichko
- better diagnostics on PSONET_REPO_TOKEN auth failure - (dfe8b0b) - Anton Velichko
- use `git config --add` so both insteadOf rules coexist - (eb1ebbd) - Anton Velichko
- cargo fmt sweep on testsuite - (2ec2c51) - Anton Velichko
- re-trigger after PSONET_REPO_TOKEN landed - (5845fa2) - Anton Velichko
- auth private psonet/* git deps via PSONET_REPO_TOKEN - (f1c04b0) - Anton Velichko
#### Miscellaneous Chores
- (**deps**) pin noir_rs patch to psonet/noir_rs git ref - (4d6e829) - Anton Velichko
- switch sibling-repo deps from path to git refs - (37310f0) - Anton Velichko
#### Style
- cargo fmt for schnorr.rs - (0ab0aee) - Anton Velichko

- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).