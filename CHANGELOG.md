# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## v0.9.0 - 2026-06-17
#### Features
- <span style="background-color: #d73a49; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold; font-size: 0.85em;">BREAKING</span>(**binding**) thread binding_hash through the prover (TD submit + L1 redemption) - (e676512) - Anton Velichko

- - -

## v0.8.4 - 2026-06-16
#### Bug Fixes
- (**testsuite**) generous receipt timeout for S043/S044 (CI block-time jitter) - (9e65906) - Anton Velichko

- - -

## v0.8.3 - 2026-06-16
#### Bug Fixes
- (**testsuite**) users lane uses the node's 0x76 VdfProtectedTransaction envelope - (f9745bc) - Anton Velichko

- - -

## v0.8.2 - 2026-06-16
#### Bug Fixes
- (**testsuite**) align registry surface to research AttestersRegistry - (5a735db) - Anton Velichko
#### Tests
- (**framework**) SRANotActive -> AttesterNotActive decoder round-trip - (e272954) - Anton Velichko

- - -

## v0.8.1 - 2026-06-16
#### Bug Fixes
- (**testsuite**) use pso_vdfInfo (one-shot) for difficulty + head block - (170c9d3) - Anton Velichko

- - -

## v0.8.0 - 2026-06-15
#### Features
- (**testsuite**) S045 — verify chain commits a DA batch to L1 DaInbox - (cb87569) - Anton Velichko
#### Style
- (**testsuite**) rustfmt parse_address - (17f3217) - Anton Velichko

- - -

## v0.7.0 - 2026-06-15
#### Features
- (**l2-client**) thread real referrerAddress through the SU mint flow - (94e1fb7) - Anton Velichko
- (**l2-client**) sync ABI bindings to commitment-token contract overhaul - (3516d0a) - Anton Velichko
- (**su-hash**) consume pso-protocol 0.5.0 — thread attester/referrer - (af983c7) - Anton Velichko
#### Bug Fixes
- (**testsuite**) rustfmt + re-sync S001 inline entity mirrors to current ABI - (fde26b7) - Anton Velichko
- (**wwd**) encode worldwide_day as YYYYMMDD, not days-since-2021 - (0ae542f) - Anton Velichko
#### Refactoring
- (**abi**) rename TD suHashes -> suIds to match pso-chain - (db7abdb) - Anton Velichko

- - -

## v0.6.0 - 2026-06-04
#### Features
- (**e2e**) wallet-direct topology release — refresh release & image docs - (77b4d42) - Anton Velichko
#### Tests
- (**e2e**) real wallet/SRA topology — wallet-direct TD, mobile-API sim, lifecycle scenarios - (4508ecd) - Anton Velichko
- (**e2e**) S041 — users envelope from unregistered wallet clears pool admission - (400750e) - Anton Velichko

- - -

## v0.5.0 - 2026-06-01
#### Features
- (**ci**) version-suffix release artifacts, publish Kotlin lib to GitHub Packages Maven, add dev-tools mobile slices - (45f7b10) - Anton Velichko
#### Tests
- (**mobile**) gate network-dependent SRS e2e test out of the offline unit job - (7297b94) - Anton Velichko

- - -

## v0.4.0 - 2026-05-29
#### Features
- (**mobile**) gate Grumpkin secret keys + add generate_tribute_key - (f9b13ba) - Anton Velichko

- - -

## v0.3.10 - 2026-05-27
#### Bug Fixes
- (**fmt**) apply rustfmt after settlement-prefix rename - (ac0d02d) - Anton Velichko
#### Refactoring
- drop redundant settlement prefix from SU/TD fields - (a5f9361) - Anton Velichko

- - -

## v0.3.9 - 2026-05-27
#### Bug Fixes
- (**integrations**) unify App. A KDF on spec-correct HKDF/ECDH-x - (5f4f407) - Anton Velichko
- (**mobile**) reduce nft sk mod q_Grumpkin before bb derive - (9bf5f46) - Anton Velichko
- update e2e tests according to the new SU validation errors - (cffaa17) - Qooqoot
#### Documentation
- (**aggregation**) mark SU-ownership redesign closed (2026-05-26) - (d533808) - Anton Velichko
- (**wallet**) correct stale aggregation-proof doc on submit_tribute_draft - (c6024ca) - Anton Velichko
#### Continuous Integration
- run fmt + tests on every PR; keep build/artifact jobs off PR runs - (290ea09) - Anton Velichko
#### Refactoring
- (**integrations**) unify Fr wire format on big-endian everywhere - (9b3f4bd) - Anton Velichko
- (**witness**) flip witness builders to BE; bump pso-protocol + pso-zk-circuits to ^0.3 - (b529d7d) - Anton Velichko
#### Miscellaneous Chores
- (**deps**) pin pso-zk-circuits to v0.3.0 tag, drop patch overrides - (cceb686) - Anton Velichko
#### Style
- cargo fmt (rustfmt-required multi-line on bs58 decode) - (aea2127) - Anton Velichko

- - -

## v0.3.8 - 2026-05-22
#### Bug Fixes
- (**ci**) build libbb-external.a from source for Android - (93a1ece) - Anton Velichko

- - -

## v0.3.7 - 2026-05-21
#### Bug Fixes
- (**release**) broaden verify-release identity regex to accept refs/heads/main - (018d25d) - Anton Velichko
- (**release**) downgrade cosign tooling to v3.x / v2.x action lines - (b9244a0) - Anton Velichko
- (**release**) sign release artifacts with sigstore cosign + SLSA attest - (4468aa9) - Anton Velichko
#### Miscellaneous Chores
- (**deps**) bump pso-zk-circuits git tag to v0.2.5 (first signed release) - (fa1038f) - Anton Velichko

- - -

## v0.3.6 - 2026-05-20
#### Bug Fixes
- (**release**) move Kotlin JAR from pso-mobile-integration to pso-sra-integration - (fc91b9e) - Anton Velichko

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