//! Scenario registry.
//!
//! Each scenario lives in `sNNN_*.rs` and exports a unit struct
//! implementing [`Scenario`](crate::scenario::Scenario). The CLI
//! driver collects them via [`all`] in canonical order — the same
//! order the markdown / JSON report prints.

pub mod s001_happy_flow;
pub mod s002_attester_cannot_td_via_agents_pool;
pub mod s003_wallet_cannot_register_sr;
pub mod s004_wallet_cannot_register_ar;
pub mod s005_wallet_cannot_mint_su;
pub mod s006_attester_cannot_use_actor_endpoint;
pub mod s007_sr_duplicate_id_rejected;
pub mod s008_sr_id_zero_rejected;
pub mod s009_su_with_foreign_sr_rejected;
pub mod s010_su_double_spend_rejected;
pub mod s011_su_with_nonexistent_sr_rejected;
pub mod s012_td_empty_array_rejected;
pub mod s013_envelope_bad_magic_rejected;
pub mod s014_envelope_nullifier_replay_rejected;
pub mod s015_envelope_stale_submitted_block_rejected;
pub mod s016_envelope_bad_vdf_proof_rejected;
pub mod s017_envelope_wrong_vdf_output_rejected;
pub mod s018_td_malformed_aggregation_proof_rejected;
pub mod s019_td_invalid_aggregation_proof_rejected;
pub mod s020_su_with_foreign_ar_rejected;
pub mod s021_td_su_not_found_rejected;
pub mod s022_td_not_same_worldwide_day_rejected;
pub mod s023_td_not_same_currency_rejected;
pub mod s026_su_invalid_amount_rejected;
pub mod s027_registry_not_admin_rejected;
pub mod s028_registry_zero_address_rejected;
pub mod s029_registry_invalid_mask_rejected;
pub mod s030_attester_not_active_rejected;
pub mod s031_envelope_wrong_difficulty_rejected;
pub mod s032_envelope_previous_difficulty_accepted;
pub mod s033_revoked_attester_submit_rejected;
pub mod s035_update_mask_round_trip;
pub mod s036_rotation_candidate_round_trip;
pub mod s037_revoke_unknown_rejected;
// S038 (SequencerEpoch) + S039/S040 (SlashingVerifier) removed: the new chain
// has no such L2 contracts — sequencer-epoch/leader election and slashing live
// in the consensus layer (pso-chain-node consensus/slashing.rs, pso-da
// election.rs, pso-rotation anchor.rs), not at 0x5200..02/03.
pub mod s041_users_envelope_unregistered_wallet_admitted;
pub mod s042_mobile_api_wallet_flow;
pub mod s043_envelope_aged_proof_accepted;
pub mod s044_wallet_nonce_lifecycle;
pub mod s045_da_batch_committed;

use crate::scenario::Scenario;

/// Collect every scenario in canonical order. Listed top-to-bottom
/// so the printed report matches the spec table.
pub fn all() -> Vec<Box<dyn Scenario>> {
    vec![
        Box::new(s001_happy_flow::S001),
        Box::new(s002_attester_cannot_td_via_agents_pool::S002),
        Box::new(s003_wallet_cannot_register_sr::S003),
        Box::new(s004_wallet_cannot_register_ar::S004),
        Box::new(s005_wallet_cannot_mint_su::S005),
        Box::new(s006_attester_cannot_use_actor_endpoint::S006),
        Box::new(s007_sr_duplicate_id_rejected::S007),
        Box::new(s008_sr_id_zero_rejected::S008),
        Box::new(s009_su_with_foreign_sr_rejected::S009),
        Box::new(s010_su_double_spend_rejected::S010),
        Box::new(s011_su_with_nonexistent_sr_rejected::S011),
        Box::new(s012_td_empty_array_rejected::S012),
        Box::new(s013_envelope_bad_magic_rejected::S013),
        Box::new(s014_envelope_nullifier_replay_rejected::S014),
        Box::new(s015_envelope_stale_submitted_block_rejected::S015),
        Box::new(s016_envelope_bad_vdf_proof_rejected::S016),
        Box::new(s017_envelope_wrong_vdf_output_rejected::S017),
        Box::new(s018_td_malformed_aggregation_proof_rejected::S018),
        Box::new(s019_td_invalid_aggregation_proof_rejected::S019),
        Box::new(s020_su_with_foreign_ar_rejected::S020),
        Box::new(s021_td_su_not_found_rejected::S021),
        Box::new(s022_td_not_same_worldwide_day_rejected::S022),
        Box::new(s023_td_not_same_currency_rejected::S023),
        Box::new(s026_su_invalid_amount_rejected::S026),
        Box::new(s027_registry_not_admin_rejected::S027),
        Box::new(s028_registry_zero_address_rejected::S028),
        Box::new(s029_registry_invalid_mask_rejected::S029),
        Box::new(s030_attester_not_active_rejected::S030),
        Box::new(s031_envelope_wrong_difficulty_rejected::S031),
        Box::new(s032_envelope_previous_difficulty_accepted::S032),
        Box::new(s033_revoked_attester_submit_rejected::S033),
        Box::new(s035_update_mask_round_trip::S035),
        Box::new(s036_rotation_candidate_round_trip::S036),
        Box::new(s037_revoke_unknown_rejected::S037),
        Box::new(s041_users_envelope_unregistered_wallet_admitted::S041),
        Box::new(s042_mobile_api_wallet_flow::S042),
        Box::new(s043_envelope_aged_proof_accepted::S043),
        Box::new(s044_wallet_nonce_lifecycle::S044),
        // S045 needs L1/DaInbox wiring; main() drops it when --l1-rpc-url
        // is absent, so it only runs where the DA path is exposed.
        Box::new(s045_da_batch_committed::S045),
    ]
}
