//! Scenario registry.
//!
//! Each scenario lives in `sNNN_*.rs` and exports a unit struct
//! implementing [`Scenario`](crate::scenario::Scenario). The CLI
//! driver collects them via [`all`] in canonical order — the same
//! order the markdown / JSON report prints.

pub mod s001_happy_flow;
pub mod s002_sra_cannot_td_via_agents_pool;
pub mod s003_wallet_cannot_register_sr;
pub mod s004_wallet_cannot_register_ar;
pub mod s005_wallet_cannot_mint_su;
pub mod s006_sra_cannot_use_actor_endpoint;
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
pub mod s024_td_aggregation_tier_unavailable_rejected;

use crate::scenario::Scenario;

/// Collect every scenario in canonical order. Listed top-to-bottom
/// so the printed report matches the spec table.
pub fn all() -> Vec<Box<dyn Scenario>> {
    vec![
        Box::new(s001_happy_flow::S001),
        Box::new(s002_sra_cannot_td_via_agents_pool::S002),
        Box::new(s003_wallet_cannot_register_sr::S003),
        Box::new(s004_wallet_cannot_register_ar::S004),
        Box::new(s005_wallet_cannot_mint_su::S005),
        Box::new(s006_sra_cannot_use_actor_endpoint::S006),
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
        Box::new(s024_td_aggregation_tier_unavailable_rejected::S024),
    ]
}
