//! Error type for the L2 client surface.

use thiserror::Error;

/// Top-level error returned by every `pso-l2-client` function.
#[derive(Debug, Error)]
pub enum L2ClientError {
    /// Failed to parse an RPC URL or other configuration string.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// The caller asked for a signed operation but the client was
    /// constructed without a signer (or vice versa).
    #[error("operation requires a signing wallet; client was built read-only")]
    NoSigner,

    /// JSON-RPC, network, or alloy-internal error. Boxed because
    /// alloy's `RpcError` is parameterised and unwieldy to surface
    /// directly through the public API.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// Contract call reverted or returned malformed data.
    #[error("contract call failed: {0}")]
    Contract(String),

    /// `pso-protocol` formula failed (Poseidon setup, byte layout, etc.).
    #[error("protocol error: {0}")]
    Protocol(#[from] pso_protocol::ProtocolError),

    /// Witness builder or downstream crypto failed.
    #[error("witness error: {0}")]
    Witness(String),

    /// Prover (Noir/Barretenberg) failed.
    #[error("prover error: {0}")]
    Prover(String),

    /// Aggregation tier resolution failed (too many SUs).
    #[error("aggregation tier unavailable: {detail}")]
    AggregationTierUnavailable {
        /// Caller-facing reason.
        detail: String,
    },

    /// A Noir circuit this code path needs hasn't been built /
    /// compiled / canonicalized yet. Surfaces at the prover-call
    /// boundary so callers don't get a silent failure. See
    /// `docs/aggregation-redesign.md` for the redesign blocking
    /// these paths.
    #[error("circuit not available: {detail}")]
    CircuitNotAvailable {
        /// Caller-facing reason — usually points at the docs.
        detail: String,
    },

    /// Invalid input bytes — wrong length, malformed hex, etc.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// I/O failure when reading/writing JSON artifacts.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failure on artifacts.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
