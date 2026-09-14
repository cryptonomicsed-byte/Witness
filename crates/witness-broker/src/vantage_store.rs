//! Witness broker ↔ Vantage witness_store wiring.
//!
//! When a WitnessAttestation arrives, this module opens a Vantage witness
//! round (POST /api/witness/rounds) so that tier-weighted peer agents can
//! vote approve/reject — the BlockMesh quorum protocol.
//!
//! Fail-open: all errors are logged and returned, never panics.

use serde::{Deserialize, Serialize};
use serde_json::json;
use witness_types::WitnessAttestation;

fn vantage_base() -> String {
    std::env::var("VANTAGE_URL").unwrap_or_else(|_| "http://127.0.0.1:8000".to_string())
}

fn vantage_key() -> Option<String> {
    std::env::var("VANTAGE_KEY").ok().filter(|s| !s.is_empty())
}

/// Response from POST /api/witness/rounds
#[derive(Debug, Deserialize)]
pub struct WitnessRound {
    pub round_id:     i64,
    pub subject_type: String,
    pub subject_id:   i64,
    pub status:       String,
}

/// Open a Vantage witness round for a physical attestation.
///
/// `subject_id` is mapped from `attest_id` (hashed to u32 for the int column).
/// The sim_receipt_id is carried through for proof binding (P0-9).
pub async fn open_round_for_attestation(
    attestation: &WitnessAttestation,
    sim_receipt_id: Option<&str>,
) -> Result<WitnessRound, String> {
    let base = vantage_base();
    let url = format!("{base}/api/witness/rounds");

    // Use first 8 hex chars of observation_hash as a stable i64 subject_id.
    let subject_id = i64::from_str_radix(&attestation.observation_hash[..8.min(attestation.observation_hash.len())], 16)
        .unwrap_or(0);

    let body = json!({
        "subject_type":      format!("witness_attestation:{:?}", attestation.kind),
        "subject_id":        subject_id,
        "artifact_url":      "",
        "description":       format!("Witness attestation {} from device {}", attestation.attest_id, attestation.device_id),
        "sim_receipt_id":    attestation.sim_receipt_id.as_deref().or(sim_receipt_id),
        "consensus_output_id": null,
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("client build: {e}"))?;

    let mut req = client.post(&url)
        .header("Content-Type", "application/json")
        .json(&body);

    if let Some(key) = vantage_key() {
        req = req.header("Authorization", format!("Bearer {key}"));
    }

    let resp = req.send().await.map_err(|e| format!("POST {url}: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Vantage /api/witness/rounds returned {status}: {text}"));
    }

    resp.json::<WitnessRound>()
        .await
        .map_err(|e| format!("parse WitnessRound: {e}"))
}

/// Cast a vote on an existing round (approve/reject) as the broker agent.
pub async fn cast_vote(
    round_id: i64,
    vote: &str,
    comment: &str,
) -> Result<(), String> {
    let base = vantage_base();
    let url = format!("{base}/api/witness/rounds/{round_id}/vote");

    let body = json!({ "vote": vote, "comment": comment });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("client build: {e}"))?;

    let mut req = client.post(&url)
        .header("Content-Type", "application/json")
        .json(&body);

    if let Some(key) = vantage_key() {
        req = req.header("Authorization", format!("Bearer {key}"));
    }

    req.send().await
        .map_err(|e| format!("POST {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("vote error: {e}"))?;
    Ok(())
}
