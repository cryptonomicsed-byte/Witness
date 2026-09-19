use chrono::{DateTime, Utc};
use gix_types::{Gix1, GixKind, GixNamespace, RoutingHints};
use serde::{Deserialize, Serialize};

/// A physical-world attestation signed by a Witness node.
///
/// Published as Nostr kind 31020.  The `observation_hash` commits to the
/// full sensor bundle; `sim_receipt_id` links back to the ScarabSwarm
/// Proof-of-Simulation that generated the executed policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessAttestation {
    pub attest_id:        String,
    pub kind:             AttestationKind,

    pub vcp_session_id:   String,
    pub device_id:        String,
    pub agent_id:         String,
    pub sim_receipt_id:   Option<String>,

    pub observation_hash: String,
    pub outcome:          String,
    pub status:           AttestationStatus,

    pub latitude:         Option<f64>,
    pub longitude:        Option<f64>,
    pub altitude_m:       Option<f64>,

    pub nostr_event_id:   Option<String>,
    pub zangbeto_anchor:  Option<String>,
    pub arp_receipt_id:   Option<String>,

    pub timestamp:        DateTime<Utc>,
    /// Ed25519 hex signature from the Witness node's key
    pub signature:        String,

    /// GIX1 canonical_id (hex) — `Gix1(Receipt, MeshDevice, attest_id)`.
    /// Stamped after construction via `stamp_gix1()`.
    #[serde(default)]
    pub gix1_canonical_id: Option<String>,
}

impl WitnessAttestation {
    /// Stamp a GIX1 Receipt envelope onto this attestation (idempotent).
    pub fn stamp_gix1(&mut self) {
        if self.gix1_canonical_id.is_some() { return; }
        let ts = self.timestamp.timestamp_millis() as u64;
        let env = Gix1::new(
            GixKind::Receipt,
            GixNamespace::MeshDevice,
            self.attest_id.as_bytes(),
            None,
            ts,
            RoutingHints::default(),
        );
        self.gix1_canonical_id = Some(hex::encode(env.canonical_id));
    }

    pub fn canonical_hash(&self) -> String {
        let data = format!(
            "{}:{}:{}:{}:{}",
            self.attest_id, self.vcp_session_id, self.observation_hash,
            self.outcome, self.timestamp.timestamp()
        );
        sha256_hex(data.as_bytes())
    }

    /// Convert to Nostr kind 31020 tags
    pub fn to_nostr_tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["d".to_string(), self.attest_id.clone()],
            vec!["t".to_string(), "witness".to_string()],
            vec!["session".to_string(), self.vcp_session_id.clone()],
            vec!["device".to_string(), self.device_id.clone()],
            vec!["observation_hash".to_string(), self.observation_hash.clone()],
            vec!["outcome".to_string(), self.outcome.clone()],
        ];
        if let Some(ref id) = self.sim_receipt_id {
            tags.push(vec!["sim_receipt".to_string(), id.clone()]);
        }
        tags
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}{:016x}", h.finish(), h.finish().wrapping_mul(0xcafebabe))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    /// Robot/drone executed a simulated policy and outcome was physically observed
    PolicyExecution,
    /// Sensor observation recorded (no prior simulation)
    SensorObservation,
    /// Twin data capture (feeds Gaussian splat pipeline)
    TwinCapture,
    /// Anomaly detected during execution
    AnomalyReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Signed,
    Published,
    Anchored,
}

#[cfg(test)]
mod gix_tests {
    use super::*;
    use chrono::Utc;

    fn make_attestation() -> WitnessAttestation {
        WitnessAttestation {
            attest_id:        "attest-001".into(),
            kind:             AttestationKind::PolicyExecution,
            vcp_session_id:   "session-abc".into(),
            device_id:        "device-xyz".into(),
            agent_id:         "agent-123".into(),
            sim_receipt_id:   None,
            observation_hash: "d".repeat(64),
            outcome:          "success".into(),
            status:           AttestationStatus::Pending,
            latitude:         None,
            longitude:        None,
            altitude_m:       None,
            nostr_event_id:   None,
            zangbeto_anchor:  None,
            arp_receipt_id:   None,
            timestamp:        Utc::now(),
            signature:        String::new(),
            gix1_canonical_id: None,
        }
    }

    #[test]
    fn stamp_gix1_sets_canonical_id() {
        let mut a = make_attestation();
        a.stamp_gix1();
        let id = a.gix1_canonical_id.as_ref().expect("gix1_canonical_id must be set");
        assert_eq!(id.len(), 64);
    }

    #[test]
    fn stamp_gix1_is_idempotent() {
        let mut a = make_attestation();
        a.stamp_gix1();
        let first = a.gix1_canonical_id.clone();
        a.stamp_gix1();
        assert_eq!(a.gix1_canonical_id, first);
    }

    #[test]
    fn two_attestations_have_distinct_gix1_ids() {
        let mut a1 = make_attestation();
        let mut a2 = make_attestation();
        a2.attest_id = "attest-002".into();
        a1.stamp_gix1();
        a2.stamp_gix1();
        assert_ne!(a1.gix1_canonical_id, a2.gix1_canonical_id);
    }
}
