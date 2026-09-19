use chrono::{DateTime, Utc};
use gix_types::{Gix1, GixKind, GixNamespace, RoutingHints};
use serde::{Deserialize, Serialize};

/// A bundle of sensor readings captured during a physical execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationBundle {
    pub bundle_id:   String,
    pub device_id:   String,
    pub session_id:  String,
    pub readings:    Vec<SensorReading>,
    pub duration_ms: u64,
    pub hash:        String,
    pub captured_at: DateTime<Utc>,

    /// GIX1 canonical_id (hex) — `Gix1(Receipt, MeshDevice, bundle_id)`.
    /// Stamped via `stamp_gix1()` after `hash` is finalised.
    #[serde(default)]
    pub gix1_canonical_id: Option<String>,
}

impl ObservationBundle {
    /// Stamp a GIX1 Receipt envelope onto this bundle (idempotent).
    /// Call after `self.hash = self.compute_hash()`.
    pub fn stamp_gix1(&mut self) {
        if self.gix1_canonical_id.is_some() { return; }
        let ts = self.captured_at.timestamp_millis() as u64;
        let env = Gix1::new(
            GixKind::Receipt,
            GixNamespace::MeshDevice,
            self.bundle_id.as_bytes(),
            None,
            ts,
            RoutingHints::default(),
        );
        self.gix1_canonical_id = Some(hex::encode(env.canonical_id));
    }

    pub fn compute_hash(&self) -> String {
        let data: String = self.readings.iter()
            .map(|r| format!("{}:{}:{}", r.channel, r.value, r.timestamp_ms))
            .collect::<Vec<_>>()
            .join("|");
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        data.hash(&mut h);
        format!("{:016x}", h.finish())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorReading {
    pub channel:      String,
    pub value:        f64,
    pub unit:         String,
    pub timestamp_ms: u64,
    pub quality:      f32,
}

/// A single high-level physical observation (summary of a bundle).
#[cfg(test)]
mod gix_tests {
    use super::*;
    use chrono::Utc;

    fn make_bundle() -> ObservationBundle {
        ObservationBundle {
            bundle_id:         "bundle-001".into(),
            device_id:         "device-xyz".into(),
            session_id:        "session-abc".into(),
            readings:          vec![],
            duration_ms:       500,
            hash:              String::new(),
            captured_at:       Utc::now(),
            gix1_canonical_id: None,
        }
    }

    #[test]
    fn stamp_gix1_sets_canonical_id() {
        let mut b = make_bundle();
        b.stamp_gix1();
        assert!(b.gix1_canonical_id.is_some());
        assert_eq!(b.gix1_canonical_id.unwrap().len(), 64);
    }

    #[test]
    fn stamp_gix1_is_idempotent() {
        let mut b = make_bundle();
        b.stamp_gix1();
        let first = b.gix1_canonical_id.clone();
        b.stamp_gix1();
        assert_eq!(b.gix1_canonical_id, first);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalObservation {
    pub obs_id:      String,
    pub bundle_id:   String,
    pub agent_id:    String,
    pub description: String,
    pub outcome:     String,
    pub confidence:  f32,
    pub timestamp:   DateTime<Utc>,
}
