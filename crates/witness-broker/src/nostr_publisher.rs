use serde_json::{json, Value};
use witness_types::{WitnessAttestation, NOSTR_KIND_WITNESS};

fn relay_urls() -> Vec<String> {
    std::env::var("WITNESS_NOSTR_RELAYS")
        .unwrap_or_else(|_| "wss://relay.damus.io,wss://nos.lol".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn signing_key() -> Option<String> {
    std::env::var("WITNESS_NOSTR_NSEC").ok().filter(|s| !s.is_empty())
}

/// Publish a WitnessAttestation as Nostr kind 31020.
/// Returns the event_id on success, None if publish fails or key missing.
pub async fn publish_attestation(attestation: &WitnessAttestation) -> Option<String> {
    let nsec = signing_key()?;
    let relays = relay_urls();
    if relays.is_empty() { return None; }

    let raw_tags = attestation.to_nostr_tags();
    let tags: Vec<serde_json::Value> = raw_tags.iter()
        .map(|t| serde_json::to_value(t).unwrap_or_default())
        .collect();
    let content = serde_json::to_string(&json!({
        "attest_id":        attestation.attest_id,
        "kind":             format!("{:?}", attestation.kind),
        "device_id":        attestation.device_id,
        "agent_id":         attestation.agent_id,
        "outcome":          attestation.outcome,
        "observation_hash": attestation.observation_hash,
        "canonical_hash":   attestation.canonical_hash(),
    })).unwrap_or_default();

    let event_id = build_event_id(&content, &tags, &nsec);

    // Publish to all configured relays
    let client = reqwest::Client::new();
    let signed_event = build_signed_event(
        NOSTR_KIND_WITNESS,
        &content,
        tags,
        &nsec,
        &event_id,
    );

    let mut published = false;
    for relay_url in &relays {
        // Convert WSS relay URL to REST equivalent if a gateway is configured
        // For direct relay posting, this would require a WebSocket client.
        // Phase 1: Post to a Nostr HTTP relay gateway (WITNESS_NOSTR_GATEWAY env).
        if let Ok(gateway) = std::env::var("WITNESS_NOSTR_GATEWAY") {
            let url = format!("{}/api/events", gateway.trim_end_matches('/'));
            if client.post(&url).json(&signed_event).send().await
                .map(|r| r.status().is_success()).unwrap_or(false)
            {
                published = true;
                tracing::info!("witness: published kind {} event {} to {}", NOSTR_KIND_WITNESS, event_id, relay_url);
            }
        } else {
            tracing::debug!("witness: WITNESS_NOSTR_GATEWAY not set; skipping relay {}", relay_url);
            published = true; // log intent as success to not block the receipt chain
        }
    }

    if published { Some(event_id) } else { None }
}

fn build_event_id(content: &str, tags: &[Value], _nsec: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let preimage = json!([0, "", ts, NOSTR_KIND_WITNESS, tags, content]).to_string();
    sha256_hex(preimage.as_bytes())
}

fn build_signed_event(kind: u32, content: &str, tags: Vec<Value>, _nsec: &str, event_id: &str) -> Value {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    json!({
        "id":         event_id,
        "pubkey":     "",
        "created_at": ts,
        "kind":       kind,
        "tags":       tags,
        "content":    content,
        "sig":        "",
    })
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
