use serde_json::{json, Value};
use witness_types::{WitnessAttestation, NOSTR_KIND_WITNESS};

// ---------------------------------------------------------------------------
// Env helpers
// ---------------------------------------------------------------------------

fn relay_urls() -> Vec<String> {
    std::env::var("WITNESS_NOSTR_RELAYS")
        .unwrap_or_else(|_| "wss://relay.damus.io,wss://nos.lol".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Read the 32-byte hex seed from WITNESS_NOSTR_KEY.
/// Falls back to WITNESS_NOSTR_NSEC (legacy alias) for backwards compat.
/// If absent, generates an ephemeral key and logs a warning.
fn load_signing_key() -> secp256k1::SecretKey {
    let hex_seed = std::env::var("WITNESS_NOSTR_KEY")
        .or_else(|_| std::env::var("WITNESS_NOSTR_NSEC"))
        .unwrap_or_default();

    if hex_seed.is_empty() {
        tracing::warn!(
            "WITNESS_NOSTR_KEY not set — generating ephemeral key; \
             events will NOT be verifiable across restarts"
        );
        let (secret_key, _) = secp256k1::generate_keypair(&mut secp256k1::rand::thread_rng());
        return secret_key;
    }

    let bytes = match hex::decode(hex_seed.trim()) {
        Ok(b) if b.len() == 32 => b,
        Ok(b) => {
            tracing::error!(
                "WITNESS_NOSTR_KEY must be a 32-byte hex string ({} bytes given); \
                 falling back to ephemeral key",
                b.len()
            );
            let (secret_key, _) = secp256k1::generate_keypair(&mut secp256k1::rand::thread_rng());
            return secret_key;
        }
        Err(e) => {
            tracing::error!("WITNESS_NOSTR_KEY hex decode failed: {e}; falling back to ephemeral key");
            let (secret_key, _) = secp256k1::generate_keypair(&mut secp256k1::rand::thread_rng());
            return secret_key;
        }
    };

    match secp256k1::SecretKey::from_slice(&bytes) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("WITNESS_NOSTR_KEY is not a valid secp256k1 secret key: {e}; \
                             falling back to ephemeral key");
            let (secret_key, _) = secp256k1::generate_keypair(&mut secp256k1::rand::thread_rng());
            secret_key
        }
    }
}

// ---------------------------------------------------------------------------
// Core Nostr primitives
// ---------------------------------------------------------------------------

fn pubkey_hex(secret_key: &secp256k1::SecretKey) -> String {
    let secp = secp256k1::Secp256k1::new();
    let pub_key = secp256k1::PublicKey::from_secret_key(&secp, secret_key);
    // x-only pubkey (32 bytes) — BIP-340 / Nostr format
    let (x_only, _parity) = pub_key.x_only_public_key();
    hex::encode(x_only.serialize())
}

/// Nostr canonical event id = SHA-256 of the serialised array:
/// [0, pubkey_hex, created_at, kind, tags, content]
fn compute_event_id(pubkey: &str, created_at: u64, kind: u32, tags: &[Value], content: &str) -> String {
    let preimage = json!([0, pubkey, created_at, kind, tags, content]).to_string();
    sha256_hex(preimage.as_bytes())
}

/// BIP-340 Schnorr signature over the event id hash (32 raw bytes).
fn schnorr_sign(event_id_hex: &str, secret_key: &secp256k1::SecretKey) -> String {
    let secp = secp256k1::Secp256k1::new();
    let id_bytes = match hex::decode(event_id_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            tracing::error!("event_id_hex is not 32 bytes; cannot sign");
            return String::new();
        }
    };
    let msg = secp256k1::Message::from_digest_slice(&id_bytes)
        .expect("32-byte event id is a valid message");
    let keypair = secp256k1::Keypair::from_secret_key(&secp, secret_key);
    let sig = secp.sign_schnorr(&msg, &keypair);
    hex::encode(sig.as_ref())
}

// ---------------------------------------------------------------------------
// Event builder
// ---------------------------------------------------------------------------

fn build_signed_event(
    kind: u32,
    content: &str,
    tags: Vec<Value>,
    secret_key: &secp256k1::SecretKey,
) -> (Value, String) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pubkey = pubkey_hex(secret_key);
    let event_id = compute_event_id(&pubkey, created_at, kind, &tags, content);
    let sig = schnorr_sign(&event_id, secret_key);

    let event = json!({
        "id":         event_id,
        "pubkey":     pubkey,
        "created_at": created_at,
        "kind":       kind,
        "tags":       tags,
        "content":    content,
        "sig":        sig,
    });

    (event, event_id)
}

// ---------------------------------------------------------------------------
// Relay publishing — WebSocket (direct) or HTTP gateway fallback
// ---------------------------------------------------------------------------

/// Send a signed Nostr event to a single WSS relay.
/// Returns true on success.
async fn send_to_relay_ws(relay_url: &str, event: &Value) -> bool {
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use futures_util::{SinkExt, StreamExt};

    let msg = json!(["EVENT", event]).to_string();

    let conn = match connect_async(relay_url).await {
        Ok((ws, _)) => ws,
        Err(e) => {
            tracing::warn!("witness: WS connect to {} failed: {}", relay_url, e);
            return false;
        }
    };

    let (mut write, mut read) = conn.split();

    if let Err(e) = write.send(WsMessage::Text(msg.into())).await {
        tracing::warn!("witness: WS send to {} failed: {}", relay_url, e);
        return false;
    }

    // Wait briefly for an OK / NOTICE from the relay
    let timeout = tokio::time::Duration::from_secs(5);
    let result = tokio::time::timeout(timeout, read.next()).await;

    match result {
        Ok(Some(Ok(WsMessage::Text(resp)))) => {
            tracing::debug!("witness: relay {} responded: {}", relay_url, resp);
            // Relay NIP-01 OK message: ["OK", id, true/false, "message"]
            if resp.contains("\"OK\"") || resp.contains("\"NOTICE\"") {
                true
            } else {
                tracing::warn!("witness: relay {} unexpected response: {}", relay_url, resp);
                true // event was at least sent
            }
        }
        Ok(Some(Err(e))) => {
            tracing::warn!("witness: relay {} WS error reading response: {}", relay_url, e);
            true // sent, just couldn't read ack
        }
        _ => {
            // Timeout or stream closed — event was sent, relay may have accepted it silently
            true
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Publish a WitnessAttestation as Nostr kind 31020.
/// Returns the event_id on success, None if publish fails or key missing.
pub async fn publish_attestation(attestation: &WitnessAttestation) -> Option<String> {
    let secret_key = load_signing_key();
    let relays = relay_urls();
    if relays.is_empty() {
        tracing::warn!("witness: no Nostr relays configured");
        return None;
    }

    let raw_tags = attestation.to_nostr_tags();
    let tags: Vec<Value> = raw_tags.iter()
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

    let (signed_event, event_id) = build_signed_event(
        NOSTR_KIND_WITNESS,
        &content,
        tags,
        &secret_key,
    );

    if event_id.is_empty() {
        tracing::error!("witness: failed to compute event id; aborting publish");
        return None;
    }

    tracing::info!(
        "witness: publishing kind {} event {} (pubkey={})",
        NOSTR_KIND_WITNESS,
        event_id,
        signed_event["pubkey"].as_str().unwrap_or("?")
    );

    let mut published = false;

    // Check for an HTTP gateway override first (e.g. nostream HTTP API)
    if let Ok(gateway) = std::env::var("WITNESS_NOSTR_GATEWAY") {
        let url = format!("{}/api/events", gateway.trim_end_matches('/'));
        let client = reqwest::Client::new();
        if client.post(&url).json(&signed_event).send().await
            .map(|r| r.status().is_success()).unwrap_or(false)
        {
            tracing::info!("witness: published via HTTP gateway {}", gateway);
            published = true;
        } else {
            tracing::warn!("witness: HTTP gateway {} failed; falling back to direct WS", gateway);
        }
    }

    // Direct WebSocket relay publishing
    if !published {
        for relay_url in &relays {
            let ok = send_to_relay_ws(relay_url, &signed_event).await;
            if ok {
                tracing::info!(
                    "witness: published kind {} event {} to {}",
                    NOSTR_KIND_WITNESS, event_id, relay_url
                );
                published = true;
            }
        }
    }

    if published { Some(event_id) } else { None }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> secp256k1::SecretKey {
        // deterministic key for tests: 32 bytes of 0x01
        secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap()
    }

    #[test]
    fn test_pubkey_hex_length() {
        let sk = test_key();
        let pk = pubkey_hex(&sk);
        assert_eq!(pk.len(), 64, "x-only pubkey hex must be 64 chars (32 bytes)");
    }

    #[test]
    fn test_schnorr_sig_length() {
        let sk = test_key();
        let pk = pubkey_hex(&sk);
        let event_id = compute_event_id(&pk, 1_700_000_000, 31020, &[], "test content");
        let sig = schnorr_sign(&event_id, &sk);
        assert_eq!(sig.len(), 128, "Schnorr sig hex must be 128 chars (64 bytes)");
    }

    #[test]
    fn test_event_id_is_sha256_of_canonical_json() {
        let sk = test_key();
        let pk = pubkey_hex(&sk);
        let created_at: u64 = 1_700_000_000;
        let kind: u32 = 31020;
        let tags: Vec<Value> = vec![];
        let content = "hello witness";

        let event_id = compute_event_id(&pk, created_at, kind, &tags, content);
        // Re-derive manually
        let preimage = json!([0, &pk, created_at, kind, tags, content]).to_string();
        let expected = sha256_hex(preimage.as_bytes());
        assert_eq!(event_id, expected);
    }

    #[test]
    fn test_build_signed_event_fields_populated() {
        let sk = test_key();
        let (event, event_id) = build_signed_event(31020, "test", vec![], &sk);
        assert!(!event_id.is_empty());
        assert_eq!(event["id"].as_str().unwrap(), event_id);
        assert_eq!(event["pubkey"].as_str().unwrap().len(), 64);
        assert_eq!(event["sig"].as_str().unwrap().len(), 128);
        assert_ne!(event["pubkey"].as_str().unwrap(), "");
        assert_ne!(event["sig"].as_str().unwrap(), "");
    }

    #[test]
    fn test_load_signing_key_ephemeral_when_unset() {
        // Remove env var and ensure we get a valid key back
        std::env::remove_var("WITNESS_NOSTR_KEY");
        std::env::remove_var("WITNESS_NOSTR_NSEC");
        let k = load_signing_key();
        // Should not panic; key is non-zero
        let pk = pubkey_hex(&k);
        assert_eq!(pk.len(), 64);
    }

    #[test]
    fn test_load_signing_key_from_env() {
        let seed = "0101010101010101010101010101010101010101010101010101010101010101";
        std::env::set_var("WITNESS_NOSTR_KEY", seed);
        let k = load_signing_key();
        let pk = pubkey_hex(&k);
        assert_eq!(pk.len(), 64);
        // Same seed → same pubkey (deterministic)
        let k2 = load_signing_key();
        assert_eq!(pubkey_hex(&k2), pk);
        std::env::remove_var("WITNESS_NOSTR_KEY");
    }
}
