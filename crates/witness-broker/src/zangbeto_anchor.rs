use serde_json::json;

fn zangbeto_base() -> String {
    std::env::var("ZANGBETO_URL")
        .or_else(|_| std::env::var("VANTAGE_API_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string())
}

fn api_key() -> String {
    std::env::var("VANTAGE_API_KEY").unwrap_or_default()
}

/// Anchor a WitnessAttestation to Zàngbétò (the sovereign ledger).
/// Returns the anchor_id (receipt hash from Zàngbétò) on success.
pub async fn anchor_attestation(
    attest_id: &str,
    canonical_hash: &str,
    nostr_event_id: Option<&str>,
) -> Option<String> {
    let client = reqwest::Client::new();
    let key = api_key();

    let body = json!({
        "kind":          "witness_attestation",
        "object_id":     attest_id,
        "canonical_hash": canonical_hash,
        "nostr_event_id": nostr_event_id,
        "timestamp": now_secs(),
    });

    let url = format!("{}/api/zangbeto/records", zangbeto_base());
    let mut req = client.post(&url).json(&body)
        .timeout(std::time::Duration::from_secs(8));
    if !key.is_empty() {
        req = req.header("X-Agent-Key", &key);
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            resp.json::<serde_json::Value>().await.ok()
                .and_then(|v| v.get("anchor_id").and_then(|a| a.as_str()).map(String::from))
        }
        Ok(resp) => {
            tracing::debug!("zangbeto anchor: {}", resp.status());
            None
        }
        Err(e) => {
            tracing::debug!("zangbeto unreachable: {e}");
            None
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
