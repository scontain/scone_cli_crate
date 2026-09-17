use anyhow::{Context, Result, anyhow};

/// Finds the `CAS_KEY` in an attestation report that exposes it as a plain JSON field.
///
/// Unlike the in-process backend this does not decode certificate chains; a report that only
/// carries the key inside certificates is rejected with an error rather than guessed at.
pub(crate) fn cas_key_from_report(report_json: &str) -> Result<String> {
    let value: serde_json::Value =
        serde_json::from_str(report_json).context("Invalid CAS attestation JSON")?;
    find_cas_key(&value).ok_or_else(|| {
        anyhow!(
            "The attestation report does not expose a CAS_KEY field that this backend can read."
        )
    })
}

fn find_cas_key(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Object(object) => {
            for key in ["CAS_KEY", "cas_key", "casKey", "cas_key_hash", "casKeyHash"] {
                if let Some(found) = object.get(key).and_then(serde_json::Value::as_str) {
                    let trimmed = found.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_owned());
                    }
                }
            }
            object.values().find_map(find_cas_key)
        }
        serde_json::Value::Array(values) => values.iter().find_map(find_cas_key),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
