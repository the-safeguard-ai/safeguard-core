//! Outbound DLP for streamed (SSE) responses.
//!
//! The non-streaming path scans the whole model response before returning it.
//! For streaming we can't wait for the end, so this transforms the upstream SSE
//! stream on the fly: it accumulates `delta.content`, redacts settled text, and
//! re-emits OpenAI-compatible chunks — holding back a tail window so a PII match
//! that straddles chunk boundaries is still caught before anything is sent.
//!
//! Non-content frames (role, finish_reason, usage) and `[DONE]` are preserved so
//! clients see a valid stream. Block/flag are inbound concerns; only `redact`
//! policies affect the response, so a passthrough is used when none apply.

use axum::body::Bytes;
use dlp::{Action, Policy};
use futures::{Stream, StreamExt};
use serde_json::Value;

/// Chars kept unsent at the tail so a detector match spanning chunk boundaries
/// isn't emitted partially. Comfortably covers SSN/card/phone/IBAN/most emails.
const HOLDBACK: usize = 64;

/// True if any enabled policy would redact response text (the only action that
/// matters for outbound streaming).
pub fn has_outbound_redaction(policies: &[Policy]) -> bool {
    policies
        .iter()
        .any(|p| p.enabled && p.action == Action::Redact && !p.patterns.is_empty())
}

struct State<S> {
    upstream: S,
    /// Raw SSE bytes received but not yet split into complete events.
    raw: String,
    /// Decoded model text accepted but not yet emitted (redaction buffer).
    pending: String,
    id: Option<String>,
    model: Option<String>,
    policies: Vec<Policy>,
    upstream_done: bool,
    emitted_done: bool,
}

/// Wrap an upstream SSE byte stream with on-the-fly outbound redaction.
pub fn redact_sse<S, E>(
    upstream: S,
    policies: Vec<Policy>,
) -> impl Stream<Item = Result<Bytes, std::io::Error>>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    let state = State {
        upstream,
        raw: String::new(),
        pending: String::new(),
        id: None,
        model: None,
        policies,
        upstream_done: false,
        emitted_done: false,
    };

    futures::stream::unfold(state, |mut st| async move {
        loop {
            if st.emitted_done {
                return None;
            }
            if st.upstream_done {
                // Upstream finished: flush whatever remains, then end the stream.
                st.emitted_done = true;
                let mut out = frame(
                    &st.id,
                    &st.model,
                    &release(&mut st.pending, &st.policies, true),
                );
                if !st.raw.trim().is_empty() {
                    // Any trailing partial event without a terminator — pass through.
                    out.push_str(st.raw.trim());
                    out.push_str("\n\n");
                }
                out.push_str("data: [DONE]\n\n");
                return Some((Ok(Bytes::from(out)), st));
            }

            match st.upstream.next().await {
                Some(Ok(bytes)) => {
                    st.raw.push_str(&String::from_utf8_lossy(&bytes));
                    let out = drain_events(&mut st);
                    if !out.is_empty() {
                        return Some((Ok(Bytes::from(out)), st));
                    }
                    // No complete event yet — keep pulling.
                }
                Some(Err(e)) => {
                    st.emitted_done = true;
                    return Some((Err(std::io::Error::other(e.to_string())), st));
                }
                None => {
                    st.upstream_done = true;
                }
            }
        }
    })
}

/// Split the raw buffer into complete `\n\n`-terminated SSE events and process
/// each, returning the bytes to emit downstream.
fn drain_events<S>(st: &mut State<S>) -> String {
    let mut out = String::new();
    while let Some(idx) = st.raw.find("\n\n") {
        let event = st.raw[..idx].to_string();
        st.raw.drain(..idx + 2);
        process_event(st, &event, &mut out);
    }
    out
}

fn process_event<S>(st: &mut State<S>, event: &str, out: &mut String) {
    // An SSE event may carry comment lines; we only care about `data:` payloads.
    let Some(payload) = event.lines().find_map(|l| l.strip_prefix("data:")) else {
        return;
    };
    let payload = payload.trim();

    if payload == "[DONE]" {
        out.push_str(&frame(
            &st.id,
            &st.model,
            &release(&mut st.pending, &st.policies, true),
        ));
        out.push_str("data: [DONE]\n\n");
        st.emitted_done = true;
        return;
    }

    let Ok(json) = serde_json::from_str::<Value>(payload) else {
        // Unparseable frame — forward verbatim rather than drop data.
        out.push_str("data: ");
        out.push_str(payload);
        out.push_str("\n\n");
        return;
    };

    if st.id.is_none() {
        st.id = json.get("id").and_then(|v| v.as_str()).map(String::from);
    }
    if st.model.is_none() {
        st.model = json.get("model").and_then(|v| v.as_str()).map(String::from);
    }

    let choice = json.get("choices").and_then(|c| c.get(0));
    let content = choice
        .and_then(|c| c.get("delta"))
        .and_then(|d| d.get("content"))
        .and_then(|v| v.as_str());
    let finish = choice
        .and_then(|c| c.get("finish_reason"))
        .filter(|v| !v.is_null())
        .and_then(|v| v.as_str())
        .map(String::from);

    if let Some(c) = content {
        st.pending.push_str(c);
        let settled = release(&mut st.pending, &st.policies, false);
        out.push_str(&frame(&st.id, &st.model, &settled));
    }

    if let Some(reason) = finish {
        // Flush everything before signalling completion, then emit a finish frame.
        out.push_str(&frame(
            &st.id,
            &st.model,
            &release(&mut st.pending, &st.policies, true),
        ));
        out.push_str(&finish_frame(&st.id, &st.model, &reason));
    } else if content.is_none() {
        // Role-only / usage / other frames: pass through unchanged.
        out.push_str("data: ");
        out.push_str(payload);
        out.push_str("\n\n");
    }
}

/// Move settled (fully-received, non-straddling) text out of `pending`, redacted.
/// Keeps a `HOLDBACK` tail (unless `flush_all`) and never cuts through a match.
fn release(pending: &mut String, policies: &[Policy], flush_all: bool) -> String {
    if pending.is_empty() {
        return String::new();
    }
    let res = dlp::scan(pending, policies);

    // Target cut in ORIGINAL coordinates.
    let mut target = if flush_all {
        pending.len()
    } else {
        pending.len().saturating_sub(HOLDBACK)
    };
    // Pull back so we never cut through a finding that extends past the target.
    for f in &res.findings {
        if f.start < target && f.end > target {
            target = f.start;
        }
    }
    // Snap to a char boundary.
    while target > 0 && !pending.is_char_boundary(target) {
        target -= 1;
    }
    if target == 0 {
        return String::new();
    }

    // Redact findings fully within [0, target) of the prefix, right-to-left.
    let prefix = &pending[..target];
    let mut text = prefix.to_string();
    let mut settled: Vec<_> = res.findings.iter().filter(|f| f.end <= target).collect();
    settled.sort_by_key(|f| std::cmp::Reverse(f.start));
    for f in settled {
        text.replace_range(f.start..f.end, &format!("[REDACTED:{}]", f.label));
    }

    *pending = pending[target..].to_string();
    text
}

/// Build an OpenAI-compatible chunk frame carrying `content` (empty → no frame).
fn frame(id: &Option<String>, model: &Option<String>, content: &str) -> String {
    if content.is_empty() {
        return String::new();
    }
    let json = serde_json::json!({
        "id": id.clone().unwrap_or_default(),
        "object": "chat.completion.chunk",
        "model": model.clone().unwrap_or_default(),
        "choices": [{ "index": 0, "delta": { "content": content }, "finish_reason": Value::Null }],
    });
    format!("data: {json}\n\n")
}

fn finish_frame(id: &Option<String>, model: &Option<String>, reason: &str) -> String {
    let json = serde_json::json!({
        "id": id.clone().unwrap_or_default(),
        "object": "chat.completion.chunk",
        "model": model.clone().unwrap_or_default(),
        "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }],
    });
    format!("data: {json}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    fn redact_policy() -> Vec<Policy> {
        vec![Policy {
            name: "t".into(),
            enabled: true,
            patterns: vec!["email".into()],
            action: Action::Redact,
        }]
    }

    async fn collect(chunks: Vec<&str>, policies: Vec<Policy>) -> String {
        let up = stream::iter(
            chunks
                .into_iter()
                .map(|c| Ok::<_, std::convert::Infallible>(Bytes::from(c.to_string()))),
        );
        let mut s = Box::pin(redact_sse(up, policies));
        let mut out = String::new();
        while let Some(Ok(b)) = s.next().await {
            out.push_str(&String::from_utf8_lossy(&b));
        }
        out
    }

    #[tokio::test]
    async fn redacts_email_split_across_chunks() {
        // The email is split mid-token across two SSE frames.
        let chunks = vec![
            "data: {\"id\":\"1\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"mail me at jane@ac\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"me.co now\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        ];
        let out = collect(chunks, redact_policy()).await;
        assert!(out.contains("[REDACTED:EMAIL]"), "got: {out}");
        assert!(!out.contains("jane@acme.co"), "leaked: {out}");
        assert!(out.contains("data: [DONE]"));
        assert!(out.contains("\"finish_reason\":\"stop\""));
    }

    #[tokio::test]
    async fn passes_clean_text_through() {
        let chunks = vec![
            "data: {\"id\":\"1\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"hello world\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        ];
        let out = collect(chunks, redact_policy()).await;
        assert!(out.contains("hello world"), "got: {out}");
        assert!(out.contains("data: [DONE]"));
    }
}
