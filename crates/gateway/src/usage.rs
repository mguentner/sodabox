//! Reading token usage out of a provider's response as it streams through.
//!
//! The gateway forwards response bytes unchanged; the scanner looks at a copy
//! of them. Each API reports usage differently:
//!
//! - OpenAI-compatible SSE (`data: {…}` lines): a chunk with a non-null
//!   `usage` object, normally the last one. OpenAI only sends it when the
//!   request sets `stream_options.include_usage`; Mistral sends it anyway.
//! - Ollama NDJSON: the line with `"done": true` carries `prompt_eval_count`
//!   and `eval_count`.
//! - Non-streamed responses: the whole body is one JSON object with the same
//!   fields.

use serde_json::Value;
use sodabox_common::event::Tokens;

/// Longest line kept while looking for usage. A usage line is small; longer
/// lines are content, and are skipped instead of buffered without bound.
const MAX_LINE: usize = 1 << 20;
/// Largest non-streamed body kept for parsing usage.
const MAX_BODY: usize = 16 << 20;

/// How the response is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// OpenAI-compatible server-sent events.
    OpenaiSse,
    /// One OpenAI-compatible JSON object.
    OpenaiJson,
    /// Ollama newline-delimited JSON.
    OllamaNdjson,
    /// One Ollama JSON object.
    OllamaJson,
}

/// Collects usage from response bytes fed to it in arbitrary chunks.
#[derive(Debug)]
pub struct UsageScanner {
    framing: Framing,
    buf: Vec<u8>,
    /// The current line grew past [`MAX_LINE`]; skip until its end.
    skipping: bool,
    tokens: Option<Tokens>,
}

impl UsageScanner {
    pub fn new(framing: Framing) -> Self {
        Self {
            framing,
            buf: Vec::new(),
            skipping: false,
            tokens: None,
        }
    }

    /// Feed the next chunk of the response body.
    pub fn feed(&mut self, mut data: &[u8]) {
        if matches!(self.framing, Framing::OpenaiJson | Framing::OllamaJson) {
            if self.buf.len() + data.len() <= MAX_BODY {
                self.buf.extend_from_slice(data);
            } else {
                self.skipping = true;
            }
            return;
        }
        while let Some(nl) = data.iter().position(|&b| b == b'\n') {
            if !self.skipping {
                self.buf.extend_from_slice(&data[..nl]);
                let line = std::mem::take(&mut self.buf);
                self.line(&line);
            }
            self.buf.clear();
            self.skipping = false;
            data = &data[nl + 1..];
        }
        if !self.skipping {
            if self.buf.len() + data.len() > MAX_LINE {
                self.buf.clear();
                self.skipping = true;
            } else {
                self.buf.extend_from_slice(data);
            }
        }
    }

    /// The usage seen so far. Call after the body has ended (or was cut off);
    /// a final line without a trailing newline is still read.
    pub fn finish(&mut self) -> Option<Tokens> {
        let rest = std::mem::take(&mut self.buf);
        if !self.skipping && !rest.is_empty() {
            match self.framing {
                Framing::OpenaiJson => {
                    if let Ok(v) = serde_json::from_slice::<Value>(&rest) {
                        self.tokens = openai_usage(&v).or(self.tokens);
                    }
                }
                Framing::OllamaJson => {
                    if let Ok(v) = serde_json::from_slice::<Value>(&rest) {
                        self.tokens = ollama_usage(&v).or(self.tokens);
                    }
                }
                _ => self.line(&rest),
            }
        }
        self.skipping = false;
        self.tokens
    }

    fn line(&mut self, line: &[u8]) {
        let line = trim(line);
        match self.framing {
            Framing::OpenaiSse => {
                let Some(payload) = line.strip_prefix(b"data:") else {
                    return;
                };
                let payload = trim(payload);
                if payload == b"[DONE]" {
                    return;
                }
                if let Ok(v) = serde_json::from_slice::<Value>(payload) {
                    if let Some(t) = openai_usage(&v) {
                        self.tokens = Some(t);
                    }
                }
            }
            Framing::OllamaNdjson => {
                if let Ok(v) = serde_json::from_slice::<Value>(line) {
                    if let Some(t) = ollama_usage(&v) {
                        self.tokens = Some(t);
                    }
                }
            }
            Framing::OpenaiJson | Framing::OllamaJson => {}
        }
    }
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = b {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = b {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn count(v: &Value, path: &[&str]) -> u64 {
    path.iter()
        .try_fold(v, |v, k| v.get(k))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// `usage` of an OpenAI-compatible response or chunk, if present.
pub fn openai_usage(v: &Value) -> Option<Tokens> {
    let u = v.get("usage").filter(|u| u.is_object())?;
    Some(Tokens {
        input: count(u, &["prompt_tokens"]),
        output: count(u, &["completion_tokens"]),
        reasoning: count(u, &["completion_tokens_details", "reasoning_tokens"]),
        cache_read: count(u, &["prompt_tokens_details", "cached_tokens"]),
    })
}

/// Usage of a final Ollama response object (`"done": true`), if this is one.
pub fn ollama_usage(v: &Value) -> Option<Tokens> {
    if v.get("done").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    Some(Tokens {
        input: count(v, &["prompt_eval_count"]),
        output: count(v, &["eval_count"]),
        ..Tokens::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `body` in chunks of `n` bytes, to exercise line reassembly.
    fn scan(framing: Framing, body: &str, n: usize) -> Option<Tokens> {
        let mut s = UsageScanner::new(framing);
        for chunk in body.as_bytes().chunks(n) {
            s.feed(chunk);
        }
        s.finish()
    }

    const OPENAI_SSE: &str =
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}],\"usage\":null}\n\n\
data: {\"choices\":[],\"usage\":{\"prompt_tokens\":120,\"completion_tokens\":30,\
\"prompt_tokens_details\":{\"cached_tokens\":100},\
\"completion_tokens_details\":{\"reasoning_tokens\":10}}}\n\n\
data: [DONE]\n\n";

    // Mistral puts usage on the last content chunk, without stream_options.
    const MISTRAL_SSE: &str =
        "data: {\"id\":\"x\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n\
data: {\"id\":\"x\",\"choices\":[{\"delta\":{\"content\":\"\"},\"finish_reason\":\"stop\"}],\
\"usage\":{\"prompt_tokens\":9,\"total_tokens\":13,\"completion_tokens\":4}}\n\n\
data: [DONE]\n\n";

    const OLLAMA_NDJSON: &str = "{\"model\":\"m\",\"message\":{\"content\":\"Hi\"},\"done\":false}\n\
{\"model\":\"m\",\"message\":{\"content\":\"\"},\"done\":true,\"prompt_eval_count\":26,\"eval_count\":290}\n";

    #[test]
    fn openai_sse_usage_in_any_chunking() {
        for n in [1, 7, 64, 4096] {
            let t = scan(Framing::OpenaiSse, OPENAI_SSE, n).unwrap();
            assert_eq!(
                (t.input, t.output, t.cache_read, t.reasoning),
                (120, 30, 100, 10)
            );
            assert_eq!(t.metered(), 50);
        }
    }

    #[test]
    fn mistral_usage_without_stream_options() {
        let t = scan(Framing::OpenaiSse, MISTRAL_SSE, 5).unwrap();
        assert_eq!((t.input, t.output), (9, 4));
    }

    #[test]
    fn ollama_ndjson_usage_on_the_done_line() {
        for n in [1, 13, 4096] {
            let t = scan(Framing::OllamaNdjson, OLLAMA_NDJSON, n).unwrap();
            assert_eq!((t.input, t.output), (26, 290));
        }
        // A final line without a trailing newline still counts.
        let t = scan(Framing::OllamaNdjson, OLLAMA_NDJSON.trim_end(), 8).unwrap();
        assert_eq!(t.output, 290);
    }

    #[test]
    fn non_streamed_bodies() {
        let openai = r#"{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":7}}"#;
        let t = scan(Framing::OpenaiJson, openai, 3).unwrap();
        assert_eq!((t.input, t.output), (5, 7));
        let ollama = r#"{"done":true,"prompt_eval_count":3,"eval_count":4}"#;
        assert_eq!(scan(Framing::OllamaJson, ollama, 2).unwrap().output, 4);
    }

    #[test]
    fn no_usage_and_cut_off_streams() {
        assert_eq!(
            scan(Framing::OpenaiSse, "data: {\"choices\":[]}\n\n", 4),
            None
        );
        // Cut off before the usage chunk: nothing to book.
        let cut = &OPENAI_SSE[..OPENAI_SSE.find("data: {\"choices\":[],").unwrap()];
        assert_eq!(scan(Framing::OpenaiSse, cut, 16), None);
        assert_eq!(scan(Framing::OpenaiJson, "{not json", 4), None);
    }

    #[test]
    fn huge_lines_are_skipped_not_buffered() {
        let mut s = UsageScanner::new(Framing::OllamaNdjson);
        s.feed(&vec![b'x'; MAX_LINE + 10]);
        assert!(s.buf.is_empty() && s.skipping);
        s.feed(b"\n{\"done\":true,\"prompt_eval_count\":1,\"eval_count\":2}\n");
        assert_eq!(s.finish().unwrap().output, 2);
    }
}
