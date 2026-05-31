//! Third scoring engine: LLM-based skill analysis.
//!
//! Works alongside the native scanner and the VT enrichment, following the
//! same immutability contract: the LLM never modifies `ScanResult`, it only
//! produces a parallel annotation the caller can render.
//!
//! Supports 5 providers via a common trait:
//! - Ollama (local) — `http://localhost:11434`
//! - Ollama Cloud — `https://ollama.com`
//! - LMStudio — `http://localhost:1234/v1` (OpenAI-compatible)
//! - OpenAI — `https://api.openai.com/v1`
//! - Anthropic — `https://api.anthropic.com/v1`

pub(crate) mod cache;
pub(crate) mod client;
pub(crate) mod enrich;
pub(crate) mod fp_review;
pub(crate) mod prompt;
pub(crate) mod providers;
pub(crate) mod taint_adjudication;
pub(crate) mod types;
