//! Cross-cutting helpers used by both the LLM and VT subsystems.

pub(crate) mod bounded_read;
pub(crate) mod cache_io;
pub(crate) mod secure_fs;
pub(crate) mod terminal_safe;
