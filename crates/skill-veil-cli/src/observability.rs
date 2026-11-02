//! Process-wide diagnostic logging for the CLI.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use regex::Regex;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::cli_args::{Cli, LogFormatArg, LogLevelArg};
use crate::util::terminal_safe::{sanitise_for_terminal, terminal_path};

const MAX_LOG_EVENT_BYTES: usize = 64 * 1024;
const TRUNCATED_SUFFIX: &str = "...[truncated]";

pub(crate) struct LogConfig<'a> {
    format: LogFormatArg,
    file: Option<&'a Path>,
    level: Option<LogLevelArg>,
    quiet: bool,
    verbose: bool,
}

impl<'a> LogConfig<'a> {
    pub(crate) fn from_cli(cli: &'a Cli) -> Self {
        Self {
            format: cli.log_format,
            file: cli.log_file.as_deref(),
            level: cli.log_level,
            quiet: cli.quiet,
            verbose: cli.verbose,
        }
    }

    fn fallback_level(&self) -> &'static str {
        match self.level {
            Some(LogLevelArg::Trace) => "trace",
            Some(LogLevelArg::Debug) => "debug",
            Some(LogLevelArg::Info) => "info",
            Some(LogLevelArg::Warn) => "warn",
            Some(LogLevelArg::Error) => "error",
            None if self.quiet => "error",
            None if self.verbose => "debug",
            None => "warn",
        }
    }

    fn filter(&self) -> EnvFilter {
        if self.level.is_some() {
            return EnvFilter::new(self.fallback_level());
        }
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(self.fallback_level()))
    }
}

pub(crate) fn init(config: &LogConfig<'_>) {
    let (writer, destination_error) = SafeMakeWriter::new(config.file);
    let filter = config.filter();
    let result = match config.format {
        LogFormatArg::Text => tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_ansi(false)
                    .with_writer(writer),
            )
            .with(filter)
            .try_init(),
        LogFormatArg::Json => tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true)
                    .with_span_list(true)
                    .with_target(true)
                    .with_ansi(false)
                    .with_writer(writer),
            )
            .with(filter)
            .try_init(),
    };

    if let Err(err) = result {
        eprintln!(
            "warning: diagnostic logger unavailable: {}",
            sanitise_for_terminal(&err.to_string())
        );
        return;
    }
    if let Some((path, err)) = destination_error {
        tracing::warn!(
            event_name = "logging.destination_fallback",
            operation = "logging.init",
            status = "fallback",
            path = %terminal_path(&path),
            error_type = "io",
            error = %sanitise_for_terminal(&err.to_string()),
            "log file unavailable; using stderr"
        );
    }
}

#[derive(Clone)]
struct SafeMakeWriter {
    destination: LogDestination,
}

impl SafeMakeWriter {
    fn new(path: Option<&Path>) -> (Self, Option<(std::path::PathBuf, io::Error)>) {
        let Some(path) = path else {
            return (
                Self {
                    destination: LogDestination::Stderr,
                },
                None,
            );
        };
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => (
                Self {
                    destination: LogDestination::File(Arc::new(Mutex::new(file))),
                },
                None,
            ),
            Err(err) => (
                Self {
                    destination: LogDestination::Stderr,
                },
                Some((path.to_path_buf(), err)),
            ),
        }
    }
}

impl<'a> MakeWriter<'a> for SafeMakeWriter {
    type Writer = SafeEventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SafeEventWriter {
            destination: self.destination.clone(),
            buffer: Vec::new(),
            truncated: false,
        }
    }
}

#[derive(Clone)]
enum LogDestination {
    Stderr,
    File(Arc<Mutex<File>>),
}

struct SafeEventWriter {
    destination: LogDestination,
    buffer: Vec<u8>,
    truncated: bool,
}

impl SafeEventWriter {
    fn emit(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() && !self.truncated {
            return Ok(());
        }
        let rendered = render_log_event(&self.buffer, self.truncated);
        self.buffer.clear();
        self.truncated = false;
        match &self.destination {
            LogDestination::Stderr => io::stderr().write_all(rendered.as_bytes()),
            LogDestination::File(file) => file
                .lock()
                .map_err(|_| io::Error::other("log file lock poisoned"))?
                .write_all(rendered.as_bytes()),
        }
    }
}

impl Write for SafeEventWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let available = MAX_LOG_EVENT_BYTES.saturating_sub(self.buffer.len());
        let accepted = available.min(buf.len());
        self.buffer.extend_from_slice(&buf[..accepted]);
        self.truncated |= accepted < buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit()
    }
}

impl Drop for SafeEventWriter {
    fn drop(&mut self) {
        let _ = self.emit();
    }
}

fn render_log_event(buf: &[u8], truncated: bool) -> String {
    let mut text = String::from_utf8_lossy(buf).into_owned();
    if truncated {
        text.push_str(TRUNCATED_SUFFIX);
    }
    let text = redact_secrets(&text);
    sanitise_log_chunk_for_terminal(text.as_bytes())
}

fn redact_secrets(text: &str) -> String {
    let text = auth_scheme_pattern()
        .replace_all(text, "$1 <redacted>")
        .into_owned();
    let text = named_secret_pattern()
        .replace_all(&text, "$1<redacted>")
        .into_owned();
    private_key_pattern()
        .replace_all(&text, "$1<redacted>$2")
        .into_owned()
}

fn auth_scheme_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
            .expect("authentication redaction regex must compile")
    })
}

fn named_secret_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r#"(?i)((?:x-api-key|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|token|authorization|password|passwd|cookie|session[_-]?id|client[_-]?secret|secret)["']?\s*(?:=|:)\s*["']?)[^"',\s}\]\\&]+"#,
        )
        .expect("named-secret redaction regex must compile")
    })
}

fn private_key_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?is)(-----BEGIN [^-\r\n]*PRIVATE KEY-----).*?(-----END [^-\r\n]*PRIVATE KEY-----)",
        )
        .expect("private-key redaction regex must compile")
    })
}

pub(crate) fn sanitise_log_chunk_for_terminal(buf: &[u8]) -> String {
    let text = String::from_utf8_lossy(buf);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\n' && chars.peek().is_none() {
            out.push('\n');
        } else if c == '\t' {
            out.push(' ');
        } else if c.is_control() {
            out.push('?');
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Arc;
    use std::thread;

    use tracing_subscriber::fmt::MakeWriter;

    use super::{
        render_log_event, sanitise_log_chunk_for_terminal, LogConfig, LogDestination, LogFormatArg,
        LogLevelArg, SafeMakeWriter, MAX_LOG_EVENT_BYTES, TRUNCATED_SUFFIX,
    };

    #[test]
    fn configured_levels_cover_trace_through_error() {
        let cases = [
            (LogLevelArg::Trace, "trace"),
            (LogLevelArg::Debug, "debug"),
            (LogLevelArg::Info, "info"),
            (LogLevelArg::Warn, "warn"),
            (LogLevelArg::Error, "error"),
        ];
        for (level, expected) in cases {
            let config = LogConfig {
                format: LogFormatArg::Text,
                file: None,
                level: Some(level),
                quiet: false,
                verbose: false,
            };
            assert_eq!(config.fallback_level(), expected);
        }
    }

    #[test]
    fn log_boundary_redacts_credentials_and_private_keys() {
        let rendered = render_log_event(
            b"authorization: Bearer abc.def api_key=top-secret password='hunter2' -----BEGIN PRIVATE KEY-----private-material-----END PRIVATE KEY-----\n",
            false,
        );

        assert!(!rendered.contains("abc.def"));
        assert!(!rendered.contains("top-secret"));
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("private-material"));
        assert!(rendered.matches("<redacted>").count() >= 4);
    }

    #[test]
    fn log_boundary_neutralises_injected_lines_and_controls() {
        let rendered = sanitise_log_chunk_for_terminal(b"WARN bad\x1b[2J\nforged event\x07\n");

        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\x07'));
        assert_eq!(rendered.matches('\n').count(), 1);
        assert!(rendered.contains("bad?[2J?forged event?"));
    }

    #[test]
    fn oversized_event_is_bounded() {
        let rendered = render_log_event(&vec![b'a'; MAX_LOG_EVENT_BYTES], true);

        assert_eq!(rendered.len(), MAX_LOG_EVENT_BYTES + TRUNCATED_SUFFIX.len());
        assert!(rendered.ends_with(TRUNCATED_SUFFIX));
    }

    #[test]
    fn file_destination_serialises_concurrent_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("events.log");
        let (writer, error) = SafeMakeWriter::new(Some(&path));
        assert!(error.is_none());
        let writer = Arc::new(writer);
        let handles: Vec<_> = (0..16)
            .map(|index| {
                let writer = Arc::clone(&writer);
                thread::spawn(move || {
                    let mut event = writer.make_writer();
                    writeln!(event, "event-{index}").expect("write event");
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("join writer");
        }

        let content = std::fs::read_to_string(path).expect("read log");
        assert_eq!(content.lines().count(), 16);
        for index in 0..16 {
            assert!(content.lines().any(|line| line == format!("event-{index}")));
        }
    }

    #[test]
    fn unavailable_file_destination_falls_back_to_stderr() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing").join("events.log");
        let (writer, error) = SafeMakeWriter::new(Some(&path));

        assert!(error.is_some());
        assert!(matches!(writer.destination, LogDestination::Stderr));
    }
}
