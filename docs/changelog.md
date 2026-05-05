# Changelog

All notable changes to `skill-veil` will be documented in this file.

The project aims to follow Keep a Changelog and semantic versioning once the
release process is formalized.

## [Unreleased]

## [0.1.2] - 2026-05-05

### Fixed

- Made cache override tests portable on Windows while preserving Unix
  broken-symlink coverage, unblocking the full CI matrix.

### Added

- strict `scan-file` and package-oriented `scan-package`
- labeled regression corpus and benchmark command
- findings model with evidence kind, artifact kind, remediation, and action
- threat model document
- artifact graph with declared and observed capabilities
- manifest analyzers for `package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `Dockerfile`, and `docker-compose`
- context policies for `install`, `network`, `secrets`, `code_modification`, and `external_comms`
- baseline, waivers, and diff support
- policy file schema with configurable profiles and auditable overrides
- CI-oriented diff summary and fail policies
- rule-pack fixtures and external pack test runner
- GitHub CI workflow and release workflow
- local and CI usage documentation

### Changed

- policy precedence is now explicit: waiver -> baseline -> override -> profile/context escalation
- CLI text output now includes context policies and suppression summaries
- README now documents installation, examples, CI usage, and release model

### Fixed

- logical bug in composite rule handling
- profile-based `fail_on` enforcement in scan filtering
- noisy README promotion when explicit skill entrypoints exist
