# Operational Notes

## Purpose
Document why remote bootstrap patterns such as `curl | bash` are forbidden in our environment.

## Guidance
- Do not execute remote installers.
- Download reviewed artifacts manually and verify checksums first.
- Ask for approval before any install-time command execution.
