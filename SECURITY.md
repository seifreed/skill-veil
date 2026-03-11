# Security Policy

## Reporting

Report suspected vulnerabilities or scanner bypasses privately to the maintainers.

For operational support boundaries, see [docs/support.md](docs/support.md).

Include:

- affected version or commit
- reproduction steps
- sample artifact if legally shareable
- expected behavior
- actual behavior

## Scope

This includes:

- crashes caused by crafted inputs
- rule bypasses with clear security impact
- report integrity issues
- unsafe default behavior in policy or scanning paths

It does not include:

- false positives without security impact
- feature requests
- unsupported third-party integrations

## Disclosure Process

The project uses coordinated disclosure:

1. report privately with a reproduction
2. maintainers triage severity and impact
3. a fix is prepared when needed
4. release notes document the issue at publication time when safe to do so
