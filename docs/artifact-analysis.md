# Artifact Analysis

`skill-veil` does not stop at `SKILL.md`. The scanner also analyzes nearby and
referenced artifacts to catch cases where the markdown delegates the risky
behavior to another file.

## Current artifact coverage

Package and infrastructure artifacts:

- `package.json`
- `requirements.txt`
- `pyproject.toml`
- `Cargo.toml`
- `Dockerfile`
- `docker-compose.yml`
- `docker-compose.yaml`
- `Makefile`
- `.npmrc`
- `pip.conf`
- `package-lock.json`
- `Cargo.lock`
- `poetry.lock`
- `uv.lock`
- `yarn.lock`
- `pnpm-lock.yaml`

Referenced scripts:

- shell: `sh`, `bash`, `zsh`
- Python: `py`
- Node-style scripts: `js`, `ts`
- PowerShell: `ps1`

## Current script heuristics

The current implementation looks for:

- remote script or binary downloads
- deferred execution
- persistence setup
- install-time side effects
- subprocess/process spawning
- network access
- filesystem reads and writes
- secret access patterns
- scheduled task / startup / registry persistence

These detections are still heuristic, but they are now explicit and tied to the
referenced artifact instead of being inferred only from the markdown.

## Artifact graph

The JSON report includes an `artifact_graph` with:

- nodes
- capabilities
- edges

Current edge types include:

- `references`
- `contains`
- `locks`
- `downloads`
- `executes`
- `loads`
- `persists`
- `mounts`
- `connects_to`
- `reads`
- `writes`
- `accesses_secrets`

This allows the report to say not only "this artifact is risky", but also
"this artifact downloads remote content", "this compose file mounts the host
filesystem", or "this script accesses secrets and writes persistence state".

## Limitations

This is still not full semantic analysis. Current gaps include:

- deep AST-aware parsing for all script languages
- precise lockfile verification against manifest dependency graphs
- richer persistence semantics across all platforms
- stronger correlation between graph edges and blast-radius scoring

The current goal is to move from flat heuristics to explicit artifact-level
analysis with explainable graph output.
