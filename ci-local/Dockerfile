# skill-veil CI deployment + detection harness.
#
# Stage 1 proves "el despliegue": the release binary builds from a clean
# Rust image with `--locked` (Cargo.lock is honoured, no system C deps).
# Stage 2 proves the artifact is self-contained: it runs on debian-slim
# with only ca-certificates (TLS for the optional online `init`).
#
# Build:  docker build -f ci-local/Dockerfile -t skill-veil-ci:local .
#         (build context MUST be the repo root — see .dockerignore)
#
# Cache layering: the heavy `cargo build` layer only sees Cargo.{toml,lock}
# and `crates/`. Examples, fixtures, and ci-local/ are copied separately
# in the runtime stage, so editing the harness scripts does not invalidate
# the build cache.

ARG RUST_IMAGE=rust:1.94-bookworm

FROM ${RUST_IMAGE} AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p skill-veil \
 && /src/target/release/skill-veil --version

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git jq bash \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/skill-veil /usr/local/bin/skill-veil
WORKDIR /work
COPY examples ./examples
COPY benchmarks/fixtures ./benchmarks/fixtures
COPY benchmarks/corpus.yaml ./benchmarks/corpus.yaml
COPY ci-local ./ci-local
ENV SKILL_VEIL_BIN=/usr/local/bin/skill-veil
# CMD (not ENTRYPOINT): `docker compose run harness` runs the smoke gate,
# while CI engines (GitLab/act) that use this as a job image override the
# command with their own job script.
CMD ["bash", "ci-local/smoke.sh"]
