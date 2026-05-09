# PromptIntel Vendored Corpus

Snapshot of the PromptIntel curated jailbreak corpus pinned for
regression testing. The live API at
`https://api.promptintel.novahunting.ai/api/v1/prompts` returns the
same 50 entries; the snapshot exists so a CI runner without an API key
can still execute the regression test, and so a future API change
cannot silently move our detection numbers.

## Files

- `_index.json` — per-prompt metadata (id, title, severity, categories,
  threats, markdown_path)
- `_meta.json` — snapshot provenance (`fetched_at`, `source`,
  `total_in_api`, `prompts_written`)
- `prompts/<uuid>.md` — one markdown file per prompt, the same shape
  produced by `skill-veil promptintel download`
- `SHA256SUMS` — integrity manifest for the snapshot

## Refreshing

```bash
skill-veil promptintel download --dest data/promptintel
cp data/promptintel/_index.json data/promptintel/_meta.json benchmarks/promptintel-corpus/
cp data/promptintel/prompts/*.md benchmarks/promptintel-corpus/prompts/
( cd benchmarks/promptintel-corpus && \
  find . -type f \( -name "*.md" -o -name "*.json" \) | sort | xargs shasum -a 256 > SHA256SUMS )
```

Then update the regression test thresholds in
`crates/skill-veil-cli/tests/promptintel_baseline.rs` if the corpus
shape moved (per-severity counts, total).

## Safety

These markdown files contain adversarial prompts curated for
defensive testing — meth-synthesis frames, multilingual code-switching
bomb requests, system-override jailbreaks, etc. They are inputs to the
scanner, not executable code, and they are already public via the
PromptIntel API. Treat them like any other security-research fixture.
