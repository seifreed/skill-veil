# 0029. LLM-Adjudicated Taint Downgrade (validated, pending reviewed implementation)

Date: 2026-05-18

## Status

Proposed — empirically validated, implementation deferred to a reviewed change.

## Context

After exhausting the rule/verdict-layer levers for the
`ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK` false-positive bucket
(two independent reverted experiments: a corroboration relaxation at
+89 TP / −182 FP, and a documentation-host strip at 0 FP gain / −1
recall), the single remaining lever is semantic: distinguishing
"secret → obscure-but-legitimate vendor API" (benign) from
"secret → attacker host" (malicious). Static allowlists provably
cannot do this — the FP sink hosts are either shared with the
malicious corpus or are obscure vendors where absence from a finite
malicious sample is not evidence of trustworthiness.

The project's LLM enrichment is deliberately **read-only**: a
parallel scorer that annotates but never modifies the core verdict.
`crates/skill-veil-cli/src/commands/scan/mod.rs` enforces this with
a `verdict_snapshot` anti-tamper fingerprint and an explicit
"CONTRACT (do not break)" comment. Letting the LLM downgrade a core
`Malicious` is therefore a deliberate trust-model inversion.

## Empirical validation

A focused cross-LLM triage (OpenAI gpt-4o-mini + xAI grok-4-fast +
DeepSeek-V3.1 671B, 1965 calls) over the two relevant sets, with the
gate "core verdict = Malicious AND sole driver is
`ARTIFACT_TAINT_SECRET/IDENTITY_TO_EXTERNAL_NETWORK` AND ≥2 of 3
providers say benign → downgrade Malicious → Suspicious":

| side | set | size | would downgrade | meaning |
|---|---|--:|--:|---|
| FP | benign corpus, taint-driven Malicious | 461 | **126** | false positives recovered |
| FN | malicious corpus, taint-driven Malicious | 194 | **8** | true-malicious softened to Suspicious (still surfaced for review) |

Trade ratio **15.75 : 1** in favour of FP reduction. The 8 FN cases
are softened Malicious → Suspicious (RequireApproval), not silenced;
and in all 8 the LLM cohort itself judged the skill benign, i.e.
they are genuinely ambiguous / likely VT-mislabelled.

## Decision (design — to be implemented under review)

Implement the downgrade WITHOUT breaking core-verdict purity:

1. The core `PackageScanResult.verdict` stays immutable; the
   `verdict_snapshot` assertion remains valid (it fingerprints the
   core verdict, which is never mutated).
2. Add a separate, explicitly-labelled CLI "effective verdict"
   reconciliation computed post-enrichment as a pure function
   `(core_verdict, llm_consensus, gate) -> effective_verdict`.
3. **Gate (all required):** core verdict `Malicious`; the only
   Block-strength MaliciousBehavior driver is
   `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK` or
   `ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK` on an untrusted
   host; no conclusive-rule finding; no compound-chain reason.
4. **Consensus:** ≥2 of 3 distinct providers return `benign`.
5. **Prompt-injection hardening:** reuse the existing
   `llm/prompt` untrusted-blob markers + system-prompt mandate to
   ignore embedded instructions; the adjudication question is
   structural ("is this sink host consistent with the skill's
   stated purpose?"), skill text supplied only as fenced untrusted
   data.
6. **Opt-in flag** (default off): the read-only behaviour remains
   the default; operators choose the trust trade explicitly.
7. Downgrade target is `Suspicious` (RequireApproval), never
   `Benign` — analyst visibility is preserved.

## Why implementation is deferred

This inverts a security invariant guarded by an explicit
anti-tamper assertion. It must ship as a deliberately reviewed
diff, not an unattended self-paced-loop change. The validation
above is the decision-grade evidence; the reusable triage tooling
(`scripts/fp_triage*.sh`, `taint-fp-triage.jsonl`,
`taint-fn-triage.jsonl`) reproduces the numbers.

## Consequences

- Recovers ~126 of the residual ~169 LLM-consensus FPs (the largest
  remaining error bucket on the FP side).
- Soft cost: ~8 ambiguous true-malicious move Malicious → Suspicious
  (still surfaced).
- New trust dependency: a prompt-injectable LLM can, under the
  strict gate only, soften a taint-only Block. Mitigated by the
  multi-provider consensus, the narrow gate, the hardened prompt,
  and opt-in default-off.
