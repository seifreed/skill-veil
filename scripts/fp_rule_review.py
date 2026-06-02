#!/usr/bin/env python3
"""Adjudicate benign-corpus false positives with OpenAI + Grok and implicate rules.

For every skill in the benign corpus that skill-veil verdicted `malicious`
(an approximate false positive vs the VirusTotal benign label), ask two
independent LLMs (OpenAI gpt-4o-mini and xAI grok-4-fast) two things:

  1. an overall verdict for the skill (benign | suspicious | malicious), and
  2. for each *decisive* rule that fired (signal_class=malicious_behavior or
     recommended_action=block), whether that rule's firing is a justified
     true positive or a false positive on this skill.

Results stream to `fp_review.jsonl` (resumable: paths already present are
skipped). Runs both providers for many skills concurrently via a thread pool.

Env: OPENAI_API_KEY, GROK_API_KEY.

Usage:
    fp_rule_review.py --raw RESULTS/benign.raw.json --out RESULTS/fp_review.jsonl \
        [--limit N] [--workers 16] [--content-chars 2500]
"""

import argparse
import concurrent.futures as cf
import json
import os
import pathlib
import threading
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

PROVIDERS = {
    "openai": ("https://api.openai.com/v1/chat/completions", "OPENAI_API_KEY", "gpt-4o-mini"),
    "grok": ("https://api.x.ai/v1/chat/completions", "GROK_API_KEY", "grok-4-fast"),
}

SYSTEM = (
    "You are a malware analyst reviewing Claude/agent 'skills' (markdown + scripts). "
    "A static scanner flagged the skill below as MALICIOUS. Decide independently "
    "whether that is correct. Be skeptical of benign developer tooling: reading a "
    "skill's own config, calling a documented vendor API with an env-var key, or "
    "non-English prose are NOT by themselves malicious. Genuine malice means covert "
    "credential exfiltration, remote code download+exec, persistence/callback, or "
    "deceptive prompt-injection against the host agent."
)

INSTR = (
    "Return ONLY compact JSON: "
    '{"verdict":"benign|suspicious|malicious",'
    '"rules":{"<RULE_ID>":"justified|false_positive", ...},'
    '"reason":"<=200 chars"}. '
    "Judge each listed rule's firing on THIS skill."
)


def decisive_findings(report: dict) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in report.get("findings", []):
        if f.get("signal_class") == "malicious_behavior" or f.get("recommended_action") == "block":
            rid = f["rule_id"]
            if rid not in seen:
                seen[rid] = f
    return list(seen.values())


def read_excerpt(skill_path: str, limit: int) -> str:
    p = REPO_ROOT / skill_path
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return "(content unavailable)"
    return text[:limit]


def build_prompt(report: dict, decisive: list[dict], content_chars: int) -> str:
    rule_lines = []
    for f in decisive[:12]:
        ev = (f.get("match_value") or f.get("matched_on") or "")[:160]
        rule_lines.append(f'- {f["rule_id"]} ({f.get("category","")}): {f.get("reason","")[:120]} | evidence: {ev!r}')
    excerpt = read_excerpt(report.get("skill_path", ""), content_chars)
    return (
        f"DECISIVE RULES THAT FIRED:\n" + "\n".join(rule_lines) +
        f"\n\nSKILL CONTENT (truncated):\n{excerpt}\n\n{INSTR}"
    )


def call_llm(provider: str, prompt: str) -> dict:
    url, env, model = PROVIDERS[provider]
    key = os.environ.get(env)
    if not key:
        return {"error": f"{env} unset"}
    body = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 400,
        "response_format": {"type": "json_object"},
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            d = json.load(r)
        content = d["choices"][0]["message"]["content"]
        return json.loads(content)
    except Exception as e:  # noqa: BLE001 - record provider/transport failures inline
        detail = ""
        if hasattr(e, "read"):
            try:
                detail = e.read()[:200].decode(errors="replace")
            except Exception:  # noqa: BLE001
                pass
        return {"error": f"{type(e).__name__}: {e} {detail}"}


def adjudicate(report: dict, content_chars: int) -> dict:
    decisive = decisive_findings(report)
    prompt = build_prompt(report, decisive, content_chars)
    result = {
        "path": report.get("skill_path", ""),
        "decisive_rules": sorted({f["rule_id"] for f in decisive}),
    }
    for provider in PROVIDERS:
        result[provider] = call_llm(provider, prompt)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--raw", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--content-chars", type=int, default=2500)
    args = ap.parse_args()

    reports = [
        e["report"] for e in json.load(args.raw.open())["reports"]
        if e["report"].get("verdict") == "malicious"
    ]
    if args.limit:
        reports = reports[: args.limit]

    done: set[str] = set()
    if args.out.exists():
        for line in args.out.open():
            try:
                done.add(json.loads(line)["path"])
            except (json.JSONDecodeError, KeyError):
                pass
    todo = [r for r in reports if r.get("skill_path", "") not in done]
    print(f"benign FPs: {len(reports)}  already done: {len(done)}  to do: {len(todo)}", flush=True)

    lock = threading.Lock()
    n = [0]
    with args.out.open("a") as out, cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(adjudicate, r, args.content_chars): r for r in todo}
        for fut in cf.as_completed(futures):
            res = fut.result()
            with lock:
                out.write(json.dumps(res, sort_keys=True) + "\n")
                out.flush()
                n[0] += 1
                if n[0] % 25 == 0:
                    print(f"  {n[0]}/{len(todo)}", flush=True)
    print(f"done: wrote {n[0]} results to {args.out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
