#!/usr/bin/env python3
"""Server-local patches to make agent detonation use a configured
openai-compatible provider (Ollama Cloud / GLM-5) instead of the free
opencode zen gateway (ECONNRESET'd from this datacenter IP)."""
import os

ROOT = "/root/sv-run"

# 1) executor.rs — allowlist ollama.com through the agent proxy.
p = os.path.join(ROOT, "crates/skill-veil-cli/src/sandbox/executor.rs")
s = open(p).read()
old = '"opencode.ai,models.dev,github.com,registry.npmjs.org,githubusercontent.com";'
new = '"opencode.ai,models.dev,github.com,registry.npmjs.org,githubusercontent.com,ollama.com";'
assert old in s, "allowlist literal not found"
if "ollama.com" not in s:
    open(p, "w").write(s.replace(old, new, 1))
    print("executor.rs: allowlist patched")
else:
    print("executor.rs: already has ollama.com")

# 2) mod.rs — forward host LLM env into the detonation container.
p = os.path.join(ROOT, "crates/skill-veil-cli/src/sandbox/mod.rs")
s = open(p).read()
anchor = '        ("SV_DETONATE_TIMEOUT".to_string(), "150".to_string()),\n    ];'
add = anchor + (
    '\n    for key in ["SV_DETONATE_MODEL", "SV_OPENCODE_API_KEY", "SV_OPENCODE_BASEURL"] {\n'
    '        if let Ok(val) = std::env::var(key) {\n'
    '            policy.extra_env.push((key.to_string(), val));\n'
    '        }\n'
    '    }'
)
assert anchor in s, "extra_env anchor not found"
if "SV_OPENCODE_API_KEY" not in s:
    open(p, "w").write(s.replace(anchor, add, 1))
    print("mod.rs: extra_env forwarding added")
else:
    print("mod.rs: already patched")

# 3) detonate.py — write an opencode provider config from env at startup.
p = os.path.join(ROOT, "crates/skill-veil-cli/src/sandbox/image/detonate.py")
s = open(p).read()
anchor = '    model = os.environ.get("SV_DETONATE_MODEL", "opencode/deepseek-v4-flash-free")\n'
block = anchor + (
    '    api_key = os.environ.get("SV_OPENCODE_API_KEY")\n'
    '    if api_key:\n'
    '        import json as _json\n'
    '        cfg_dir = os.path.join(home, ".config", "opencode")\n'
    '        os.makedirs(cfg_dir, exist_ok=True)\n'
    '        base_url = os.environ.get("SV_OPENCODE_BASEURL", "https://ollama.com/v1")\n'
    '        prov = model.split("/", 1)[0] if "/" in model else "ollama-cloud"\n'
    '        prov_model = model.split("/", 1)[1] if "/" in model else model\n'
    '        with open(os.path.join(cfg_dir, "opencode.json"), "w") as _fh:\n'
    '            _json.dump({\n'
    '                "$schema": "https://opencode.ai/config.json",\n'
    '                "provider": {prov: {"npm": "@ai-sdk/openai-compatible", "name": prov,\n'
    '                    "options": {"baseURL": base_url, "apiKey": api_key},\n'
    '                    "models": {prov_model: {"name": prov_model}}}},\n'
    '                "model": model,\n'
    '            }, _fh)\n'
)
assert anchor in s, "detonate model anchor not found"
if "SV_OPENCODE_API_KEY" not in s:
    open(p, "w").write(s.replace(anchor, block, 1))
    print("detonate.py: config-write added")
else:
    print("detonate.py: already patched")
