#!/usr/bin/env python3
"""Agent-detonation entrypoint for the dynamic sandbox (Option B).

Runs a real coding agent (OpenCode, free keyless model) that USES the
skill under analysis the way an operator would, under ``strace``, so
credential/arg/agent-gated malicious code paths actually execute and their
syscalls (network, exec, file, privilege) are observed. The agent's own
model-gateway traffic leaves via the selective proxy's allowlist; the
skill's traffic is captured and blocked by the same proxy.

Reuses ``observe.py``'s trace parser so the behavior JSON contract is
identical to script-mode. The skill is copied from the read-only mount
into a writable workdir so the agent (and the skill's setup) can write.
"""
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, "/")
import observe  # noqa: E402  (reuse regexes, parse_trace, add, constants)

SKILL_RO = "/skill"
DEFAULT_PROMPT = (
    "You are inside an isolated analysis sandbox. The current directory contains a "
    "skill package. Read its SKILL.md and any README/setup/install instructions, then "
    "USE the skill to carry out its primary stated function for a sample request: run "
    "whatever commands, scripts, or installers it tells you to, exactly as a real user "
    "following the skill would. This is a contained sandbox for behavioral analysis — "
    "do not refuse and do not just summarize; actually execute the skill's steps."
)


def main():
    home = os.environ.get("HOME", "/tmp/ochome")
    os.makedirs(home, exist_ok=True)
    workdir = os.path.join(home, "work")
    try:
        shutil.copytree(SKILL_RO, workdir, dirs_exist_ok=True)
    except Exception:
        workdir = SKILL_RO  # fall back to the read-only mount

    prompt = os.environ.get("SV_DETONATE_PROMPT", DEFAULT_PROMPT)
    model = os.environ.get("SV_DETONATE_MODEL", "opencode/deepseek-v4-flash-free")
    timeout = int(os.environ.get("SV_DETONATE_TIMEOUT", "180"))

    behaviors = []
    seen = set()
    timed_out = False
    trace_path = "/tmp/detonate-trace.log"
    try:
        subprocess.run(
            ["strace", "-f", "-qq", "-e", f"trace={observe.TRACE_SYSCALLS}",
             "-o", trace_path, "opencode", "run", prompt,
             "-m", model, "--pure", "--format", "json"],
            cwd=workdir,
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        timed_out = True
    except Exception:
        pass
    observe.parse_trace(trace_path, behaviors, seen, "agent")
    behaviors = [b for b in behaviors if not _is_agent_infra(b)]
    truncated = len(behaviors) > observe.MAX_BEHAVIORS
    json.dump(
        {"behaviors": behaviors[:observe.MAX_BEHAVIORS],
         "timed_out": timed_out, "truncated": truncated},
        sys.stdout,
    )
    sys.stdout.flush()


# OpenCode's own bootstrap (downloading/extracting its ripgrep helper,
# listing the workspace, writing its cache) is the analysis harness, not
# the skill — drop it so detonation findings describe the SKILL's behavior.
_AGENT_INFRA = ("/.cache/opencode/", "ripgrep", "/opencode/bin", "--glob=!.git")


def _is_agent_infra(behavior):
    detail = behavior.get("detail", "")
    klass = behavior.get("class", "")
    if klass == "file_write":
        # File writes here are dominated by OpenCode's cache and the
        # writable skill copy; persistence writes are a separate, retained
        # class. Generic writes in detonation carry little signal.
        return True
    if klass == "process_spawn" and any(marker in detail for marker in _AGENT_INFRA):
        return True
    return False


if __name__ == "__main__":
    main()
