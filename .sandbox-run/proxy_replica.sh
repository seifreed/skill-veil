#!/usr/bin/env bash
# Replicate the exact detonation proxy setup and run opencode through it
# under gVisor, to see whether the proxy tunnels ollama.com or fails.
set -u
TAG=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep skill-veil-sandbox-agent | head -1)
KEY=$(python3 -c 'import json;print(json.load(open("/root/.config/opencode/opencode.json"))["provider"]["ollama-cloud"]["options"]["apiKey"])')
ALLOW="opencode.ai,models.dev,github.com,registry.npmjs.org,githubusercontent.com,ollama.com"
NET=svrep; EGR=svrep-egr
docker rm -f svrep-proxy 2>/dev/null
docker network rm "$NET" "$EGR" 2>/dev/null
docker network create --internal "$NET" >/dev/null
docker network create "$EGR" >/dev/null

docker run -d --rm --name svrep-proxy --network "$NET" --network-alias proxy \
  --user 65534:65534 --read-only --cap-drop ALL \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m --security-opt no-new-privileges \
  --env "SV_PROXY_ALLOWLIST=$ALLOW" --entrypoint python3 "$TAG" /proxy.py >/dev/null
docker network connect "$EGR" svrep-proxy
sleep 2
PIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" svrep-proxy)
echo "proxy ip on internal net: $PIP"

docker run --rm --runtime=runsc --network "$NET" \
  -e "HTTP_PROXY=http://$PIP:8080" -e "HTTPS_PROXY=http://$PIP:8080" \
  -e "K=$KEY" -e HOME=/tmp/ochome --entrypoint bash "$TAG" -c '
    mkdir -p /tmp/ochome/.config/opencode
    python3 -c "import json,os;json.dump({\"provider\":{\"ollama-cloud\":{\"npm\":\"@ai-sdk/openai-compatible\",\"name\":\"ollama-cloud\",\"options\":{\"baseURL\":\"https://ollama.com/v1\",\"apiKey\":os.environ[\"K\"]}}},\"model\":\"ollama-cloud/devstral-small-2:24b\"},open(\"/tmp/ochome/.config/opencode/opencode.json\",\"w\"))"
    cd /tmp
    timeout 70 opencode run "Run the bash tool with cmd: echo BEHAVIORTEST" -m ollama-cloud/devstral-small-2:24b --pure --print-logs --log-level ERROR > /tmp/o.out 2>/tmp/o.err
    echo "opencode rc=$?"
    echo "--- behaviortest executed? ---"; grep -i BEHAVIORTEST /tmp/o.out /tmp/o.err | head -2
    echo "--- opencode errors ---"; grep -iE "error|econn|refused|tunnel|TransportError|ConnectionRefused" /tmp/o.err | tail -6
  '
echo "=== PROXY LOGS (what it intercepted) ==="
docker logs svrep-proxy 2>&1 | tail -20
docker rm -f svrep-proxy 2>/dev/null
docker network rm "$NET" "$EGR" 2>/dev/null
