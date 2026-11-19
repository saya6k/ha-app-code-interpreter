#!/bin/sh
# T2 egress PoC: internal network + CONNECT allowlist proxy + hardened sandbox.
# Checks SPEC Success Criteria 2 (no allowlist) and 3 (allowlist) and prints
# a PASS/FAIL table. Run on a Docker host (linux-test):
#   scripts/poc-egress.sh [sandbox-image]
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
sbx_image=${1:-app-code-interpreter-sandbox:dev}
py_image=python:3.13-slim
owner=io.hass.code-interpreter.owner=poc
net=ci-egress-poc
proxy=ci-egress-proxy-poc
fails=0

cleanup() {
  docker ps -aq --filter "label=$owner" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

harden="--user 65534:65534 --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges -e HOME=/tmp"

report() { # name expected-ok actual-ok detail
  if [ "$2" = "$3" ]; then r=PASS; else r=FAIL; fails=$((fails + 1)); fi
  printf '%-4s | %-44s | %s\n' "$r" "$1" "$4"
}

docker pull -q "$py_image" >/dev/null
# inhibit_ipv4: no host-side IP on the bridge, so the sandbox cannot reach host
# services (on HAOS: HA Core on host network, :8123) via the network gateway.
docker network create --internal -o com.docker.network.bridge.inhibit_ipv4=true \
  --label "$owner" "$net" >/dev/null

# Stand-ins: an "app" container on the default bridge, a listener in the host
# netns (the HA host / 172.30.32.1 analogue).
docker run -d --label "$owner" --name ci-poc-app "$py_image" python3 -m http.server 8099 >/dev/null
docker run -d --label "$owner" --name ci-poc-host --network host "$py_image" python3 -m http.server 18099 >/dev/null

# Proxy: internal network + default bridge (PoC mounts proxy.py; T8 uses the app image).
# shellcheck disable=SC2086
docker run -d --label "$owner" --name "$proxy" --network bridge $harden \
  -v "$repo/code-interpreter/rootfs/opt/egress/proxy.py:/proxy.py:ro" \
  -e EGRESS_ALLOWLIST="pypi.org,*.pythonhosted.org" \
  "$py_image" python3 -u /proxy.py >/dev/null
docker network connect "$net" "$proxy"

app_ip=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' ci-poc-app)
bridge_gw=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
# First address of the subnet: where the gateway would sit without inhibit_ipv4.
internal_gw=$(docker network inspect "$net" -f '{{(index .IPAM.Config 0).Subnet}}' | sed 's#0/.*#1#')
proxy_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$proxy")
sleep 1

# Check runner executed inside the sandbox; prints "name|expect|actual|detail".
checks='
import os, socket, subprocess, sys, urllib.request
P = os.environ.get("PROXY", "")
def https(url): urllib.request.urlopen(url, timeout=15).read(64)
def tcp(ip, port): socket.create_connection((ip, int(port)), timeout=3).close()
def raw(req):
    h, p = P.rsplit(":", 1)
    s = socket.create_connection((h, int(p)), timeout=5); s.sendall(req)
    line = s.recv(128).split(b"\r\n")[0]; s.close()
    if b" 200 " not in line: raise RuntimeError(line.decode())
def pip(): subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "-q", "-d", "/tmp/dl", "requests"], check=True, capture_output=True, timeout=120)
def dns(): socket.getaddrinfo("example.com", 443)
T = {
 "https": lambda: https("https://pypi.org/simple/requests/"),
 "pip": pip,
 "denied": lambda: https("https://example.com/"),
 "ipliteral": lambda: raw(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n\r\n"),
 "plainhttp": lambda: raw(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
 "proxyname": lambda: socket.getaddrinfo(P.rsplit(":", 1)[0], 3128),
 "directip": lambda: tcp("1.1.1.1", 443),
 "dns": dns,
 "app": lambda: tcp(os.environ["APP_IP"], 8099),
 "bridgegw": lambda: tcp(os.environ["BRIDGE_GW"], 18099),
 "internalgw": lambda: tcp(os.environ["INTERNAL_GW"], 18099),
 "proxyip": lambda: tcp(os.environ["PROXY_IP"], 3128),
}
for spec in sys.argv[1:]:
    name, expect = spec.split("=")
    try: T[name](); ok, d = "1", "ok"
    except Exception as e: ok, d = "0", (type(e).__name__ + ": " + str(e))[:70]
    print(f"{name}|{expect}|{ok}|{d}")
'

run_checks() { # container, then name=expect...
  c=$1; shift
  docker exec "$c" python3 -c "$checks" "$@" | while IFS='|' read -r name expect ok detail; do
    report "$label $name" "$expect" "$ok" "$detail"
    [ "$expect" = "$ok" ] || echo FAIL >>/tmp/poc-fails
  done
}
rm -f /tmp/poc-fails

envs="-e APP_IP=$app_ip -e BRIDGE_GW=$bridge_gw -e INTERNAL_GW=$internal_gw -e PROXY_IP=$proxy_ip"
proxy_env="-e PROXY=$proxy:3128 -e HTTPS_PROXY=http://$proxy:3128 -e HTTP_PROXY=http://$proxy:3128 -e NO_PROXY="

echo "== Scenario A: allowlist [pypi.org, *.pythonhosted.org], sandbox --dns 127.0.0.1"
# shellcheck disable=SC2086
docker run -d --label "$owner" --name ci-poc-sbx --network "$net" --dns 127.0.0.1 \
  $harden $envs $proxy_env --entrypoint sleep "$sbx_image" infinity >/dev/null
label="[A]"
run_checks ci-poc-sbx https=1 pip=1 denied=0 ipliteral=0 plainhttp=0 proxyname=1 \
  directip=0 dns=0 app=0 bridgegw=0 internalgw=0

echo "== Scenario B (R2): same, but Docker default DNS (no --dns)"
# shellcheck disable=SC2086
docker run -d --label "$owner" --name ci-poc-sbx-dns --network "$net" \
  $harden $envs $proxy_env --entrypoint sleep "$sbx_image" infinity >/dev/null
label="[B]"
run_checks ci-poc-sbx-dns dns=0 proxyname=1 directip=0

echo "== Scenario C: empty allowlist -> network_mode=none"
# shellcheck disable=SC2086
docker run -d --label "$owner" --name ci-poc-none --network none \
  $harden $envs -e PROXY="$proxy_ip:3128" --entrypoint sleep "$sbx_image" infinity >/dev/null
label="[C]"
run_checks ci-poc-none directip=0 dns=0 proxyip=0 app=0 bridgegw=0

echo "== Proxy audit log"
sbx_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" ci-poc-sbx)
logs=$(docker logs "$proxy" 2>&1)
label="[log]"
if echo "$logs" | grep '"host": "pypi.org"' | grep '"allowed": true' | grep -q "\"src_ip\": \"$sbx_ip\""; then
  report "$label pypi.org allowed, src_ip=sandbox" 1 1 "$sbx_ip"
else report "$label pypi.org allowed, src_ip=sandbox" 1 0 "missing"; echo FAIL >>/tmp/poc-fails; fi
if echo "$logs" | grep '"host": "example.com"' | grep -q '"allowed": false'; then
  report "$label example.com denied" 1 1 "logged"
else report "$label example.com denied" 1 0 "missing"; echo FAIL >>/tmp/poc-fails; fi
if echo "$logs" | grep -q '"reason": "ip-literal"'; then
  report "$label ip-literal denied" 1 1 "logged"
else report "$label ip-literal denied" 1 0 "missing"; echo FAIL >>/tmp/poc-fails; fi

if [ -f /tmp/poc-fails ]; then
  echo "RESULT: $(wc -l </tmp/poc-fails) FAIL"; rm -f /tmp/poc-fails; exit 1
fi
echo "RESULT: ALL PASS"
