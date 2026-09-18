#!/usr/bin/env bash
# 本地冒烟测试：起 server+client+测试目标，验证正向/穿透/UDP 三条链路后自动清理。
# 用法: bash scripts/smoke.sh
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
cleanup() {
  kill $SRV_PID $CLI_PID $HTTP_PID $HTTP2_PID $UDP_PID 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

go build -o "$WORK/caochuan.exe" ./cmd/caochuan 2>/dev/null || go build -o "$WORK/caochuan" ./cmd/caochuan
BIN="$WORK/caochuan.exe"; [ -f "$BIN" ] || BIN="$WORK/caochuan"

cat > "$WORK/server.json" <<'EOF'
{"tunnel_addr":"127.0.0.1:17800","panel_addr":"127.0.0.1:17801","password":"test123","ip_whitelist":[],"secret":"smoke","clients":[{"name":"c1","token":"smoketoken"}],
 "rules":[
  {"id":"f1","name":"fwd","proto":"tcp","listen":17802,"client":"","target":"127.0.0.1:17990","enabled":true},
  {"id":"f2","name":"tun","proto":"tcp","listen":17803,"client":"c1","target":"127.0.0.1:17991","enabled":true},
  {"id":"f3","name":"udp","proto":"udp","listen":17804,"client":"c1","target":"127.0.0.1:17992","enabled":true},
  {"id":"r1","name":"rev","side":"client","proto":"tcp","listen":17993,"client":"c1","target":"127.0.0.1:17990","enabled":true},
  {"id":"r2","name":"rev-udp","side":"client","proto":"udp","listen":17994,"client":"c1","target":"127.0.0.1:17992","enabled":true}]}
EOF
echo '{"server_addr":"127.0.0.1:17800","token":"smoketoken"}' > "$WORK/client.json"
cat > "$WORK/udpecho.py" <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 17992))
while True:
    d, a = s.recvfrom(65535); s.sendto(d, a)
EOF

py -m http.server 17990 --bind 127.0.0.1 >/dev/null 2>&1 & HTTP_PID=$!
py -m http.server 17991 --bind 127.0.0.1 >/dev/null 2>&1 & HTTP2_PID=$!
py "$WORK/udpecho.py" >/dev/null 2>&1 & UDP_PID=$!
"$BIN" server -c "$WORK/server.json" >/dev/null 2>&1 & SRV_PID=$!
sleep 1
# server 启动时给缺失的 panel_prefix 自动补随机值并回写配置
PREFIX=$(py -c "import json;print(json.load(open(r'$(cygpath -w "$WORK/server.json")',encoding='utf-8'))['panel_prefix'])")
BASE="http://127.0.0.1:17801/$PREFIX"
"$BIN" client -c "$WORK/client.json" >/dev/null 2>&1 & CLI_PID=$!
sleep 2

echo -n "根路径应404:   "; curl -s -m 5 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:17801/
echo -n "面板登录:      "; curl -s -m 5 -c "$WORK/jar" -X POST "$BASE/api/login" -d '{"password":"test123"}' -H "Content-Type: application/json"
echo
echo -n "客户端在线:    "; curl -s -m 5 -b "$WORK/jar" "$BASE/api/clients" | grep -o '"online":true' | head -1
echo -n "TCP 正向 17802: "; curl -s -m 5 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:17802/
echo -n "TCP 穿透 17803: "; curl -s -m 5 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:17803/
echo -n "UDP 穿透 17804: "
py - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(b"ping", ("127.0.0.1", 17804))
assert s.recv(100) == b"ping"
print("OK")
EOF
echo -n "TCP 反向 17993: "; curl -s -m 5 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:17993/
echo -n "UDP 反向 17994: "
py - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(b"rev", ("127.0.0.1", 17994))
assert s.recv(100) == b"rev"
print("OK")
EOF
echo "全部通过"
