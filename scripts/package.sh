#!/usr/bin/env bash
# 打包脚本：交叉编译 Windows/Linux 包，二进制用 upx 压缩，
# 包内配置统一放 conf/ 目录。
#
# 用法: scripts/package.sh [版本号]     （默认从 git tag 取，无 tag 则 dev）
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo dev)}
OUT=dist
rm -rf "$OUT"
mkdir -p "$OUT"

command -v upx >/dev/null 2>&1 || echo "警告: 未安装 upx，跳过压缩"

# $1=goos $2=exe后缀
assemble() {
  local goos=$1 ext=$2
  local name="caochuan-$VERSION-$goos-amd64"
  local dir="$OUT/$name"
  mkdir -p "$dir/conf" "$dir/deploy"

  echo ">> 构建 $name"
  GOOS=$goos GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$dir/caochuan$ext" ./cmd/caochuan

  if command -v upx >/dev/null 2>&1; then
    upx -q --best "$dir/caochuan$ext" >/dev/null
  fi

  cp conf/server.example.json conf/client.example.json "$dir/conf/"
  cp deploy/caochuan.service "$dir/deploy/"
  cp README.md "$dir/"

  if [ "$goos" = "windows" ]; then
    printf '@echo off\ncaochuan server -c conf\\server.json\n'  > "$dir/start-server.bat"
    printf '@echo off\ncaochuan client -c conf\\client.json\n'  > "$dir/start-client.bat"
    # 优先产 zip：zip 命令 / Windows 自带 bsdtar，都没有则退回 tar.gz
    if command -v zip >/dev/null 2>&1; then
      (cd "$OUT" && zip -qr "$name.zip" "$name")
    elif [ -x "/c/Windows/System32/tar.exe" ]; then
      (cd "$OUT" && /c/Windows/System32/tar.exe -a -cf "$name.zip" "$name")
    else
      tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
    fi
  else
    printf '#!/bin/sh\n./caochuan server -c conf/server.json\n' > "$dir/start-server.sh"
    printf '#!/bin/sh\n./caochuan client -c conf/client.json\n' > "$dir/start-client.sh"
    chmod +x "$dir/start-server.sh" "$dir/start-client.sh" "$dir/caochuan"
    tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
  fi
  echo "   -> $OUT/$name"
}

assemble windows .exe
assemble linux ""

echo "完成:"
ls -lh "$OUT" | grep -E 'zip|tar.gz'
