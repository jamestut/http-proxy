#!/bin/sh
set -eu

cd "$(dirname "$0")"

commit=unknown
date_value=$(date +%Y-%m-%dT%H:%M:%S%z)
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [ -n "$(git status --porcelain)" ]; then
    commit=$(git rev-parse --short HEAD)-dev
  else
    commit=$(git describe --tags --exact-match HEAD 2>/dev/null || git rev-parse --short HEAD)
  fi
fi

ldflags="-X main.commit=${commit} -X main.date=${date_value}"
mkdir -p dist

build() {
  output="dist/http-proxy-$1-$3"
  CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -ldflags "$ldflags" -o "$output" ./src
  printf 'built %s\n' "$output"
}

build darwin arm64 arm64
build linux arm64 arm64
build linux amd64 x64
