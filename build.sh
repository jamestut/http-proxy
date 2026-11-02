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
  output="dist/$1-$3-$5"
  CGO_ENABLED=0 GOOS="$3" GOARCH="$4" go build -ldflags "$ldflags" -o "$output" "$2"
  printf 'built %s\n' "$output"
}

for program in http-proxy reverse-proxy agent; do
  case "$program" in
    http-proxy) source=./src ;;
    reverse-proxy) source=./cmd/reverse-proxy ;;
    agent) source=./cmd/agent ;;
  esac
  build "$program" "$source" darwin arm64 arm64
  build "$program" "$source" linux arm64 arm64
  build "$program" "$source" linux amd64 x64
done
