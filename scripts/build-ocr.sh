#!/bin/sh
set -eu

: "${OCR_SOURCE_URL:=https://github.com/zsmj-xu/open-code-review.git}"
: "${OCR_VERSION:=codex/argus-aligned-refactor}"
: "${OCR_COMMIT:=072808b6b0b12a1408b31889539c03878eff0f61}"
: "${OCR_OUTPUT:=/out/ocr}"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

git init --quiet "$work_dir/src"
git -C "$work_dir/src" remote add origin "$OCR_SOURCE_URL"
git -C "$work_dir/src" fetch --quiet --depth 1 origin "$OCR_COMMIT"
git -C "$work_dir/src" checkout --quiet --detach FETCH_HEAD
actual_commit="$(git -C "$work_dir/src" rev-parse HEAD)"
if [ "$actual_commit" != "$OCR_COMMIT" ]; then
  echo "OpenCodeReview ref mismatch: expected $OCR_VERSION/$OCR_COMMIT, got $actual_commit" >&2
  exit 1
fi

mkdir -p "$(dirname "$OCR_OUTPUT")"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
short_commit="$(printf '%s' "$actual_commit" | cut -c 1-12)"
go -C "$work_dir/src" build -trimpath \
  -ldflags="-s -w -X main.Version=$OCR_VERSION -X main.GitCommit=$short_commit -X main.BuildDate=$build_date" \
  -o "$OCR_OUTPUT" ./cmd/opencodereview
chmod 0755 "$OCR_OUTPUT"
