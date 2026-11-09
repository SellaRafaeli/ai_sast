#!/usr/bin/env bash
# Clone the test apps at their pinned versions. Safe to re-run: existing clones are skipped.
set -euo pipefail
cd "$(dirname "$0")"

clone() { # url ref dir
  local url=$1 ref=$2 dir=$3
  if [ -d "$dir/.git" ]; then echo "skip $dir (exists)"; return; fi
  mkdir -p "$(dirname "$dir")"
  git clone -q "$url" "$dir"
  git -C "$dir" -c advice.detachedHead=false checkout -q "$ref"
  echo "ok   $dir @ $ref"
}

clone https://github.com/aegra/aegra.git                v0.9.6                                   aegra-v0.9.6
clone https://github.com/snoopysecurity/dvws-node.git   05e1b6fafd38fa37e8c1d9a909e375016fcc6e88 node/dvws-node
