#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p .secrets

exec vagrant up --provider=virtualbox --provision 2>&1 | tee .secrets/build.log
