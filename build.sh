#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p .secrets

if [[ -f shell.php.old && ! -f shell.php ]]; then
  cp shell.php.old shell.php
fi

exec vagrant up --provider=virtualbox --provision 2>&1 | tee .secrets/build.log
