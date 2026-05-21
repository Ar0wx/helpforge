#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p .secrets

vagrant ssh -c 'cd /vagrant && sudo ansible-playbook -i "localhost," -c local ansible/playbook.yml --tags verify -e @ansible/local-vars.yml' \
  2>&1 | tee .secrets/verify.log
