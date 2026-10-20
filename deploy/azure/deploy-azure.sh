#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
printf '%s\n' \
  'DISABLED: the former Azure example was dashboard polling, not an OpenShell sandbox.' \
  'No cloud resources, builds, uploads or paid deployments are performed.' \
  'Use scripts/deploy-local-risk-guard.sh --check and deploy/local/OPERATIONS.md instead.' >&2
exit 1
