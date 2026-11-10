#!/usr/bin/env bash
set -euo pipefail
# Subject recipe is shared with the live tests; no duplicate build flags or key.
cargo +1.98.0 run --locked -p busbar-auth-ldap --example prepare_e2e
