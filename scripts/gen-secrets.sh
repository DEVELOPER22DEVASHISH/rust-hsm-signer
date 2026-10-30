#!/bin/sh
# Generates DEV secrets into ./secrets/ (gitignored).
# 0644 permissions so the container's non-root user can read bind-mounted files.
# In real deployments use orchestrator secrets (Docker secrets, K8s Secrets, Vault, etc.)
set -eu

mkdir -p secrets

# HSM PINs — 16 hex bytes = 128-bit entropy (more than enough for a SoftHSM PIN).
openssl rand -hex 16 > secrets/hsm_pin
openssl rand -hex 16 > secrets/hsm_so_pin

# API bearer token — 32 hex bytes = 256-bit entropy.
TOKEN=$(openssl rand -hex 32)
printf '%s' "$TOKEN" > secrets/api_token

# Token file stores only the SHA-256 digest; the plaintext token never touches disk.
if command -v sha256sum >/dev/null 2>&1; then
  HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
else
  HASH=$(printf '%s' "$TOKEN" | shasum -a 256 | cut -d' ' -f1)
fi
cat > secrets/api-tokens.json <<EOF
[{"name":"demo-client","token_sha256":"${HASH}","key_ids":["arkion-intermediate-prod","arkion-data-key"]}]
EOF

chmod 644 secrets/*
echo "secrets written to ./secrets (gitignored)"
echo "  api_token:       $(cat secrets/api_token)"
echo "  hsm_pin:         $(cat secrets/hsm_pin)"