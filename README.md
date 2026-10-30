```
# HSM-Backed Signing Service

A Rust HTTP service that signs payloads with an **ECDSA P-256 key** and encrypts data with an **AES-256-GCM key** — both stored inside a **PKCS#11 HSM (SoftHSM2)**. Private and symmetric key material is **non-extractable** (`CKA_EXTRACTABLE=false`) and never touches application memory, disk, or logs.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Build the Container Image](#2-build-the-container-image)
3. [Generate Development Secrets](#3-generate-development-secrets)
4. [Run the Service](#4-run-the-service)
5. [Verify the Service Is Healthy](#5-verify-the-service-is-healthy)
6. [Test the Signing Endpoint](#6-test-the-signing-endpoint)
7. [Verify the Signature Independently (openssl)](#7-verify-the-signature-independently-openssl)
8. [Test AES-GCM Encrypt / Decrypt](#8-test-aes-gcm-encrypt--decrypt)
9. [Test Authentication and Authorization](#9-test-authentication-and-authorization)
10. [Test Input Validation](#10-test-input-validation)
11. [Inspect Prometheus Metrics](#11-inspect-prometheus-metrics)
12. [Run the Load Test (1 / 10 / 100 / 500 concurrency)](#12-run-the-load-test)
13. [Run the Automated Test Suite](#13-run-the-automated-test-suite)
14. [Cleanup](#14-cleanup)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Prerequisites

| Tool | Minimum version | Check |
|---|---|---|
| Docker Desktop | 20.x | `docker --version` |
| Rust (only for local `cargo test`) | 1.88 | `cargo --version` |
| openssl | any | `openssl version` |
| python3 | 3.8+ | `python3 --version` |

If you are on **Apple Silicon (M1/M2/M3)**: nothing extra is needed — the image builds for `linux/arm64` natively.

**Clone the repo and enter it:**
```bash
git clone <your-repo-url> signing_service
cd signing_service
```

---

## 2. Build the Container Image

```bash
docker build -t hsm-signer .
```

**Expected output (tail):**
```
#12 naming to docker.io/library/hsm-signer:latest done
#12 DONE 13.1s
```

This is a **multi-stage build**:
- `builder` — compiles `hsm-signer` and `loadtest` binaries in Rust 1.97
- `test` — installs SoftHSM2 (only used by `--target test`)
- `runtime` — Debian slim + SoftHSM2, runs as **non-root uid 10001**

Total build time on a warm cache: ~20s. Cold cache: ~2 min.

---

## 3. Generate Development Secrets

```bash
sh scripts/gen-secrets.sh
```

**Expected output:**
```
secrets written to ./secrets (gitignored)
  api_token:       2499d1...a8716      ← save this
  hsm_pin:         ab12cd...ef34
```

This creates four files under `secrets/`:

| File | Purpose |
|---|---|
| `hsm_pin` | User PIN for SoftHSM2 token |
| `hsm_so_pin` | Security Officer PIN (only used at token init) |
| `api_token` | Plaintext bearer token (dev convenience) |
| `api-tokens.json` | Server-side store — **only the SHA-256 digest of the token** |

The `secrets/` directory is `.gitignore`d. In production, use Docker/K8s secrets or a Vault.

**Export the token for later steps:**
```bash
export TOKEN=$(cat secrets/api_token)
echo "TOKEN=$TOKEN"
```

---

## 4. Run the Service

```bash
docker run -d \
  -p 8080:8080 \
  -p 9100:9100 \
  -v "$(pwd)/secrets:/secrets:ro" \
  -e SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf \
  -e HSM_INIT_TOKEN=true \
  -e HSM_TOKEN_LABEL=arkion \
  -e HSM_PIN_FILE=/secrets/hsm_pin \
  -e HSM_SO_PIN_FILE=/secrets/hsm_so_pin \
  -e API_TOKENS_FILE=/secrets/api-tokens.json \
  -e HSM_PROVISION=true \
  -e LOG_FORMAT=json \
  --name hsm-signer \
  hsm-signer
```

| Flag | Purpose |
|---|---|
| `-d` | Detached — runs in background |
| `-p 8080:8080` | API port |
| `-p 9100:9100` | Prometheus metrics port |
| `-v .../secrets:/secrets:ro` | Mount secrets read-only |
| `HSM_INIT_TOKEN=true` | Initialise SoftHSM2 token on first start |
| `HSM_PROVISION=true` | Generate EC + AES keys inside HSM if missing |
| `API_TOKENS_FILE` | Server-side token digest store |
| `LOG_FORMAT=json` | Structured JSON audit logs |

**Confirm it's up:**
```bash
docker logs hsm-signer 2>&1 | grep "PKCS#11 backend ready"
```

**Expected — the golden line:**
```json
{"timestamp":"...","level":"INFO","fields":{"message":"PKCS#11 backend ready","pool":8,"ec_keys":1,"aes_keys":1}}
```

This single log line proves:
- SoftHSM2 token was initialised
- EC P-256 key was generated with `CKA_EXTRACTABLE=false`
- AES-256 key was generated with `CKA_EXTRACTABLE=false`
- Startup self-test (sign + verify inside HSM) passed
- 8-session pool is ready

---

## 5. Verify the Service Is Healthy

```bash
curl -s http://localhost:8080/healthz; echo
curl -s http://localhost:8080/readyz; echo
```

**Expected:**
```
ok
ready
```

`/readyz` actually pings the HSM (`C_GetSessionInfo`), not just the HTTP server.

---

## 6. Test the Signing Endpoint

```bash
curl -s http://localhost:8080/v1/sign \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8gd29ybGQ="}'
```

**Expected:**
```json
{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","signature":"<base64>","duration_ms":2}
```

The `signature` is 64 bytes (raw `r‖s`) base64-encoded, produced inside the HSM. `duration_ms` is wall-clock time including pool wait.

**Fetch the corresponding public key:**
```bash
curl -s http://localhost:8080/v1/keys/arkion-intermediate-prod/public \
  -H "Authorization: Bearer $TOKEN"
```

**Expected:**
```json
{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","public_key_sec1":"BF+eyVrJ...z8vw9Y="}
```

The public key is the **uncompressed SEC1 point** — 65 bytes = `04 ‖ X(32) ‖ Y(32)`. It is safely public; only the private key lives exclusively in the HSM.

---

## 7. Verify the Signature Independently (openssl)

This proves — with a **third-party tool that has no knowledge of this codebase** — that the signature came from the HSM's private key.

```bash
bash <<'SCRIPT'
set -e
TOKEN=$(cat secrets/api_token)

# Sign
SIG_RESP=$(curl -s http://localhost:8080/v1/sign \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8gd29ybGQ="}')
SIG_B64=$(echo "$SIG_RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["signature"])')

# Fetch public key
PK_RESP=$(curl -s http://localhost:8080/v1/keys/arkion-intermediate-prod/public \
  -H "Authorization: Bearer $TOKEN")
PK_B64=$(echo "$PK_RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["public_key_sec1"])')

# Convert raw r||s to DER
python3 - "$SIG_B64" <<'PY'
import sys, base64
sig = base64.b64decode(sys.argv[1])
r = int.from_bytes(sig[:32], 'big')
s = int.from_bytes(sig[32:], 'big')
def der_int(i):
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')
    if b[0] & 0x80: b = b'\x00' + b
    return b'\x02' + bytes([len(b)]) + b
body = der_int(r) + der_int(s)
open('/tmp/sig.der', 'wb').write(b'\x30' + bytes([len(body)]) + body)
PY

# Convert SEC1 point to PEM SPKI
python3 - "$PK_B64" <<'PY'
import sys, base64
pk = base64.b64decode(sys.argv[1])
prefix = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
body = base64.b64encode(prefix + pk).decode()
pem = '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(body[i:i+64] for i in range(0, len(body), 64)) + '\n-----END PUBLIC KEY-----\n'
open('/tmp/pk.pem', 'w').write(pem)
PY

printf 'hello world' > /tmp/payload.bin
openssl dgst -sha256 -verify /tmp/pk.pem -signature /tmp/sig.der /tmp/payload.bin
SCRIPT
```

**Expected:**
```
Verified OK
```

The payload `aGVsbG8gd29ybGQ=` is base64 for `hello world` — the exact bytes openssl verifies. `Verified OK` means the ECDSA P-256 signature is mathematically valid.

---

## 8. Test AES-GCM Encrypt / Decrypt

```bash
# Encrypt "secret message" (base64: c2VjcmV0IG1lc3NhZ2U=)
CT_RESP=$(curl -s http://localhost:8080/v1/encrypt \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_id":"arkion-data-key","plaintext":"c2VjcmV0IG1lc3NhZ2U="}')
echo "Encrypt: $CT_RESP"
CT_B64=$(echo "$CT_RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["ciphertext"])')

# Decrypt
echo "Decrypt: $(curl -s http://localhost:8080/v1/decrypt \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"key_id\":\"arkion-data-key\",\"ciphertext\":\"$CT_B64\"}")"
```

**Expected:**
```
Encrypt: {"key_id":"arkion-data-key","ciphertext":"aBXrIp...VYmWK"}
Decrypt: {"key_id":"arkion-data-key","plaintext":"c2VjcmV0IG1lc3NhZ2U="}
```

The ciphertext is **different every run** because the IV is drawn from the HSM's TRNG. Output layout: `IV(12) ‖ ciphertext ‖ tag(16)`.

**Tamper test — flip the last bit of the auth tag:**

```bash
TAMPERED=$(printf '%s' "$CT_B64" | python3 -c 'import sys,base64;b=bytearray(base64.b64decode(sys.stdin.read().strip()));b[-1]^=0xFF;print(base64.b64encode(bytes(b)).decode())')
curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/decrypt \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"key_id\":\"arkion-data-key\",\"ciphertext\":\"$TAMPERED\"}"
```

**Expected:**
```json
{"error":{"code":"decryption_failed","message":"decryption failed"}}
HTTP 400
```

The GCM auth tag is being checked. Any bit change in ciphertext, tag, or AAD causes rejection.

---

## 9. Test Authentication and Authorization

```bash
# 9.1 — No token → 401
curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
  -H "Content-Type: application/json" \
  -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}'

# 9.2 — Wrong token → 401
curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
  -H "Authorization: Bearer not-a-real-token" -H "Content-Type: application/json" \
  -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}'

# 9.3 — Valid token, out-of-scope key → 403
curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_id":"some-other-key","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}'
```

**Expected:**
```
{"error":{"code":"unauthorized","message":"authentication required"}}
HTTP 401

{"error":{"code":"unauthorized","message":"authentication required"}}
HTTP 401

{"error":{"code":"forbidden","message":"not permitted for this key"}}
HTTP 403
```

Note: an out-of-scope key returns **403, not 404** — the response does not reveal whether the key exists. This prevents key-ID enumeration.

---

## 10. Test Input Validation

```bash
# 10.1 — Unsupported algorithm → 400
curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_id":"arkion-intermediate-prod","algorithm":"RSA_PSS","payload":"aGVsbG8="}'

# 10.2 — Path traversal in key_id → 400
curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_id":"../etc/passwd","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}'

# 10.3 — Invalid base64 → 400
curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"!!!not-base64"}'
```

**Expected:**
```
{"error":{"code":"unsupported_algorithm","message":"unsupported algorithm"}}
HTTP 400

{"error":{"code":"bad_request","message":"invalid key_id"}}
HTTP 400

{"error":{"code":"bad_request","message":"payload is not valid base64"}}
HTTP 400
```

Key IDs are validated against `[A-Za-z0-9._-]{1,128}` — path traversal and shell metacharacters are rejected before any backend call.

---

## 11. Inspect Prometheus Metrics

```bash
curl -s http://localhost:9100/metrics | grep -E "^(signer|hsm)" | head -30
```

**Expected (abridged):**
```
hsm_pool_acquire_timeouts_total 0
hsm_pool_capacity 8
hsm_pool_in_use 0
hsm_pool_rejected_total 0
signer_op_duration_seconds_bucket{op="sign",le="0.005"} 4
signer_op_duration_seconds_sum{op="sign"} 0.017
signer_op_duration_seconds_count{op="sign"} 5
signer_requests_total{op="sign",outcome="ok"} 5
```

| Metric | Meaning |
|---|---|
| `signer_requests_total{op,outcome}` | Counter, per-op outcome (ok / key_not_found / pool_saturated / …) |
| `signer_op_duration_seconds{op}` | Histogram, end-to-end latency incl. pool wait |
| `hsm_pool_capacity` | Configured `POOL_SIZE` |
| `hsm_pool_in_use` | Currently checked-out sessions |
| `hsm_pool_rejected_total` | Requests rejected by admission control |
| `hsm_pool_acquire_timeouts_total` | Requests that timed out waiting for a session |

These names are Prometheus-native — scrapable directly by Grafana / Alertmanager.

---

## 12. Run the Load Test

The `loadtest` binary is inside the running container. It fires 1, 10, 100, and 500 concurrent callers for 15 seconds each.

```bash
docker exec hsm-signer \
  env LT_TOKEN=$TOKEN LT_LEVELS=1,10,100,500 LT_SECS=15 \
  /usr/local/bin/loadtest
```

**Expected output (values will vary by hardware):**

```
| concurrency | requests | req/s  | p50 ms | p95 ms  | p99 ms  | error % | status breakdown          |
|-------------|----------|--------|--------|---------|---------|---------|---------------------------|
| 1           | 72842    | 4856   | 0.19   | 0.30    | 0.47    | 0.00    | {200: 72842}              |
| 10          | 221868   | 14789  | 0.59   | 1.27    | 1.86    | 0.00    | {200: 221868}             |
| 100         | 231518   | 15429  | 6.08   | 8.65    | 14.28   | 0.00    | {200: 231518}             |
| 500         | 281073   | 18676  | 4.93   | 126.72  | 183.86  | 79.63   | {200: 57254, 503: 223819} |
```

**Reading the results — *successful* throughput (200s only):**

| Concurrency | Successful req/s | p50 | Error rate |
|---|---|---|---|
| 1 | 4,856 | 0.19 ms | 0% |
| 10 | 14,789 | 0.59 ms | 0% |
| 100 | **15,429 (peak)** | 6.08 ms | 0% |
| 500 | 3,817 ↓ | — | 79.63% (503) |

**Interpretation:**

- **Concurrency 1 → 10**: throughput scales 3× — SoftHSM handles ~8 parallel sessions in its pool.
- **Concurrency 10 → 100**: throughput plateaus at ~15,400/s. This is the **actual HSM ceiling** on a laptop. Additional sessions queue.
- **Concurrency 100 → 500**: successful throughput *drops* because **79.63% of requests are rejected immediately with 503 + Retry-After**. This is the intended backpressure: better to serve 20% of traffic fast than to queue everyone and let p99 latency explode.

---

## 13. Run the Automated Test Suite

**13.1 — Mock-backend HTTP tests (fast, no HSM required):**
```bash
cargo test --release --test api_mock
```

**Expected:**
```
running 6 tests
test aes_gcm_roundtrip_and_tamper ... ok
test auth_and_authorization ... ok
test duration_ms_is_non_negative ... ok
test health_endpoints_need_no_auth ... ok
test rejects_bad_input ... ok
test sign_and_verify_with_public_key ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; finished in 0.01s
```

These tests exercise the **full HTTP stack** (axum router, auth middleware, DTOs, error mapping) against an in-memory `MockBackend` — no HSM needed. `sign_and_verify_with_public_key` cryptographically verifies the produced signature.

**13.2 — Full suite against real SoftHSM2 (via Docker):**
```bash
docker build --target test -t hsm-signer-test .
docker run --rm hsm-signer-test
```

**Expected (tail):**
```
test softhsm_end_to_end ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; finished in 0.03s
```

`softhsm_end_to_end` spins up a **throwaway SoftHSM2 token in a tempdir**, then:
1. Provisions EC P-256 + AES-256 keys
2. Signs a fixed payload inside the HSM
3. Verifies the signature in software
4. Encrypts and decrypts AES-GCM
5. Confirms tamper rejection (wrong AAD, bit-flip)
6. Fires 40 concurrent sign calls to exercise the pool
7. Tests graceful shutdown

Only one test in that file because **`C_Initialize` is process-global** — running two SoftHSM tests in parallel within one process would clash.

---

## 14. Cleanup

```bash
# Stop and remove the running container
docker rm -f hsm-signer

# Remove the test image (optional)
docker rmi hsm-signer-test

# Regenerate secrets if you shared a token in a screenshot (recommended)
sh scripts/gen-secrets.sh
```

---

## 15. Troubleshooting

### `exec /usr/local/bin/entrypoint.sh: exec format error`
The entrypoint file is missing its shebang on byte 0, or has Windows CRLF. Fix:
```bash
head -1 scripts/entrypoint.sh   # must print: #!/bin/sh
```
If it prints anything else, the shebang got clobbered. The Dockerfile invokes the script as `["/bin/sh", "/usr/local/bin/entrypoint.sh"]` so this should be impossible with the current image — but if it happens, `chmod +x scripts/entrypoint.sh` and rebuild.

### `ERROR: Could not load the SoftHSM configuration.`
`SOFTHSM2_CONF` isn't reaching the process, or `/etc/softhsm/softhsm2.conf` is not readable by uid 10001. Diagnose:
```bash
docker run --rm --entrypoint /bin/sh hsm-signer -c '
  echo "SOFTHSM2_CONF=$SOFTHSM2_CONF"
  ls -la /etc/softhsm/
  cat /etc/softhsm/softhsm2.conf
'
```
Expected:
```
SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
drwxr-xr-x 2 app app ... softhsm2.conf    ← must be 0755/app
-rw-r--r-- 1 app app ... softhsm2.conf    ← must be 0644/app
```
If the file is missing or mode is wrong, rebuild with `docker build --no-cache -t hsm-signer .` — the Dockerfile explicitly sets `chmod 0755` and `chown app:app` on `/etc/softhsm`.

### `token label "arkion" not found`
`HSM_INIT_TOKEN=true` wasn't set on the `docker run` command, so the token was never created. Either set `HSM_INIT_TOKEN=true` (first run) or manually:
```bash
docker exec hsm-signer softhsm2-util --init-token --free \
  --label arkion --so-pin 0000 --pin 1234
```
Then restart the container.

### `permission denied` reading `/secrets/*`
The host files must be readable by uid 10001:
```bash
chmod 644 secrets/*
```

### `container name already in use`
```bash
docker rm -f hsm-signer
```

### `error: rustc 1.x is not supported by package X`
The Dockerfile pins `rust:1.97.1-bookworm`. If a dependency is bumped in `Cargo.lock` requiring newer Rust, update the `FROM` line to `rust:latest-bookworm`.

---

## Endpoint Reference

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v1/sign` | Bearer | Sign base64 payload with EC key |
| `POST` | `/v1/encrypt` | Bearer | AES-256-GCM encrypt |
| `POST` | `/v1/decrypt` | Bearer | AES-256-GCM decrypt |
| `GET` | `/v1/keys/:key_id/public` | Bearer | Fetch SEC1 public key |
| `GET` | `/healthz` | none | Liveness probe |
| `GET` | `/readyz` | none | Readiness probe (pings HSM) |
| `GET` | `:9100/metrics` | none | Prometheus metrics |

**Status codes:**

| Code | Meaning |
|---|---|
| `200` | Success |
| `400` | Invalid input (base64, algorithm, key_id format, GCM auth tag) |
| `401` | Missing or invalid bearer token |
| `403` | Token valid but key not in caller's scope |
| `404` | Key not found (only reachable if key is in scope but doesn't exist) |
| `503` | Pool saturated (`Retry-After: 1`) or HSM unavailable (`Retry-After: 2`) |
| `500` | Internal error — diagnostic logged, never leaked to caller |

---

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND` | `pkcs11` | `pkcs11` (real) or `mock` (tests only) |
| `BIND_ADDR` | `0.0.0.0:8080` | API listener |
| `METRICS_ADDR` | `127.0.0.1:9100` | Prometheus listener |
| `PKCS11_MODULE` | `/usr/lib/softhsm/libsofthsm2.so` | PKCS#11 library path |
| `HSM_TOKEN_LABEL` | `arkion` | Token label to find/create |
| `HSM_PIN_FILE` | — | Path to file containing user PIN (preferred) |
| `HSM_PIN` | — | Fallback PIN env var (cleared after read, dev only) |
| `HSM_INIT_TOKEN` | `false` | Init token on startup if missing (dev only) |
| `HSM_PROVISION` | `true` | Auto-generate keys if missing |
| `SIGNING_KEY_IDS` | `arkion-intermediate-prod` | Comma-separated EC key labels |
| `AES_KEY_IDS` | `arkion-data-key` | Comma-separated AES key labels |
| `API_TOKENS_FILE` | — | Path to `api-tokens.json` |
| `ALLOW_UNAUTHENTICATED` | `false` | Disable auth — local dev only, must be explicit |
| `POOL_SIZE` | `8` | Max concurrent HSM operations |
| `POOL_MAX_WAITERS` | `256` | Queue depth before immediate 503 |
| `POOL_ACQUIRE_TIMEOUT_MS` | `500` | Max wait for a session |
| `REQUEST_TIMEOUT_MS` | `2000` | HTTP request timeout |
| `MAX_BODY_BYTES` | `1048576` | HTTP body size limit |
| `SHUTDOWN_GRACE_SECS` | `20` | Drain window on SIGTERM |
| `LOG_FORMAT` | `json` | `json` or `text` |

---

## Security Summary

| Property | How it's achieved |
|---|---|
| **Private key never leaves HSM** | `CryptoBackend` trait has no export method; key generated with `CKA_EXTRACTABLE=false` |
| **Fail-closed on policy violation** | `verify_policy()` at startup; aborts if key is extractable |
| **PIN never logged** | Read from file, wrapped in `AuthPin` (Debug redacts); env-var fallback cleared immediately |
| **Tokens never stored in plaintext** | Only SHA-256 digests on disk; plaintext printed once at generation |
| **Constant-time auth** | `subtle::ConstantTimeEq`, no early exit on match |
| **No key enumeration** | Out-of-scope key → 403 (same as nonexistent) |
| **No payload/signature logging** | Audit log includes `key_id`, `op`, `duration_us` — never payload bytes |
| **Non-root container** | uid 10001, `nologin` shell |
| **Structured audit trail** | Every op logged with `target: "audit"` |

---

```

