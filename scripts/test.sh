bash <<'BIGSCRIPT'
set -e
cd "$(pwd)"
TOKEN=$(cat secrets/api_token)

# ========== 5. AES-GCM round-trip ==========
{
  echo "=== POST /v1/encrypt ==="
  CT_JSON=$(curl -s http://localhost:8080/v1/encrypt \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"key_id":"arkion-data-key","plaintext":"c2VjcmV0IG1lc3NhZ2U="}')
  echo "$CT_JSON"
  CT_B64=$(echo "$CT_JSON" | python3 -c 'import sys,json;print(json.load(sys.stdin)["ciphertext"])')

  echo ""
  echo "=== POST /v1/decrypt (same ciphertext) ==="
  curl -s http://localhost:8080/v1/decrypt \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"key_id\":\"arkion-data-key\",\"ciphertext\":\"$CT_B64\"}"
  echo ""
  echo ""
  echo "=== round-trip assertion ==="
  if [ "$(curl -s http://localhost:8080/v1/decrypt \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d "{\"key_id\":\"arkion-data-key\",\"ciphertext\":\"$CT_B64\"}" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["plaintext"])')" \
      = "c2VjcmV0IG1lc3NhZ2U=" ]; then
    echo "PASS: decrypt(encrypt(x)) == x"
  else
    echo "FAIL"; exit 1
  fi
} | tee demo-output/05-aes-gcm.txt

# ========== 6. Tamper rejection ==========
{
  echo "=== bit-flip last byte of ciphertext (breaks GCM auth tag) ==="
  TAMPERED=$(python3 -c "
import base64
b = bytearray(base64.b64decode('$CT_B64'))
b[-1] ^= 0xFF
print(base64.b64encode(bytes(b)).decode())")
  echo "tampered: $TAMPERED"
  echo ""
  echo "=== POST /v1/decrypt (must be 400 decryption_failed) ==="
  curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/decrypt \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"key_id\":\"arkion-data-key\",\"ciphertext\":\"$TAMPERED\"}"
} | tee demo-output/06-tamper.txt

# ========== 7. Auth failures ==========
{
  echo "=== no token → expect 401 ==="
  curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
    -H "Content-Type: application/json" \
    -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}'
  echo ""
  echo "=== wrong token → expect 401 ==="
  curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
    -H "Authorization: Bearer not-a-real-token" -H "Content-Type: application/json" \
    -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}'
  echo ""
  echo "=== valid token, out-of-scope key → expect 403 ==="
  curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"key_id":"some-other-key","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}'
} | tee demo-output/07-auth.txt

# ========== 8. Bad input ==========
{
  echo "=== unsupported algorithm → expect 400 unsupported_algorithm ==="
  curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"key_id":"arkion-intermediate-prod","algorithm":"RSA_PSS","payload":"aGVsbG8="}'
  echo ""
  echo "=== path traversal key_id → expect 400 ==="
  curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"key_id":"../etc/passwd","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8="}'
  echo ""
  echo "=== invalid base64 payload → expect 400 ==="
  curl -s -w "\nHTTP %{http_code}\n" http://localhost:8080/v1/sign \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"!!!not-base64"}'
} | tee demo-output/08-bad-input.txt

# ========== 9. Metrics ==========
{
  echo "=== Prometheus metrics scrape (first 60 lines) ==="
  curl -s http://localhost:9100/metrics | head -60
} | tee demo-output/09-metrics.txt

echo ""
echo "=== ALL DEMO TESTS COMPLETE ==="
ls -la demo-output/
BIGSCRIPT