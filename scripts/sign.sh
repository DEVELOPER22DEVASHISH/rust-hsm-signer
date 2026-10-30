bash <<'SCRIPT' 2>&1 | tee demo-output/04-verify.txt
set -e
TOKEN=$(cat secrets/api_token)

echo "=== Step 1: POST /v1/sign ==="
SIGN_RESP=$(curl -s http://localhost:8080/v1/sign \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","payload":"aGVsbG8gd29ybGQ="}')
echo "$SIGN_RESP"
SIG_B64=$(echo "$SIGN_RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["signature"])')

echo ""
echo "=== Step 2: GET /v1/keys/arkion-intermediate-prod/public ==="
PK_RESP=$(curl -s http://localhost:8080/v1/keys/arkion-intermediate-prod/public \
  -H "Authorization: Bearer $TOKEN")
echo "$PK_RESP"
PK_B64=$(echo "$PK_RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["public_key_sec1"])')

echo ""
echo "=== Step 3: Convert r||s → DER ==="
python3 - "$SIG_B64" <<'PY'
import sys, base64
sig = base64.b64decode(sys.argv[1])
r = int.from_bytes(sig[:32], 'big')
s = int.from_bytes(sig[32:], 'big')
def to_der_int(i):
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, 'big')
    if b[0] & 0x80: b = b'\x00' + b
    return b'\x02' + bytes([len(b)]) + b
body = to_der_int(r) + to_der_int(s)
der = b'\x30' + bytes([len(body)]) + body
open('/tmp/sig.der', 'wb').write(der)
print(f"  wrote /tmp/sig.der ({len(der)} bytes)")
PY

echo ""
echo "=== Step 4: Convert SEC1 point → PEM SPKI ==="
python3 - "$PK_B64" <<'PY'
import sys, base64
pk = base64.b64decode(sys.argv[1])
prefix = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
body = base64.b64encode(prefix + pk).decode()
pem = '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(body[i:i+64] for i in range(0, len(body), 64)) + '\n-----END PUBLIC KEY-----\n'
open('/tmp/pk.pem', 'w').write(pem)
print(f"  wrote /tmp/pk.pem ({len(pk)}-byte SEC1 point wrapped as SPKI)")
PY

echo ""
echo "=== Step 5: openssl dgst -sha256 -verify ==="
printf 'hello world' > /tmp/payload.bin
echo "  payload: 'hello world'"
echo "  verifying..."
openssl dgst -sha256 -verify /tmp/pk.pem -signature /tmp/sig.der /tmp/payload.bin
SCRIPT