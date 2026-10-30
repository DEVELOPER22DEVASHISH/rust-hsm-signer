#!/bin/sh
# Container entrypoint.
# When HSM_INIT_TOKEN=true, initialises a SoftHSM2 token if it does not already exist.
# For a real HSM the token is provisioned out-of-band; do not set HSM_INIT_TOKEN=true.
set -eu

if [ "${HSM_INIT_TOKEN:-false}" = "true" ]; then
    if ! softhsm2-util --show-slots | grep -q "Label:[[:space:]]*${HSM_TOKEN_LABEL}\$"; then
        echo "Initialising SoftHSM2 token '${HSM_TOKEN_LABEL}' ..."
        softhsm2-util \
            --init-token --free \
            --label "${HSM_TOKEN_LABEL}" \
            --so-pin "$(cat "${HSM_SO_PIN_FILE}")" \
            --pin    "$(cat "${HSM_PIN_FILE}")"    \
            >/dev/null
        echo "Token initialised."
    else
        echo "Token '${HSM_TOKEN_LABEL}' already exists; skipping init."
    fi
fi

exec /usr/local/bin/hsm-signer