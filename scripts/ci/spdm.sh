#!/usr/bin/env bash
# Run inside the shared CI image; Harden-Runner monitors Docker from the host.
set -euo pipefail

: "${WOLFSSL_SHA:?}" "${SPDM_NAME:?}" "${SPDM_MODE:?}"
prefix="$PWD/wolfssl-install"
# Checkout and cache files belong to the host runner, not the container user.
git config --global --add safe.directory "$PWD"
git config --global --add safe.directory "$PWD/wolfssl"
if [ "${WOLFSSL_CACHE_HIT:-false}" != true ]; then
    rm -rf wolfssl
    git init -q wolfssl
    git -C wolfssl remote add origin https://github.com/wolfSSL/wolfssl.git
    git -C wolfssl fetch --depth 1 origin "$WOLFSSL_SHA"
    git -C wolfssl checkout -q --detach FETCH_HEAD
    (
        cd wolfssl
        ./autogen.sh
        ./configure --enable-wolftpm --enable-pkcallbacks --enable-keygen \
            --enable-aescfb CFLAGS=-DWC_RSA_NO_PADDING --prefix="$prefix"
        make -j"$(nproc)"
    )
fi
make -C wolfssl install
export LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

./autogen.sh
if [ "$SPDM_MODE" = build ]; then
    read -r -a config <<< "${SPDM_CONFIG:?}"
else
    config=(--enable-fwtpm --enable-spdm --enable-tcg --enable-psk
        --enable-nuvoton --enable-nations --enable-debug --enable-swtpm)
fi
./configure "${config[@]}" --with-wolfcrypt="$prefix"
make -j"$(nproc)"

if [ "$SPDM_MODE" = build ]; then
    make install DESTDIR="$PWD/inst" >/dev/null
    printf '%s\n' '#include <wolftpm/tpm2_wrap.h>' \
        '#include <wolftpm/spdm/spdm.h>' '#include <wolfspdm/spdm.h>' \
        'int main(void) { return 0; }' > consumer.c
    cc -c consumer.c -o consumer.o -I"$PWD/inst/usr/local/include" \
        -I"$prefix/include"
    printf '%s\n' '#include <wolfspdm/spdm.h>' \
        'int main(void) { return 0; }' > consumer2.c
    cc -c consumer2.c -o consumer2.o -I"$PWD/inst/usr/local/include" \
        -I"$prefix/include"
    case "$SPDM_NAME" in
        spdm-nuvoton)
            vendor=nations
            expected='Nations adapter is not available in this build' ;;
        spdm-nations)
            vendor=nuvoton
            expected='Nuvoton adapter is not available in this build' ;;
        *) exit 0 ;;
    esac
    if output=$(./examples/spdm/spdm_ctrl "--vendor=$vendor" --status 2>&1); then
        echo 'Expected unavailable vendor rejection' >&2
        exit 1
    fi
    grep -F "$expected" <<< "$output"
else
    make check 2>&1 | tee "make-check-$SPDM_NAME.log"
    ./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl "$SPDM_MODE" \
        2>&1 | tee "spdm-$SPDM_MODE.log"
fi
