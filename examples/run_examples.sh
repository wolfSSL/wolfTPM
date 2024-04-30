#!/bin/bash

RESULT=0
ENABLE_DESTRUCTIVE_TESTS=0
PWD=$(pwd)

if [ -z "$WOLFSSL_PATH" ]; then
    WOLFSSL_PATH=../wolfssl
fi
if [ -z "$WOLFCRYPT_ENABLE" ]; then
    WOLFCRYPT_ENABLE=1
fi

rm -f run.out
touch run.out


# Create Primary Tests
echo -e "Create Primary Tests"
./examples/keygen/create_primary -rsa -oh >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary owner rsa key failed! $RESULT" && exit 1
./examples/keygen/create_primary -ecc -oh >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary owner ecc key failed! $RESULT" && exit 1

./examples/keygen/create_primary -rsa -eh >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary endosement rsa key failed! $RESULT" && exit 1
./examples/keygen/create_primary -ecc -eh >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary endosement ecc key failed! $RESULT" && exit 1

./examples/keygen/create_primary -rsa -ph >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary platform rsa key failed! $RESULT" && exit 1
./examples/keygen/create_primary -ecc -ph >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary platform ecc key failed! $RESULT" && exit 1

./examples/keygen/create_primary -rsa -oh -auth=ThisIsMyStorageKeyAuth -store=0x81000200 >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary owner rsa key stored failed! $RESULT" && exit 1

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/keygen/create_primary -rsa -oh -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary owner rsa key param enc failed! $RESULT" && exit 1
    ./examples/keygen/create_primary -ecc -oh -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary owner ecc key param enc failed! $RESULT" && exit 1

    ./examples/keygen/create_primary -rsa -eh -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary endosement rsa key param enc failed! $RESULT" && exit 1
    ./examples/keygen/create_primary -ecc -eh -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary endosement ecc key param enc failed! $RESULT" && exit 1

    ./examples/keygen/create_primary -rsa -ph -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary platform rsa key param enc failed! $RESULT" && exit 1
    ./examples/keygen/create_primary -ecc -ph -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary platform ecc key param enc failed! $RESULT" && exit 1
fi



# Native API test TPM2_x
echo -e "Native tests for TPM2_x API's"
./examples/native/native_test >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "native_test failed! $RESULT$RESULT" && exit 1


# Wrapper tests
echo -e "Wrapper tests"
./examples/wrap/wrap_test >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "wrap_test failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/wrap/wrap_test -xor >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "wrap_test (XOR param enc) failed! $RESULT" && exit 1
fi
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/wrap/wrap_test -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "wrap_test (AES param enc) failed! $RESULT" && exit 1
fi


# Key Generation Tests
echo -e "Key Generation Tests"
./examples/keygen/keygen keyblob.bin -rsa >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen rsa failed! $RESULT" && exit 1
./examples/keygen/keyload keyblob.bin >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keyload rsa failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/keygen/keygen keyblob.bin -rsa -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen rsa param enc failed! $RESULT" && exit 1
    ./examples/keygen/keyload keyblob.bin -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload rsa param enc failed! $RESULT" && exit 1

    ./examples/keygen/keyimport rsakeyblob.bin -rsa >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload rsa import load failed! $RESULT" && exit 1
    ./examples/keygen/keyload rsakeyblob.bin >> run.out 2>&1
    RESULT=$?
    rm -f rsakeyblob.bin
    [ $RESULT -ne 0 ] && echo -e "keyload rsa import load failed! $RESULT" && exit 1
fi
# keeping keyblob.bin for later tests

./examples/keygen/keygen ecckeyblob.bin -ecc >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen ecc failed! $RESULT" && exit 1
./examples/keygen/keyload ecckeyblob.bin >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keyload ecc failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/keygen/keygen ecckeyblob.bin -ecc -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen ecc param enc failed! $RESULT" && exit 1
    ./examples/keygen/keyload ecckeyblob.bin -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload ecc param enc failed! $RESULT" && exit 1
    ./examples/keygen/keyimport ecckeyblob.bin -ecc >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload ecc import failed! $RESULT" && exit 1
fi
rm -f ecckeyblob.bin

./examples/keygen/keygen symkeyblob.bin -sym=aescfb128 >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen sym aes failed! $RESULT" && exit 1
./examples/keygen/keyload symkeyblob.bin >> run.out 2>&1
RESULT=$?
rm -f symkeyblob.bin
[ $RESULT -ne 0 ] && echo -e "keygen sym aes load failed! $RESULT" && exit 1

./examples/keygen/keygen keyedhashblob.bin -keyedhash >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen keyed hash failed! $RESULT" && exit 1
./examples/keygen/keyload keyedhashblob.bin >> run.out 2>&1
RESULT=$?
rm -f keyedhashblob.bin
[ $RESULT -ne 0 ] && echo -e "keygen keyed hash load failed! $RESULT" && exit 1

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    # KeyGen under Endorsement
    ./examples/keygen/keygen rsakeyblobeh.bin -rsa -eh >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen endorsement rsa failed! $RESULT" && exit 1
    ./examples/keygen/keyload rsakeyblobeh.bin -rsa -eh >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload endorsement rsa failed! $RESULT" && exit 1

    ./examples/keygen/keygen ecckeyblobeh.bin -ecc -eh >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen endorsement rsa failed! $RESULT" && exit 1
    ./examples/keygen/keyload ecckeyblobeh.bin -ecc -eh >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen endorsement rsa failed! $RESULT" && exit 1
fi


# NV Tests
echo -e "NV Tests"
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/nvram/store -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv store param enc failed! $RESULT" && exit 1
    ./examples/nvram/read -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv read param enc failed! $RESULT" && exit 1
fi
./examples/nvram/store -priv >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv store priv only failed! $RESULT" && exit 1
./examples/nvram/read -priv >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv read priv only failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/nvram/store -priv -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv store priv only param enc failed! $RESULT" && exit 1
    ./examples/nvram/read -priv -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv read priv only param enc failed! $RESULT" && exit 1
fi
./examples/nvram/store -pub >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv store pub only failed! $RESULT" && exit 1
./examples/nvram/read -pub >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv read pub only failed! $RESULT" && exit 1

./examples/nvram/policy_nv >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv policy nv failed! $RESULT" && exit 1
./examples/nvram/policy_nv -aes >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv policy nv aes failed! $RESULT" && exit 1


# CSR Tests
./examples/keygen/keygen rsa_test_blob.raw -rsa -t >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen rsa test for csr failed! $RESULT" && exit 1
./examples/keygen/keygen ecc_test_blob.raw -ecc -t >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen ecc test for csr failed! $RESULT" && exit 1

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/csr/csr -cert >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "cert self-signed failed! $RESULT" && exit 1

    cp ./certs/tpm-rsa-cert.pem $WOLFSSL_PATH/certs/tpm-rsa-cert.pem >> run.out 2>&1
    cp ./certs/tpm-ecc-cert.pem $WOLFSSL_PATH/certs/tpm-ecc-cert.pem >> run.out 2>&1

    ./examples/csr/csr >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "csr gen failed! $RESULT" && exit 1

    ./certs/certreq.sh 2>&1 >> run.out 2>&1
    cp ./certs/ca-ecc-cert.pem $WOLFSSL_PATH/certs/tpm-ca-ecc-cert.pem >> run.out 2>&1
    cp ./certs/ca-rsa-cert.pem $WOLFSSL_PATH/certs/tpm-ca-rsa-cert.pem >> run.out 2>&1
fi

# PKCS7 Tests
echo -e "PKCS7 tests"
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/pkcs7/pkcs7 >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pkcs7 failed! $RESULT" && exit 1

    ./examples/pkcs7/pkcs7 -ecc >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pkcs7 ecc failed! $RESULT" && exit 1
fi

# TLS Tests
echo -e "TLS tests"
generate_port() {
    # for now it is okay to use the same port
    # Note: The SW TPM uses many local ports, which can cause bind() issue
    port=11111
    echo -e "Using port $port"
    echo -e "Using port $port" >> run.out 2>&1
}

run_tpm_tls_client() { # Usage: run_tpm_tls_client [ecc/rsa] [tpmargs]]
    echo -e "TLS test (TPM as client) $1 $2"
    generate_port
    pushd $WOLFSSL_PATH >> run.out 2>&1
    echo -e "./examples/server/server -p $port -w -g -A ./certs/tpm-ca-$1-cert.pem"
    ./examples/server/server -p $port -w -g -A ./certs/tpm-ca-$1-cert.pem &> $PWD/run.out &
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tls server $1 $2 failed! $RESULT" && exit 1
    popd >> run.out 2>&1
    sleep 0.1

    echo -e "./examples/tls/tls_client -p=$port -$1 $2"
    ./examples/tls/tls_client -p=$port -$1 $2 >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tpm tls client $1 $2 failed! $RESULT" && exit 1
}

run_tpm_tls_server() { # Usage: run_tpm_tls_server [ecc/rsa] [tpmargs]]
    echo -e "TLS test (TPM as server) $1 $2"
    generate_port

    echo -e "./examples/tls/tls_server -p=$port -$1 $2"
    ./examples/tls/tls_server -p=$port -$1 $2 >> run.out 2>&1 &
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tpm tls server $1 $2 failed! $RESULT" && exit 1
    pushd $WOLFSSL_PATH >> run.out 2>&1
    sleep 0.1

    echo -e "./examples/client/client -p $port -w -g -A ./certs/tpm-ca-$1-cert.pem"
    ./examples/client/client -p $port -w -g -A ./certs/tpm-ca-$1-cert.pem &> $PWD/run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tls client $1 $2 failed! $RESULT" && exit 1
    popd >> run.out 2>&1
}

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    # Run with Crypto CB
    run_tpm_tls_client "rsa" ""
    run_tpm_tls_client "rsa" "-aes"
    run_tpm_tls_client "ecc" ""
    run_tpm_tls_client "ecc" "-aes"

    run_tpm_tls_server "rsa" ""
    run_tpm_tls_server "rsa" "-aes"
    run_tpm_tls_server "ecc" ""
    run_tpm_tls_server "ecc" "-aes"

    # Run with PK
    run_tpm_tls_client "rsa" "-pk"
    run_tpm_tls_client "rsa" "-pk -aes"
    run_tpm_tls_client "ecc" "-pk"
    run_tpm_tls_client "ecc" "-pk -aes"

    run_tpm_tls_server "rsa" "-pk "
    run_tpm_tls_server "rsa" "-pk -aes"
    run_tpm_tls_server "ecc" "-pk"
    run_tpm_tls_server "ecc" "-pk -aes"
fi


# Clock Tests
echo -e "Clock tests"
./examples/timestamp/clock_set >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "clock set failed! $RESULT" && exit 1


# Attestation tests
echo -e "Attestation tests"
./examples/timestamp/signed_timestamp >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "signed_timestamp failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/timestamp/signed_timestamp -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "signed_timestamp param enc failed! $RESULT" && exit 1
fi
./examples/timestamp/signed_timestamp -ecc >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "signed_timestamp ecc failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/timestamp/signed_timestamp -ecc -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "signed_timestamp ecc param enc failed! $RESULT" && exit 1
fi

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/keygen/keygen keyblob.bin -rsa >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen rsa failed! $RESULT" && exit 1
    ./examples/attestation/make_credential >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "make_credential failed! $RESULT" && exit 1
    ./examples/attestation/activate_credential >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "activate_credential failed! $RESULT" && exit 1

    # Endorsement hierarchy
    ./examples/keygen/keygen keyblob.bin -rsa -eh >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen rsa endorsement failed! $RESULT" && exit 1
    ./examples/attestation/make_credential -eh >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "make_credential endorsement failed! $RESULT" && exit 1
    ./examples/attestation/activate_credential -eh >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "activate_credential endorsement failed! $RESULT" && exit 1

    rm -f cred.blob
    rm -f ek.pub
    rm -f srk.pub
    rm -f ak.name
fi

# PCR Quote Tests
echo -e "PCR Quote tests"
./examples/pcr/reset 16 >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr reset failed! $RESULT" && exit 1
./examples/pcr/extend 16 /usr/bin/zip >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr extend file failed! $RESULT" && exit 1
./examples/pcr/quote 16 zip.quote >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr quote failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/pcr/quote 16 zip.quote -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr quote param enc failed! $RESULT" && exit 1
fi
./examples/pcr/quote 16 zip.quote -ecc >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr quote ecc failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/pcr/quote 16 zip.quote -ecc -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr quote ecc param enc failed! $RESULT" && exit 1
fi
rm -f zip.quote


# Benchmark tests
echo -e "Benchmark tests"
./examples/bench/bench -maxdur=25 >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "bench failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/bench/bench -maxdur=25 -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "bench (AES param enc) failed! $RESULT" && exit 1
fi

# Secure Boot ROT
echo -e "Secure Boot ROT (Root of Trust) test"
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/boot/secure_rot -nvindex=0x1400200 -authstr=test -write=./certs/example-ecc256-key-pub.der >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc256! $RESULT" && exit 1
    ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test -write=./certs/example-ecc384-key-pub.der -sha384 >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384! $RESULT" && exit 1
    ./examples/boot/secure_rot -nvindex=0x1400202 -authstr=test -write=./certs/example-rsa2048-key-pub.der >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write rsa2048! $RESULT" && exit 1
    ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test -sha384 -hash=e77dd3112a27948a3f2d87f32dc69ebeed0b3344c5d7726f5742f4f0c0f451aabe4213f8b3b986639e69ed0ea8b49d94 >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384 again! $RESULT" && exit 1

    if test $ENABLE_DESTRUCTIVE_TESTS -eq 1
    then
        ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test -lock >> run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384 lock! $RESULT" && exit 1
        # Test expected failure case
        ./examples/boot/secure_rot -nvindex=0x1400201 -write=./certs/example-ecc384-key-pub.der -sha384 >> run.out 2>&1
        RESULT=$?
        [ $RESULT -eq 0 ] && echo -e "secure rot write ecc384 should be locked! $RESULT" && exit 1
    fi

    ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384 read! $RESULT" && exit 1

    # Test expected failure case
    ./examples/boot/secure_rot -nvindex=0x1400201 >> run.out 2>&1
    RESULT=$?
    [ $RESULT -eq 0 ] && echo -e "secure rot write ecc384 read no auth! $RESULT" && exit 1
fi

# Seal/Unseal (PCR Policy)
echo -e "Seal/Unseal (PCR policy)"
./examples/seal/seal sealedkeyblob.bin mySecretMessage >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "seal failed! $RESULT" && exit 1
./examples/seal/unseal message.raw sealedkeyblob.bin >> run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "unseal failed! $RESULT" && exit 1
rm -f sealedkeyblob.bin

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/seal/seal sealedkeyblob.bin mySecretMessage -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "seal aes failed! $RESULT" && exit 1
    ./examples/seal/unseal message.raw sealedkeyblob.bin -aes >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "unseal aes failed! $RESULT" && exit 1
    rm -f sealedkeyblob.bin
fi

# Seal/Unseal (Policy auth)
echo -e "Seal/Unseal (Policy auth)"
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    # Extend "aaa" to test PCR 16
    echo aaa > aaa.bin
    ./examples/pcr/reset 16 >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr 16 reset failed! $RESULT" && exit 1
    ./examples/pcr/extend 16 aaa.bin >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr 16 extend failed! $RESULT" && exit 1

    # RSA
    ./examples/pcr/policy_sign -pcr=16 -rsa -key=./certs/example-rsa2048-key.der -out=pcrsig.bin -outpolicy=policyauth.bin >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign rsa der failed! $RESULT" && exit 1
    ./examples/pcr/policy_sign -pcr=16 -rsa -key=./certs/example-rsa2048-key.pem -out=pcrsig.bin -outpolicy=policyauth.bin >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign rsa pem failed! $RESULT" && exit 1

    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -rsa -policy=policyauth.bin -out=sealblob.bin -secretstr=$SECRET_STRING >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal rsa failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -rsa -publickey=./certs/example-rsa2048-key-pub.der -seal=sealblob.bin &> $TMPFILE
    RESULT=$?
    cat $TMPFILE >> run.out
    [ $RESULT -ne 0 ] && echo -e "secret unseal rsa failed! $RESULT" && exit 1
    grep "$SECRET_STRING" $TMPFILE >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret unseal rsa match failed! $RESULT" && exit 1

    # RSA (recreate policy auth using public key instead of using policyauth.bin)
    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -rsa -publickey=./certs/example-rsa2048-key-pub.der -out=sealblob.bin -secretstr=$SECRET_STRING >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal rsa alt failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -rsa -publickey=./certs/example-rsa2048-key-pub.der -seal=sealblob.bin &> $TMPFILE
    RESULT=$?
    cat $TMPFILE >> run.out
    [ $RESULT -ne 0 ] && echo -e "secret unseal rsa alt failed! $RESULT" && exit 1
    grep "$SECRET_STRING" $TMPFILE >> run.out 2>&1
    RESULT=$?
    rm -f $TMPFILE
    [ $RESULT -ne 0 ] && echo -e "secret unseal rsa alt match failed! $RESULT" && exit 1

    # Test RSA Unseal Expected Failure Case
    # Create different ECC policy key to test failure case
    openssl genrsa -out tmp-rsa2048-key.pem 2048 >> run.out 2>&1
    openssl rsa -in tmp-rsa2048-key.pem -outform der -out tmp-rsa2048-key-pub.der -pubout >> run.out 2>&1

    # Sign policy using different private key
    ./examples/pcr/policy_sign -pcr=16 -rsa -key=tmp-rsa2048-key.pem -out=pcrsig_fail.bin -outpolicy=policyauth.bin >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign (expected failure case) rsa pem failed! $RESULT" && exit 1

    # This RSA unseal should fail!
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig_fail.bin -rsa -publickey=tmp-rsa2048-key-pub.der -seal=sealblob.bin >> run.out 2>&1
    RESULT=$?
    [ $RESULT -eq 0 ] && echo -e "secret unseal rsa should have failed! $RESULT" && exit 1


    rm -f tmp-rsa2048-key.pem
    rm -f tmp-rsa2048-key-pub.der
    rm -f pcrsig_fail.bin


    # ECC
    ./examples/pcr/policy_sign -pcr=16 -ecc -key=./certs/example-ecc256-key.der -out=pcrsig.bin -outpolicy=policyauth.bin >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign ecc der failed! $RESULT" && exit 1
    ./examples/pcr/policy_sign -pcr=16 -ecc -key=./certs/example-ecc256-key.pem -out=pcrsig.bin -outpolicy=policyauth.bin >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign ecc pem failed! $RESULT" && exit 1

    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -ecc -policy=policyauth.bin -out=sealblob.bin -secretstr=$SECRET_STRING >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal ecc failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -ecc -publickey=./certs/example-ecc256-key-pub.der -seal=sealblob.bin &> $TMPFILE
    RESULT=$?
    cat $TMPFILE >> run.out
    [ $RESULT -ne 0 ] && echo -e "secret unseal ecc failed! $RESULT" && exit 1

    grep "$SECRET_STRING" $TMPFILE >> run.out 2>&1
    RESULT=$?
    rm -f $TMPFILE
    [ $RESULT -ne 0 ] && echo -e "secret unseal ecc match failed! $RESULT" && exit 1


    # ECC (recreate policy auth using public key instead of using policyauth.bin)
    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -ecc -publickey=./certs/example-ecc256-key-pub.der -out=sealblob.bin -secretstr=$SECRET_STRING >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal ecc alt failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -ecc -publickey=./certs/example-ecc256-key-pub.der -seal=sealblob.bin &> $TMPFILE
    RESULT=$?
    cat $TMPFILE >> run.out
    [ $RESULT -ne 0 ] && echo -e "secret unseal ecc alt failed! $RESULT" && exit 1
    grep "$SECRET_STRING" $TMPFILE >> run.out 2>&1
    RESULT=$?
    rm -f $TMPFILE
    [ $RESULT -ne 0 ] && echo -e "secret unseal ecc alt match failed! $RESULT" && exit 1


    # Test ECC Unseal Expected Failure Case
    # Create different ECC policy key to test failure case
    openssl ecparam -name prime256v1 -genkey -noout -out tmp-ecc256-key.pem >> run.out 2>&1
    openssl ec -in tmp-ecc256-key.pem -outform der -out tmp-ecc256-key-pub.der -pubout >> run.out 2>&1

    # Sign policy using different private key
    ./examples/pcr/policy_sign -pcr=16 -ecc -key=tmp-ecc256-key.pem -out=pcrsig_fail.bin -outpolicy=policyauth.bin >> run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign (expected failure case) ecc pem failed! $RESULT" && exit 1

    # This ECC unseal should fail!
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig_fail.bin -ecc -publickey=tmp-ecc256-key-pub.der -seal=sealblob.bin >> run.out 2>&1
    RESULT=$?
    [ $RESULT -eq 0 ] && echo -e "secret unseal ecc should have failed! $RESULT" && exit 1

    rm -f tmp-ecc256-key.pem
    rm -f tmp-ecc256-key-pub.der
    rm -f pcrsig_fail.bin

    rm -f pcrsig.bin
    rm -f policyauth.bin
    rm -f sealblob.bin
    rm -f aaa.bin

fi

rm -f keyblob.bin

echo -e "Success!"
exit 0
