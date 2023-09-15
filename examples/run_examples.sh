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

# Native API test TPM2_x
echo -e "Native tests for TPM2_x API's"
./examples/native/native_test >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "native_test failed! $RESULT$RESULT" && exit 1


# Wrapper tests
echo -e "Wrapper tests"
./examples/wrap/wrap_test >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "wrap_test failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/wrap/wrap_test -xor >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "wrap_test (XOR param enc) failed! $RESULT" && exit 1
fi
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/wrap/wrap_test -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "wrap_test (AES param enc) failed! $RESULT" && exit 1
fi


# Key Generation Tests
echo -e "Ken Generation Tests"
./examples/keygen/keygen keyblob.bin -rsa >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen rsa failed! $RESULT" && exit 1
./examples/keygen/keyload keyblob.bin >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keyload rsa failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/keygen/keygen keyblob.bin -rsa -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen rsa param enc failed! $RESULT" && exit 1
    ./examples/keygen/keyload keyblob.bin -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload rsa param enc failed! $RESULT" && exit 1

    ./examples/keygen/keyimport rsakeyblob.bin -rsa >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload rsa import load failed! $RESULT" && exit 1
    ./examples/keygen/keyload rsakeyblob.bin >> run.out
    RESULT=$?
    rm -f rsakeyblob.bin
    [ $RESULT -ne 0 ] && echo -e "keyload rsa import load failed! $RESULT" && exit 1
fi
# keeping keyblob.bin for later tests

./examples/keygen/keygen ecckeyblob.bin -ecc >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen ecc failed! $RESULT" && exit 1
./examples/keygen/keyload ecckeyblob.bin >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keyload ecc failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/keygen/keygen ecckeyblob.bin -ecc -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen ecc param enc failed! $RESULT" && exit 1
    ./examples/keygen/keyload ecckeyblob.bin -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload ecc param enc failed! $RESULT" && exit 1

    ./examples/keygen/keyimport ecckeyblob.bin -ecc >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload ecc import failed! $RESULT" && exit 1
    # TODO: TPM2_Load (TPM_RC_INTEGRITY)
    #./examples/keygen/keyload ecckeyblob.bin >> run.out
fi
rm -f ecckeyblob.bin

./examples/keygen/keygen symkeyblob.bin -sym=aescfb128 >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen sym aes failed! $RESULT" && exit 1
./examples/keygen/keyload symkeyblob.bin >> run.out
RESULT=$?
rm -f symkeyblob.bin
[ $RESULT -ne 0 ] && echo -e "keygen sym aes load failed! $RESULT" && exit 1

./examples/keygen/keygen keyedhashblob.bin -keyedhash >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen keyed hash failed! $RESULT" && exit 1
./examples/keygen/keyload keyedhashblob.bin >> run.out
RESULT=$?
rm -f keyedhashblob.bin
[ $RESULT -ne 0 ] && echo -e "keygen keyed hash load failed! $RESULT" && exit 1

# KeyGen Endorsement with Policy Secret
# TODO Fix: (TPM2_Create TPM_RC_AUTH_UNAVAILABLE)
#./examples/keygen/keygen rsakeyblobeh.bin -rsa -eh >> run.out


# NV Tests
echo -e "NV Tests"
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/nvram/store -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv store param enc failed! $RESULT" && exit 1
    ./examples/nvram/read -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv read param enc failed! $RESULT" && exit 1
fi
./examples/nvram/store -priv >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv store priv only failed! $RESULT" && exit 1
./examples/nvram/read -priv >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv read priv only failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/nvram/store -priv -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv store priv only param enc failed! $RESULT" && exit 1
    ./examples/nvram/read -priv -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv read priv only param enc failed! $RESULT" && exit 1
fi
./examples/nvram/store -pub >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv store pub only failed! $RESULT" && exit 1
./examples/nvram/read -pub >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv read pub only failed! $RESULT" && exit 1

./examples/nvram/policy_nv >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv policy nv failed! $RESULT" && exit 1
./examples/nvram/policy_nv -aes >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv policy nv aes failed! $RESULT" && exit 1


# CSR Tests
./examples/keygen/keygen rsa_test_blob.raw -rsa -t >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen rsa test for csr failed! $RESULT" && exit 1
./examples/keygen/keygen ecc_test_blob.raw -ecc -t >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen ecc test for csr failed! $RESULT" && exit 1

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/csr/csr -cert >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "cert self-signed failed! $RESULT" && exit 1

    cp ./certs/tpm-rsa-cert.pem $WOLFSSL_PATH/certs/tpm-rsa-cert.pem >> run.out
    cp ./certs/tpm-ecc-cert.pem $WOLFSSL_PATH/certs/tpm-ecc-cert.pem >> run.out

    ./examples/csr/csr >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "csr gen failed! $RESULT" && exit 1

    ./certs/certreq.sh 2>&1 >> run.out
    cp ./certs/ca-ecc-cert.pem $WOLFSSL_PATH/certs/tpm-ca-ecc-cert.pem >> run.out
    cp ./certs/ca-rsa-cert.pem $WOLFSSL_PATH/certs/tpm-ca-rsa-cert.pem >> run.out
fi

# PKCS7 Tests
echo -e "PKCS7 tests"
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/pkcs7/pkcs7 >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pkcs7 failed! $RESULT" && exit 1
fi

# TLS Tests RSA
echo -e "TLS tests"
generate_port() { # function to produce a random port number
    if [[ "$OSTYPE" == "linux"* ]]; then
        port=$(($(od -An -N2 /dev/urandom) % (65535-49512) + 49512))
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        port=$(($(od -An -N2 /dev/random) % (65535-49512) + 49512))
    else
        echo "Unknown OS TYPE"
        exit 1
    fi
    echo -e "Using port $port" >> run.out
}

run_tpm_tls_client() { # Usage: run_tpm_tls_client [ecc/rsa] [tpmargs]]
    echo -e "TLS test (TPM as client) $1 $2"
    generate_port
    pushd $WOLFSSL_PATH >> run.out
    ./examples/server/server -p $port -g -A ./certs/tpm-ca-$1-cert.pem 2>&1 >> $PWD/run.out &
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tls server $1 $2 failed! $RESULT" && exit 1
    popd >> run.out
    sleep 0.2
    ./examples/tls/tls_client -p=$port -$1 $2 2>&1 >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tpm tls client $1 $2 failed! $RESULT" && exit 1
}

run_tpm_tls_server() { # Usage: run_tpm_tls_server [ecc/rsa] [tpmargs]]
    echo -e "TLS test (TPM as server) $1 $2"
    generate_port
    ./examples/tls/tls_server -p=$port -$1 $2 2>&1 >> run.out &
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tpm tls server $1 $2 failed! $RESULT" && exit 1
    pushd $WOLFSSL_PATH >> run.out
    sleep 0.2
    ./examples/client/client -p $port -g -A ./certs/tpm-ca-$1-cert.pem 2>&1 >> $PWD/run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tls client $1 $2 failed! $RESULT" && exit 1
    popd >> run.out
}

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    run_tpm_tls_client "rsa" ""
    # TODO: Not working (TPM2_Load TPM_RC_COMMAND_SIZE)
    #run_tpm_tls_client "rsa" "-aes"
    run_tpm_tls_client "ecc" ""
    # TODO: Not working (TPM2_Load TPM_RC_COMMAND_SIZE)
    #run_tpm_tls_client "ecc" "-aes"

    run_tpm_tls_server "rsa" ""
    # TODO: Not working (TPM2_Load TPM_RC_COMMAND_SIZE)
    #run_tpm_tls_server "rsa" "-aes"
    run_tpm_tls_server "ecc" ""
    # TODO: Not working (TPM2_Load TPM_RC_COMMAND_SIZE)
    #run_tpm_tls_server "ecc" "-aes"
fi


# Clock Tests
echo -e "Clock tests"
./examples/timestamp/clock_set
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "clock set failed! $RESULT" && exit 1


# Attestation tests
echo -e "Attestation tests"
./examples/timestamp/signed_timestamp >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "signed_timestamp failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/timestamp/signed_timestamp -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "signed_timestamp param enc failed! $RESULT" && exit 1
fi
# TODO: Test broken (wolfTPM2_GetTime TPM_RC_SCHEME)
#./examples/timestamp/signed_timestamp -ecc >> run.out
#if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    #./examples/timestamp/signed_timestamp -ecc -aes >> run.out
#fi

./examples/attestation/make_credential >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "make_credential failed! $RESULT" && exit 1
# TODO: Requires keygen -ek to be working
#./examples/attestation/make_credential -eh >> run.out
# TODO: Test broken (TPM2_ActivateCredentials TPM_RC_INTEGRITY)
#./examples/attestation/activate_credential >> run.out
#./examples/attestation/activate_credential -eh >> run.out


# PCR Quote Tests
echo -e "PCR Quote tests"
./examples/pcr/reset 16 >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr reset failed! $RESULT" && exit 1
./examples/pcr/extend 16 /usr/bin/zip >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr extend file failed! $RESULT" && exit 1
./examples/pcr/quote 16 zip.quote >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr quote failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/pcr/quote 16 zip.quote -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr quote param enc failed! $RESULT" && exit 1
fi
./examples/pcr/quote 16 zip.quote -ecc >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr quote ecc failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/pcr/quote 16 zip.quote -ecc -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr quote ecc param enc failed! $RESULT" && exit 1
fi
rm -f zip.quote


# Benchmark tests
echo -e "Benchmark tests"
./examples/bench/bench -maxdur=25 >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "bench failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/bench/bench -maxdur=25 -aes >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "bench (AES param enc) failed! $RESULT" && exit 1
fi

# Secure Boot ROT
echo -e "Secure Boot ROT (Root of Trust) test"
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/boot/secure_rot -nvindex=0x1400200 -authstr=test -write=./certs/example-ecc256-key-pub.der >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc256! $RESULT" && exit 1
    ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test -write=./certs/example-ecc384-key-pub.der -sha384 >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384! $RESULT" && exit 1
    ./examples/boot/secure_rot -nvindex=0x1400202 -authstr=test -write=./certs/example-rsa2048-key-pub.der >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write rsa2048! $RESULT" && exit 1
    ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test -sha384 -hash=e77dd3112a27948a3f2d87f32dc69ebeed0b3344c5d7726f5742f4f0c0f451aabe4213f8b3b986639e69ed0ea8b49d94 >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384 again! $RESULT" && exit 1

    if test $ENABLE_DESTRUCTIVE_TESTS -eq 1
    then
        ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test -lock >> run.out
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384 lock! $RESULT" && exit 1
        # Test expected failure case
        ./examples/boot/secure_rot -nvindex=0x1400201 -write=./certs/example-ecc384-key-pub.der -sha384 >> run.out
        RESULT=$?
        [ $RESULT -eq 0 ] && echo -e "secure rot write ecc384 should be locked! $RESULT" && exit 1
    fi

    ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384 read! $RESULT" && exit 1

    # Test expected failure case
    ./examples/boot/secure_rot -nvindex=0x1400201 >> run.out
    RESULT=$?
    [ $RESULT -eq 0 ] && echo -e "secure rot write ecc384 read no auth! $RESULT" && exit 1
fi

# Seal/Unseal (PCR Policy)
echo -e "Seal/Unseal (PCR policy)"
./examples/seal/seal sealedkeyblob.bin mySecretMessage >> run.out
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "seal pcr failed! $RESULT" && exit 1
# TODO (TPM2_Load TPM_RC_BAD_AUTH)
#./examples/seal/unseal message.raw sealedkeyblob.bin >> run.out
rm -f sealedkeyblob.bin


# Seal/Unseal (Policy auth)
echo -e "Seal/Unseal (Policy auth)"
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    # Extend "aaa" to test PCR 16
    echo aaa > aaa.bin
    ./examples/pcr/reset 16 >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr 16 reset failed! $RESULT" && exit 1
    ./examples/pcr/extend 16 aaa.bin >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr 16 extend failed! $RESULT" && exit 1

    # RSA
    ./examples/pcr/policy_sign -pcr=16 -rsa -key=./certs/example-rsa2048-key.der -out=pcrsig.bin -outpolicy=policyauth.bin >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign rsa der failed! $RESULT" && exit 1
    ./examples/pcr/policy_sign -pcr=16 -rsa -key=./certs/example-rsa2048-key.pem -out=pcrsig.bin -outpolicy=policyauth.bin >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign rsa pem failed! $RESULT" && exit 1

    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -rsa -policy=policyauth.bin -out=sealblob.bin -secretstr=$SECRET_STRING >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal rsa failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -rsa -publickey=./certs/example-rsa2048-key-pub.der -seal=sealblob.bin | tee $TMPFILE >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret unseal rsa failed! $RESULT" && exit 1
    grep "$SECRET_STRING" $TMPFILE >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret unseal rsa match failed! $RESULT" && exit 1

    # RSA (recreate policy auth using public key instead of using policyauth.bin)
    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -rsa -publickey=./certs/example-rsa2048-key-pub.der -out=sealblob.bin -secretstr=$SECRET_STRING >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal rsa alt failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -rsa -publickey=./certs/example-rsa2048-key-pub.der -seal=sealblob.bin | tee $TMPFILE >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret unseal rsa alt failed! $RESULT" && exit 1
    grep "$SECRET_STRING" $TMPFILE >> run.out
    RESULT=$?
    rm -f $TMPFILE
    [ $RESULT -ne 0 ] && echo -e "secret unseal rsa alt match failed! $RESULT" && exit 1

    # ECC
    ./examples/pcr/policy_sign -pcr=16 -ecc -key=./certs/example-ecc256-key.der -out=pcrsig.bin -outpolicy=policyauth.bin >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign ecc der failed! $RESULT" && exit 1
    ./examples/pcr/policy_sign -pcr=16 -ecc -key=./certs/example-ecc256-key.pem -out=pcrsig.bin -outpolicy=policyauth.bin >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign ecc pem failed! $RESULT" && exit 1

    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -ecc -policy=policyauth.bin -out=sealblob.bin -secretstr=$SECRET_STRING >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal ecc failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -ecc -publickey=./certs/example-ecc256-key-pub.der -seal=sealblob.bin | tee $TMPFILE >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret unseal ecc failed! $RESULT" && exit 1
    grep "$SECRET_STRING" $TMPFILE >> run.out
    RESULT=$?
    rm -f $TMPFILE
    [ $RESULT -ne 0 ] && echo -e "secret unseal ecc match failed! $RESULT" && exit 1

    # ECC (recreate policy auth using public key instead of using policyauth.bin)
    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -ecc -publickey=./certs/example-ecc256-key-pub.der -out=sealblob.bin -secretstr=$SECRET_STRING >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal ecc alt failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -ecc -publickey=./certs/example-ecc256-key-pub.der -seal=sealblob.bin | tee $TMPFILE >> run.out
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret unseal ecc alt failed! $RESULT" && exit 1
    grep "$SECRET_STRING" $TMPFILE >> run.out
    RESULT=$?
    rm -f $TMPFILE
    [ $RESULT -ne 0 ] && echo -e "secret unseal ecc alt match failed! $RESULT" && exit 1

    rm -f aaa.bin
fi


echo -e "Success!"
exit 0
