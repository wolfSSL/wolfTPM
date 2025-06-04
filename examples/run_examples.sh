#!/bin/bash

RESULT=0
ENABLE_DESTRUCTIVE_TESTS=0
TPMPWD=$(pwd)

if [ -z "$WOLFSSL_PATH" ]; then
    WOLFSSL_PATH=../wolfssl
fi
if [ -z "$WOLFCRYPT_ENABLE" ]; then
    WOLFCRYPT_ENABLE=1
fi
if [ -z "$NO_FILESYSTEM" ]; then
    NO_FILESYSTEM=0
fi
if [ -z "$NO_PUBASPRIV" ]; then
    NO_PUBASPRIV=0
fi
if [ -z "$WOLFCRYPT_DEFAULT" ]; then
    WOLFCRYPT_DEFAULT=0
fi
if [ -z "$WOLFCRYPT_ECC" ]; then
    WOLFCRYPT_ECC=1
fi
if [ -z "$WOLFCRYPT_RSA" ]; then
    WOLFCRYPT_RSA=1
fi

rm -f run.out
touch run.out


# Create Primary Tests
echo -e "Create Primary Tests"
./examples/keygen/create_primary -rsa -oh >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary owner rsa key failed! $RESULT" && exit 1
./examples/keygen/create_primary -ecc -oh >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary owner ecc key failed! $RESULT" && exit 1

./examples/keygen/create_primary -rsa -eh >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary endorsement rsa key failed! $RESULT" && exit 1
./examples/keygen/create_primary -ecc -eh >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary endorsement ecc key failed! $RESULT" && exit 1

./examples/keygen/create_primary -rsa -ph >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary platform rsa key failed! $RESULT" && exit 1
./examples/keygen/create_primary -ecc -ph >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary platform ecc key failed! $RESULT" && exit 1

./examples/keygen/create_primary -rsa -oh -auth=ThisIsMyStorageKeyAuth -store=0x81000200 >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "create primary owner rsa key stored failed! $RESULT" && exit 1

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    # Provisioning examples (required --enable-provisioning)
    ./examples/keygen/create_primary -rsa -eh -iak -keep >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary endorsement rsa IAK key failed! $RESULT" && exit 1
    ./examples/keygen/create_primary -rsa -eh -idevid -keep >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary endorsement rsa IDevID key failed! $RESULT" && exit 1

    ./examples/attestation/certify -rsa -certify=0x80000001 -signer=0x80000000 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "certify RSA IDevID with IAK failed! $RESULT" && exit 1

    ./examples/management/flush 0x80000000 >> $TPMPWD/run.out 2>&1
    ./examples/management/flush 0x80000001 >> $TPMPWD/run.out 2>&1

    ./examples/keygen/create_primary -ecc -eh -iak -keep >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary endorsement ecc IAK key failed! $RESULT" && exit 1
    ./examples/keygen/create_primary -ecc -eh -idevid -keep >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary endorsement ecc IDevID key failed! $RESULT" && exit 1

    ./examples/attestation/certify -ecc -certify=0x80000001 -signer=0x80000000 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "certify ECC IDevID with IAK failed! $RESULT" && exit 1

    ./examples/management/flush 0x80000000 >> $TPMPWD/run.out 2>&1
    ./examples/management/flush 0x80000001 >> $TPMPWD/run.out 2>&1
fi

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/keygen/create_primary -rsa -oh -aes >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary owner rsa key param enc failed! $RESULT" && exit 1
    ./examples/keygen/create_primary -ecc -oh -aes >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary owner ecc key param enc failed! $RESULT" && exit 1

    ./examples/keygen/create_primary -rsa -eh -aes >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary endorsement rsa key param enc failed! $RESULT" && exit 1
    ./examples/keygen/create_primary -ecc -eh -aes >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary endorsement ecc key param enc failed! $RESULT" && exit 1

    ./examples/keygen/create_primary -rsa -ph -aes >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary platform rsa key param enc failed! $RESULT" && exit 1
    ./examples/keygen/create_primary -ecc -ph -aes >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "create primary platform ecc key param enc failed! $RESULT" && exit 1
fi



# Native API test TPM2_x
echo -e "Native tests for TPM2_x API's"
./examples/native/native_test >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "native_test failed! $RESULT$RESULT" && exit 1


# Wrapper tests
echo -e "Wrapper tests"
./examples/wrap/wrap_test >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "wrap_test failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/wrap/wrap_test -xor >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "wrap_test (XOR param enc) failed! $RESULT" && exit 1
fi
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/wrap/wrap_test -aes >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "wrap_test (AES param enc) failed! $RESULT" && exit 1
fi


# Key Generation Tests
echo -e "Key Generation Tests"
./examples/keygen/keygen keyblob.bin -rsa >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen rsa failed! $RESULT" && exit 1
./examples/keygen/keyload keyblob.bin >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keyload rsa failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/keygen/keygen keyblob.bin -rsa -xor >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen rsa param enc xor failed! $RESULT" && exit 1
    ./examples/keygen/keyload keyblob.bin -xor >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload rsa param enc xor failed! $RESULT" && exit 1

    if [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
        ./examples/keygen/keygen keyblob.bin -rsa -aes >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "keygen rsa param enc aes failed! $RESULT" && exit 1
        ./examples/keygen/keyload keyblob.bin -aes >> $TPMPWD/run.out 2>&1
        RESULT=$?

        if [ $WOLFCRYPT_RSA -eq 1 ]; then
            [ $RESULT -ne 0 ] && echo -e "keyload rsa param enc aes failed! $RESULT" && exit 1
            ./examples/keygen/keyimport rsakeyblob.bin -rsa >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "keyload rsa import load failed! $RESULT" && exit 1
            ./examples/keygen/keyload rsakeyblob.bin >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "keyload rsa load failed! $RESULT" && exit 1
            rm -f rsakeyblob.bin
        fi
    fi
fi
# keeping keyblob.bin for later tests

./examples/keygen/keygen eccblob.bin -ecc >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen ecc failed! $RESULT" && exit 1
./examples/keygen/keyload eccblob.bin >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keyload ecc failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    if [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
        ./examples/keygen/keygen eccblob.bin -ecc -aes >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "keygen ecc param enc failed! $RESULT" && exit 1
        ./examples/keygen/keyload eccblob.bin -aes >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "keyload ecc param enc failed! $RESULT" && exit 1

        if [ $WOLFCRYPT_ECC -eq 1 ]; then
            ./examples/keygen/keyimport ecckeyblob.bin -ecc >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "keyload ecc import failed! $RESULT" && exit 1

            ./examples/keygen/keyload ecckeyblob.bin >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "keyload ecc load failed! $RESULT" && exit 1
            rm -f ecckeyblob.bin
        fi
    fi
fi
rm -f ececcblob.bin


# KeyGen AES Tests
run_keygen_aes_test() { # Usage: run_keygen_aes_test [aescfb128]
    echo -e "KeyGen test: $1"
    ./examples/keygen/keygen symkeyblob.bin -sym=$1 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen sym $1 failed! $RESULT" && exit 1
    ./examples/keygen/keyload symkeyblob.bin >> $TPMPWD/run.out 2>&1
    RESULT=$?
    rm -f symkeyblob.bin
    [ $RESULT -ne 0 ] && echo -e "keygen sym $1 load failed! $RESULT" && exit 1
}

run_keygen_aes_test "aescfb128"
run_keygen_aes_test "aescfb256"
run_keygen_aes_test "aesctr128"
run_keygen_aes_test "aesctr256"
run_keygen_aes_test "aescbc128"
run_keygen_aes_test "aescbc256"

# AES 192-bit not supported with SWTPM
#run_keygen_aes_test "aescfb192"
#run_keygen_aes_test "aesctr192"
#run_keygen_aes_test "aescbc192"

./examples/keygen/keygen keyedhashblob.bin -keyedhash >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen keyed hash failed! $RESULT" && exit 1
./examples/keygen/keyload keyedhashblob.bin >> $TPMPWD/run.out 2>&1
RESULT=$?
rm -f keyedhashblob.bin
[ $RESULT -ne 0 ] && echo -e "keygen keyed hash load failed! $RESULT" && exit 1

if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    # KeyGen under Endorsement
    ./examples/keygen/keygen rsakeyblobeh.bin -rsa -eh >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen endorsement rsa failed! $RESULT" && exit 1
    ./examples/keygen/keyload rsakeyblobeh.bin -rsa -eh >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload endorsement rsa failed! $RESULT" && exit 1

    ./examples/keygen/keygen ecckeyblobeh.bin -ecc -eh >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen endorsement ecc failed! $RESULT" && exit 1
    ./examples/keygen/keyload ecckeyblobeh.bin -ecc -eh >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keyload endorsement ecc failed! $RESULT" && exit 1

    # TODO: Add tests for -auth= keygen when used in example
fi


# NV Tests
echo -e "NV Tests"
if [ $NO_FILESYSTEM -eq 0 ]; then
    if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
        ./examples/nvram/store -xor >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "nv store param enc xor failed! $RESULT" && exit 1
        ./examples/nvram/read -xor -delete >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "nv read param enc xor failed! $RESULT" && exit 1

        if [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
            ./examples/nvram/store -aes >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "nv store param enc aes failed! $RESULT" && exit 1
            ./examples/nvram/read -aes -delete >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "nv read param enc aes failed! $RESULT" && exit 1
        fi
    fi
    ./examples/nvram/store -priv >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv store priv only failed! $RESULT" && exit 1
    ./examples/nvram/read -priv -delete >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv read priv only failed! $RESULT" && exit 1
    if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
        ./examples/nvram/store -priv -xor >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "nv store priv only param enc xor failed! $RESULT" && exit 1
        ./examples/nvram/read -priv -xor -delete >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "nv read priv only param enc xor failed! $RESULT" && exit 1

        if [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
            ./examples/nvram/store -priv -aes >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "nv store priv only param enc aes failed! $RESULT" && exit 1
            ./examples/nvram/read -priv -aes -delete >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "nv read priv only param enc aes failed! $RESULT" && exit 1
        fi
    fi
    ./examples/nvram/store -pub >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv store pub only failed! $RESULT" && exit 1
    ./examples/nvram/read -pub -delete >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "nv read pub only failed! $RESULT" && exit 1

    if [ $WOLFCRYPT_ENABLE -eq 1 ] && [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
        # extend test
        ./examples/nvram/extend -aes
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "nv extend aes failed! $RESULT" && exit 1

        ./examples/nvram/extend -xor
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "nv extend xor failed! $RESULT" && exit 1
    fi
fi

./examples/nvram/policy_nv >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv policy nv failed! $RESULT" && exit 1
./examples/nvram/policy_nv -aes >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "nv policy nv aes failed! $RESULT" && exit 1


# CSR Tests
./examples/keygen/keygen rsa_test_blob.raw -rsa -t >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen rsa test for csr failed! $RESULT" && exit 1
./examples/keygen/keygen ecc_test_blob.raw -ecc -t >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "keygen ecc test for csr failed! $RESULT" && exit 1

if [ $WOLFCRYPT_ENABLE -eq 1 ] && [ $WOLFCRYPT_DEFAULT -eq 0 ] && [ $NO_FILESYSTEM -eq 0 ]; then
    ./examples/csr/csr -cert >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "cert self-signed failed! $RESULT" && exit 1

    cp ./certs/tpm-rsa-cert.pem $WOLFSSL_PATH/certs/tpm-rsa-cert.pem >> $TPMPWD/run.out 2>&1
    cp ./certs/tpm-ecc-cert.pem $WOLFSSL_PATH/certs/tpm-ecc-cert.pem >> $TPMPWD/run.out 2>&1

    ./examples/csr/csr >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "csr gen failed! $RESULT" && exit 1

    ./certs/certreq.sh 2>&1 >> $TPMPWD/run.out 2>&1
    cp ./certs/ca-ecc-cert.pem $WOLFSSL_PATH/certs/tpm-ca-ecc-cert.pem >> $TPMPWD/run.out 2>&1
    cp ./certs/ca-rsa-cert.pem $WOLFSSL_PATH/certs/tpm-ca-rsa-cert.pem >> $TPMPWD/run.out 2>&1
fi

# PKCS7 Tests
echo -e "PKCS7 tests"
if [ $WOLFCRYPT_ENABLE -eq 1 ] && [ $WOLFCRYPT_DEFAULT -eq 0 ] && [ $NO_FILESYSTEM -eq 0 ] && [ $NO_PUBASPRIV -eq 0 ]; then
    ./examples/pkcs7/pkcs7 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pkcs7 failed! $RESULT" && exit 1

    ./examples/pkcs7/pkcs7 -ecc >> $TPMPWD/run.out 2>&1
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
    echo -e "Using port $port" >> $TPMPWD/run.out 2>&1
}

run_tpm_tls_client() { # Usage: run_tpm_tls_client [ecc/rsa] [tpmargs] [tlsversion]
    echo -e "TLS test (TPM as client) $1 $2 $3"
    generate_port
    pushd $WOLFSSL_PATH >> $TPMPWD/run.out 2>&1
    echo -e "./examples/server/server -v $3 -p $port -w -g -A ./certs/tpm-ca-$1-cert.pem"
    ./examples/server/server -p $port -w -g -A ./certs/tpm-ca-$1-cert.pem >> $TPMPWD/run.out 2>&1 &
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tls server $1 $2 failed! $RESULT" && exit 1
    popd >> $TPMPWD/run.out 2>&1
    sleep 0.1

    echo -e "./examples/tls/tls_client -p=$port -$1 $2"
    ./examples/tls/tls_client -p=$port -$1 $2 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tpm tls client $1 $2 failed! $RESULT" && exit 1
}

run_tpm_tls_server() { # Usage: run_tpm_tls_server [ecc/rsa] [tpmargs] [tlsversion]
    echo -e "TLS test (TPM as server) $1 $2 $3"
    generate_port

    echo -e "./examples/tls/tls_server -p=$port -$1 $2"
    ./examples/tls/tls_server -p=$port -$1 $2 >> $TPMPWD/run.out 2>&1 &
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tpm tls server $1 $2 failed! $RESULT" && exit 1
    pushd $WOLFSSL_PATH >> $TPMPWD/run.out 2>&1
    sleep 0.1

    echo -e "./examples/client/client -v $3 -p $port -w -g -A ./certs/tpm-ca-$1-cert.pem"
    ./examples/client/client -p $port -w -g -A ./certs/tpm-ca-$1-cert.pem >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "tls client $1 $2 failed! $RESULT" && exit 1
    popd >> $TPMPWD/run.out 2>&1
}

if [ $WOLFCRYPT_ENABLE -eq 1 ] && [ $WOLFCRYPT_DEFAULT -eq 0 ] && [ $NO_FILESYSTEM -eq 0 ]; then
    if [ $WOLFCRYPT_RSA -eq 1 ]; then
        # TLS client/server RSA TLS v1.2 and v1.3 Crypto callbacks
        run_tpm_tls_client "rsa" "" "3"
        run_tpm_tls_client "rsa" "-aes" "3"
        run_tpm_tls_client "rsa" "" "4"
        run_tpm_tls_client "rsa" "-aes" "4"

        if [ $NO_PUBASPRIV -eq 0 ]; then
            run_tpm_tls_server "rsa" "" "3"
            run_tpm_tls_server "rsa" "-aes" "3"
            run_tpm_tls_server "rsa" "" "4"
            run_tpm_tls_server "rsa" "-aes" "4"
        fi

        # TLS client/server ECC TLS v1.2 and v1.3 PK callbacks
        run_tpm_tls_client "rsa" "-pk" "3"
        run_tpm_tls_client "rsa" "-pk -aes" "3"
        run_tpm_tls_client "rsa" "-pk" "4"
        run_tpm_tls_client "rsa" "-pk -aes" "4"

        if [ $NO_PUBASPRIV -eq 0 ]; then
            run_tpm_tls_server "rsa" "-pk " "3"
            run_tpm_tls_server "rsa" "-pk -aes" "3"
            run_tpm_tls_server "rsa" "-pk " "4"
            run_tpm_tls_server "rsa" "-pk -aes" "4"
        fi
    fi
    if [ $WOLFCRYPT_ECC -eq 1 ]; then
        # TLS client/server ECC TLS v1.2 and v1.3 Crypto callbacks
        run_tpm_tls_client "ecc" "" "3"
        run_tpm_tls_client "ecc" "-aes" "3"
        run_tpm_tls_client "ecc" "" "4"
        run_tpm_tls_client "ecc" "-aes" "4"

        if [ $NO_PUBASPRIV -eq 0 ]; then
            run_tpm_tls_server "ecc" "" "3"
            run_tpm_tls_server "ecc" "-aes" "3"
            run_tpm_tls_server "ecc" "" "4"
            run_tpm_tls_server "ecc" "-aes" "4"
        fi

        # TLS client/server ECC TLS v1.2 and v1.3 PK callbacks
        run_tpm_tls_client "ecc" "-pk" "3"
        run_tpm_tls_client "ecc" "-pk -aes" "3"
        run_tpm_tls_client "ecc" "-pk" "4"
        run_tpm_tls_client "ecc" "-pk -aes" "4"

        if [ $NO_PUBASPRIV -eq 0 ]; then
            run_tpm_tls_server "ecc" "-pk" "3"
            run_tpm_tls_server "ecc" "-pk -aes" "3"
            run_tpm_tls_server "ecc" "-pk" "4"
            run_tpm_tls_server "ecc" "-pk -aes" "4"
        fi
    fi
fi


# Clock Tests
echo -e "Clock tests"
./examples/timestamp/clock_set >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "clock set failed! $RESULT" && exit 1


# Attestation tests
echo -e "Attestation tests"
./examples/timestamp/signed_timestamp >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "signed_timestamp failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/timestamp/signed_timestamp -aes >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "signed_timestamp param enc failed! $RESULT" && exit 1
fi
./examples/timestamp/signed_timestamp -ecc >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "signed_timestamp ecc failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/timestamp/signed_timestamp -ecc -aes >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "signed_timestamp ecc param enc failed! $RESULT" && exit 1
fi

if [ $WOLFCRYPT_ENABLE -eq 1 ] && [ $NO_FILESYSTEM -eq 0 ]; then
    rm -f keyblob.bin

    # Endorsement hierarchy (assumes keyblob.bin for key)
    ./examples/keygen/keygen keyblob.bin -rsa -eh >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen rsa endorsement failed! $RESULT" && exit 1
    ./examples/attestation/make_credential -eh >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "make_credential endorsement failed! $RESULT" && exit 1
    ./examples/attestation/activate_credential -eh >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "activate_credential endorsement failed! $RESULT" && exit 1

    ./examples/keygen/keygen keyblob.bin -rsa >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "keygen rsa failed! $RESULT" && exit 1
    ./examples/attestation/make_credential >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "make_credential failed! $RESULT" && exit 1
    ./examples/attestation/activate_credential >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "activate_credential failed! $RESULT" && exit 1

    rm -f cred.blob
    rm -f ek.pub
    rm -f srk.pub
    rm -f ak.name
    # Keeping keyblob.bin for tests later
fi

# PCR Quote Tests
echo -e "PCR Quote tests"
./examples/pcr/reset 16 >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr reset failed! $RESULT" && exit 1
./examples/pcr/extend 16 /usr/bin/zip >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr extend file failed! $RESULT" && exit 1
./examples/pcr/quote 16 zip.quote >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr quote failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/pcr/quote 16 zip.quote -xor >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr quote param enc xor failed! $RESULT" && exit 1

    if [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
        ./examples/pcr/quote 16 zip.quote -aes >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "pcr quote param enc aes failed! $RESULT" && exit 1
    fi
fi
./examples/pcr/quote 16 zip.quote -ecc >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "pcr quote ecc failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/pcr/quote 16 zip.quote -ecc -xor >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr quote ecc param enc xor failed! $RESULT" && exit 1

    if [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
        ./examples/pcr/quote 16 zip.quote -ecc -aes >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "pcr quote ecc param enc aes failed! $RESULT" && exit 1
    fi
fi
rm -f zip.quote


# Benchmark tests
echo -e "Benchmark tests"
./examples/bench/bench -maxdur=25 >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "bench failed! $RESULT" && exit 1
if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
    ./examples/bench/bench -maxdur=25 -xor >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "bench (XOR param enc) failed! $RESULT" && exit 1

    if [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
        ./examples/bench/bench -maxdur=25 -aes >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "bench (AES param enc) failed! $RESULT" && exit 1
    fi
fi

# Secure Boot ROT
echo -e "Secure Boot ROT (Root of Trust) test"
if [ $WOLFCRYPT_ENABLE -eq 1 ] && [ $WOLFCRYPT_DEFAULT -eq 0 ] && [ $NO_FILESYSTEM -eq 0 ]; then
    ./examples/boot/secure_rot -nvindex=0x1400200 -authstr=test -write=./certs/example-ecc256-key-pub.der >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc256! $RESULT" && exit 1
    ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test -write=./certs/example-ecc384-key-pub.der -sha384 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384! $RESULT" && exit 1
    ./examples/boot/secure_rot -nvindex=0x1400202 -authstr=test -write=./certs/example-rsa2048-key-pub.der >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write rsa2048! $RESULT" && exit 1
    ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test -sha384 -hash=e77dd3112a27948a3f2d87f32dc69ebeed0b3344c5d7726f5742f4f0c0f451aabe4213f8b3b986639e69ed0ea8b49d94 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384 again! $RESULT" && exit 1

    if test $ENABLE_DESTRUCTIVE_TESTS -eq 1
    then
        ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test -lock >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384 lock! $RESULT" && exit 1
        # Test expected failure case
        ./examples/boot/secure_rot -nvindex=0x1400201 -write=./certs/example-ecc384-key-pub.der -sha384 >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -eq 0 ] && echo -e "secure rot write ecc384 should be locked! $RESULT" && exit 1
    fi

    ./examples/boot/secure_rot -nvindex=0x1400201 -authstr=test >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secure rot write ecc384 read! $RESULT" && exit 1

    # Test expected failure case
    ./examples/boot/secure_rot -nvindex=0x1400201 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -eq 0 ] && echo -e "secure rot write ecc384 read no auth! $RESULT" && exit 1
fi

# Seal/Unseal (PCR Policy)
if [ $NO_FILESYSTEM -eq 0 ]; then
    echo -e "Seal/Unseal (PCR policy)"
    ./examples/seal/seal sealedkeyblob.bin mySecretMessage >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "seal failed! $RESULT" && exit 1
    ./examples/seal/unseal message.raw sealedkeyblob.bin >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "unseal failed! $RESULT" && exit 1
    rm -f sealedkeyblob.bin

    if [ $WOLFCRYPT_ENABLE -eq 1 ] && [ $WOLFCRYPT_RSA -eq 1 ]; then
        ./examples/seal/seal sealedkeyblob.bin mySecretMessage -xor >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "seal xor failed! $RESULT" && exit 1
        ./examples/seal/unseal message.raw sealedkeyblob.bin -xor >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "unseal xor failed! $RESULT" && exit 1

        if [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
            ./examples/seal/seal sealedkeyblob.bin mySecretMessage -aes >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "seal aes failed! $RESULT" && exit 1
            ./examples/seal/unseal message.raw sealedkeyblob.bin -aes >> $TPMPWD/run.out 2>&1
            RESULT=$?
            [ $RESULT -ne 0 ] && echo -e "unseal aes failed! $RESULT" && exit 1
        fi
        rm -f sealedkeyblob.bin
    fi
fi

run_tpm_policy() { # Usage: run_tpm_policy [ecc/rsa] [key] [pcrs]
    echo -e "TPM Seal/Unseal (Policy Auth) test $1 $2 $3"

    # Test Seal/Unseal (Policy auth)
    ./examples/pcr/policy_sign $3 -$1 -key=$2.der -out=pcrsig.bin -outpolicy=policyauth.bin >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign $1 der failed! $RESULT" && exit 1
    ./examples/pcr/policy_sign $3 -$1 -key=$2.pem -out=pcrsig.bin -outpolicy=policyauth.bin >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "policy sign $1 pem failed! $RESULT" && exit 1

    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -$1 -policy=policyauth.bin -out=sealblob.bin -secretstr=$SECRET_STRING >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal $1 failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal $3 -pcrsig=pcrsig.bin -$1 -publickey=$2-pub.der -seal=sealblob.bin &> $TMPFILE
    RESULT=$?
    cat $TMPFILE >> $TPMPWD/run.out
    [ $RESULT -ne 0 ] && echo -e "secret unseal $1 failed! $RESULT" && exit 1
    grep "$SECRET_STRING" $TMPFILE >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret unseal $1 match failed! $RESULT" && exit 1

    # Recreate policy auth using public key instead of using policyauth.bin
    TMPFILE=$(mktemp)
    SECRET_STRING=`head -c 32 /dev/random | base64`
    ./examples/boot/secret_seal -$1 -publickey=$2-pub.der -out=sealblob.bin -secretstr=$SECRET_STRING >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "secret seal $1 alt failed! $RESULT" && exit 1
    ./examples/boot/secret_unseal $3 -pcrsig=pcrsig.bin -$1 -publickey=$2-pub.der -seal=sealblob.bin &> $TMPFILE
    RESULT=$?
    cat $TMPFILE >> $TPMPWD/run.out
    [ $RESULT -ne 0 ] && echo -e "secret unseal $1 alt failed! $RESULT" && exit 1
    grep "$SECRET_STRING" $TMPFILE >> $TPMPWD/run.out 2>&1
    RESULT=$?
    rm -f $TMPFILE
    [ $RESULT -ne 0 ] && echo -e "secret unseal $1 alt match failed! $RESULT" && exit 1
}

# Seal/Unseal (Policy auth)
echo -e "Seal/Unseal (Policy auth)"
if [ $WOLFCRYPT_ENABLE -eq 1 ] && [ $WOLFCRYPT_DEFAULT -eq 0 ] && [ $NO_FILESYSTEM -eq 0 ]; then
    # Extend "aaa" to test PCR 16
    echo aaa > aaa.bin
    echo bbb > bbb.bin
    ./examples/pcr/reset 16 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr 16 reset failed! $RESULT" && exit 1
    ./examples/pcr/extend 16 aaa.bin >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr 16 extend failed! $RESULT" && exit 1

    ./examples/pcr/reset 23 >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr 23 reset failed! $RESULT" && exit 1
    ./examples/pcr/extend 23 bbb.bin >> $TPMPWD/run.out 2>&1
    RESULT=$?
    [ $RESULT -ne 0 ] && echo -e "pcr 23 extend failed! $RESULT" && exit 1

    if [ $WOLFCRYPT_RSA -eq 1 ]; then
        # RSA
        run_tpm_policy "rsa" "./certs/example-rsa2048-key" "-pcr=16"
        run_tpm_policy "rsa" "./certs/example-rsa2048-key" "-pcr=23 -pcr=16"

        # Test RSA Unseal Expected Failure Case
        # Create different ECC policy key to test failure case
        openssl genrsa -out tmp-rsa2048-key.pem 2048 >> $TPMPWD/run.out 2>&1
        openssl rsa -in tmp-rsa2048-key.pem -outform der -out tmp-rsa2048-key-pub.der -pubout >> $TPMPWD/run.out 2>&1

        # Sign policy using different private key
        ./examples/pcr/policy_sign -pcr=16 -rsa -key=tmp-rsa2048-key.pem -out=pcrsig_fail.bin -outpolicy=policyauth.bin >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "policy sign (expected failure case) rsa pem failed! $RESULT" && exit 1

        # This RSA unseal should fail!
        ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig_fail.bin -rsa -publickey=tmp-rsa2048-key-pub.der -seal=sealblob.bin >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -eq 0 ] && echo -e "secret unseal rsa should have failed! $RESULT" && exit 1


        rm -f tmp-rsa2048-key.pem
        rm -f tmp-rsa2048-key-pub.der
        rm -f pcrsig_fail.bin
    fi

    if [ $WOLFCRYPT_ECC -eq 1 ]; then
        # ECC
        run_tpm_policy "ecc" "./certs/example-ecc256-key" "-pcr=16"
        run_tpm_policy "ecc" "./certs/example-ecc256-key" "-pcr=23 -pcr=16"

        # Test ECC Unseal Expected Failure Case
        # Create different ECC policy key to test failure case
        openssl ecparam -name prime256v1 -genkey -noout -out tmp-ecc256-key.pem >> $TPMPWD/run.out 2>&1
        openssl ec -in tmp-ecc256-key.pem -outform der -out tmp-ecc256-key-pub.der -pubout >> $TPMPWD/run.out 2>&1

        # Sign policy using different private key
        ./examples/pcr/policy_sign -pcr=16 -ecc -key=tmp-ecc256-key.pem -out=pcrsig_fail.bin -outpolicy=policyauth.bin >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -ne 0 ] && echo -e "policy sign (expected failure case) ecc pem failed! $RESULT" && exit 1

        # This ECC unseal should fail!
        ./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig_fail.bin -ecc -publickey=tmp-ecc256-key-pub.der -seal=sealblob.bin >> $TPMPWD/run.out 2>&1
        RESULT=$?
        [ $RESULT -eq 0 ] && echo -e "secret unseal ecc should have failed! $RESULT" && exit 1

        rm -f tmp-ecc256-key.pem
        rm -f tmp-ecc256-key-pub.der
        rm -f pcrsig_fail.bin
    fi

    rm -f pcrsig.bin
    rm -f policyauth.bin
    rm -f sealblob.bin
    rm -f aaa.bin
    rm -f bbb.bin
fi

# Endorsement key and certificate
echo -e "Endorsement Key (EK) and Certificate"
./examples/endorsement/get_ek_certs >> $TPMPWD/run.out 2>&1
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "get_ek_certs failed! $RESULT" && exit 1


rm -f keyblob.bin

echo -e "Success!"
exit 0
