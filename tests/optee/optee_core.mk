# Builds optee_core_tests: the fwTPM OP-TEE port and the real fwTPM core,
# with wolfCrypt compiled from source as WOLFSSL_OPTEE, all on the host
# against the mock TEE. Needs a wolfSSL source tree with WOLFSSL_OPTEE
# support. Run from the wolfTPM root:
#
#   make -f tests/optee/optee_core.mk WOLFSSL=../wolfssl check

WOLFSSL ?= ../wolfssl
WOLFTPM ?= .
OUT     ?= tests/optee/optee_core.test

CC      ?= gcc
CFLAGS  ?= -O1 -g
WARN    = -Wall -Wextra -Wno-unused-parameter
CPPFLAGS += -DWOLFSSL_USER_SETTINGS -DWOLFTPM_USER_SETTINGS -DWOLFSSL_OPTEE
CPPFLAGS += -I$(WOLFTPM)/tests/optee -I$(WOLFTPM) -I$(WOLFSSL)

WC_SRCS = aes.c asn.c coding.c cpuid.c ecc.c error.c hash.c hmac.c kdf.c \
	logging.c memory.c random.c rsa.c sha.c sha256.c sha512.c sp_int.c \
	wc_encrypt.c wc_port.c wolfmath.c

TPM_SRCS = src/fwtpm/fwtpm.c src/fwtpm/fwtpm_command.c \
	src/fwtpm/fwtpm_crypto.c src/fwtpm/fwtpm_nv.c \
	src/fwtpm/ports/optee/fwtpm_optee_ta.c \
	src/fwtpm/ports/optee/fwtpm_optee_nv.c \
	src/tpm2_util.c src/tpm2_packet.c src/tpm2_crypto.c src/tpm2_param_enc.c \
	tests/optee/optee_core_tests.c tests/optee/mock_tee.c

SRCS = $(addprefix $(WOLFSSL)/wolfcrypt/src/,$(WC_SRCS)) \
	$(addprefix $(WOLFTPM)/,$(TPM_SRCS))

all: $(OUT)

$(OUT): $(SRCS) $(WOLFTPM)/tests/optee/user_settings.h \
		$(WOLFTPM)/tests/optee/optee_core.mk
	$(CC) $(WARN) $(CFLAGS) $(CPPFLAGS) -o $@ $(SRCS) $(LDFLAGS)

check: $(OUT)
	./$(OUT)

clean:
	rm -f $(OUT)

.PHONY: all check clean
