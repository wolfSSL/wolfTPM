#include <wolftpm/tpm2.h>

void* TPM2_IoGetUserCtx(void){
 return NULL;
}

int   TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
word16 xferSz, void* userCtx){
	(void) ctx;
	(void) txBuf;
	(void) rxBuf;
	(void)xferSz;
	(void)userCtx;
	return 0;
}
	