#include <string.h>

#include "tpm_main.h"

int main()
{
	int ret;

	//---------------------------------------------------------------------------
	// TPM Example
	ret = TPM2_Cust_Example(NULL);

	return ret;
}
