/* Example wolfTPM options.h for U-boot compilation */

#ifndef WOLFTPM_OPTIONS_H
#define WOLFTPM_OPTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#undef  __UBOOT__
#define __UBOOT__

#undef  SIZEOF_LONG
#define SIZEOF_LONG 8

#undef  WOLFTPM2_NO_WOLFCRYPT
#define WOLFTPM2_NO_WOLFCRYPT

#undef  WOLFTPM_AUTODETECT
#define WOLFTPM_AUTODETECT

#ifdef __cplusplus
}
#endif

#endif /* WOLFMTPM_OPTIONS_H */

