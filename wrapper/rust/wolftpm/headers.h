/* bindgen shim: the single translation unit fed to bindgen.
 * tpm2_wrap.h pulls in tpm2.h -> tpm2_types.h, which is the type-heavy header. */
#include <wolftpm/options.h>
#include <wolftpm/tpm2_wrap.h>
