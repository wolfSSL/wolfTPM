# wolftpm
# Copyright (C) 2021 wolfSSL Inc.
# All right reserved.

AC_COPYRIGHT([Copyright (C) 2014-2021 wolfSSL Inc.])
AC_INIT([wolftpm],[3.1.0],[https://github.com/wolfssl/wolfTPM/issues],[wolftpm],[http://www.wolfssl.com])

AC_PREREQ([2.63])
AC_CONFIG_AUX_DIR([build-aux])

# The following sets CFLAGS to empty if unset on command line.
: ${CFLAGS=""}

# Test ar for the "U" option. Should be checked before the libtool macros.
xxx_ar_flags=$((ar --help) 2>&1)
AS_CASE([$xxx_ar_flags],[*'use actual timestamps and uids/gids'*],[: ${AR_FLAGS="Ucru"}])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 -Wall -Werror -Wno-portability foreign tar-ustar subdir-objects no-define color-tests])

AC_ARG_PROGRAM

AC_CONFIG_HEADERS([src/config.h])

WOLFTPM_LIBRARY_VERSION=16:1:0
#                        | | |
#                 +------+ | +---+
#                 |        |     |
#                current:revision:age
#                 |        |     |
#                 |        |     +- increment if interfaces have been added
#                 |        |        set to zero if interfaces have been removed
#                 |        |        or changed
#                 |        +- increment if source code has changed
#                 |           set to zero if current is incremented
#                 +- increment if interfaces have been added, removed or changed
AC_SUBST([WOLFTPM_LIBRARY_VERSION])


LT_PREREQ([2.2])
LT_INIT([disable-static], [win32-dll])
LT_LANG([C])

gl_VISIBILITY
AS_IF([test -n "$CFLAG_VISIBILITY"],
      [AM_CPPFLAGS="$AM_CPPFLAGS $CFLAG_VISIBILITY"
       CPPFLAGS="$CPPFLAGS $CFLAG_VISIBILITY"])

# silent
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for header files.
AC_CHECK_SIZEOF([long long], 8)
AC_CHECK_SIZEOF([long], 4)

# Check headers/libs
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_FUNCS([gethostbyname getaddrinfo gettimeofday inet_ntoa memset socket])
AC_CHECK_LIB([network],[socket])

# Thread local storage
AX_TLS([thread_ls_on=yes],[thread_ls_on=no])
AS_IF([test "x$thread_ls_on" = "xyes"],[AM_CFLAGS="$AM_CFLAGS -DHAVE_THREAD_LS"])

# DEBUG
DEBUG_CFLAGS="-g -O0 -DDEBUG_WOLFTPM"

# Optimizations
OPTIMIZE_CFLAGS="-O2"

AX_DEBUG
AS_IF([test "x$ax_enable_debug" != "xno"],
      [AM_CFLAGS="$DEBUG_CFLAGS $AM_CFLAGS -DDEBUG"],
      [AM_CFLAGS="$AM_CFLAGS $OPTIMIZE_CFLAGS -DNDEBUG"])


AX_PTHREAD([
    # If AX_PTHREAD is adding -Qunused-arguments, need to prepend with
    # -Xcompiler libtool will use it. Newer versions of clang don't need
    # the -Q flag when using pthreads.
    AS_CASE([$PTHREAD_CFLAGS],[-Qunused-arguments*],[PTHREAD_CFLAGS="-Xcompiler $PTHREAD_CFLAGS"])
    AM_CFLAGS="$AM_CFLAGS $PTHREAD_CFLAGS -DHAVE_PTHREAD"])


# Checks for typedefs, structures, and compiler characteristics.
if test "$ac_cv_sizeof_long" = "8"; then
   AM_CFLAGS="$AM_CFLAGS -DSIZEOF_LONG=8"
else
    if test "$ac_cv_sizeof_long_long" = "8"; then
        AM_CFLAGS="$AM_CFLAGS -DSIZEOF_LONG_LONG=8"
    fi
fi

# Verbose Logging
if test "x$ax_enable_debug" = "xverbose" || test "x$ax_enable_debug" = "xio"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_DEBUG_VERBOSE"
fi
# IO Logging
if test "x$ax_enable_debug" = "xio"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_DEBUG_IO"
fi


# Examples
AC_ARG_ENABLE([examples],
    [AS_HELP_STRING([--enable-examples],[Enable Examples (default: enabled)])],
    [ ENABLED_EXAMPLES=$enableval ],
    [ ENABLED_EXAMPLES=yes ]
    )


# Wrapper
AC_ARG_ENABLE([wrapper],
    [AS_HELP_STRING([--enable-wrapper],[Enable wrapper code (default: enabled)])],
    [ ENABLED_WRAPPER=$enableval ],
    [ ENABLED_WRAPPER=yes ]
    )

if test "$ENABLED_WRAPPER" = "no"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM2_NO_WRAPPER"
fi


# wolfSSL/wolfCrypt
AC_MSG_CHECKING([for wolfSSL/wolfCrypt
])
if test "x$prefix" = "xNONE"
then
    wcpath=$ac_default_prefix
else
    wcpath=$prefix
fi
AC_MSG_NOTICE([prefix ${prefix}])
WOLFSSL_URL="http://www.wolfssl.com/download.html"
AC_ARG_WITH(wolfcrypt,
  [AS_HELP_STRING([--with-wolfcrypt=PATH], [PATH to wolfssl install (default /usr/local)])],
  [
    if test "x$withval" != "xno" ; then
      if test -d "${withval}/lib" && test -d "${withval}/include"; then
        wcpath=${withval}
      else
        AC_MSG_ERROR([wolfCrypt path error (${withval}): missing lib and include])
      fi
    fi
  ]
)

AC_ARG_ENABLE([wolfcrypt],
    [AS_HELP_STRING([--enable-wolfcrypt],[Enable wolfCrypt hooks for RNG, Auth Sessions and Parameter encryption (default: enabled)])],
    [ ENABLED_WOLFCRYPT=$enableval ],
    [ ENABLED_WOLFCRYPT=yes ]
    )

if test "x$ENABLED_WOLFCRYPT" = "xyes"
then
    LIBS="$LIBS -lwolfssl"
    LDFLAGS="$LDFLAGS -L${wcpath}/lib"
    CPPFLAGS="$CPPFLAGS -I${wcpath}/include"

    AC_CHECK_LIB([wolfssl],[wolfCrypt_Init],,
        [AC_MSG_ERROR([WolfSSL library not found. You can get it from $WOLFSSL_URL
        If its already installed, specify its path using --with-wolfcrypt=/dir or --prefix=/dir])])
else
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM2_NO_WOLFCRYPT"
fi
AC_MSG_NOTICE([wolfCrypt path: ${wcpath}])


# I2C Support
AC_ARG_ENABLE([i2c],
    [AS_HELP_STRING([--enable-i2c],[Enable I2C TPM Support (default: disabled)])],
    [ ENABLED_I2C=$enableval ],
    [ ENABLED_I2C=no ]
    )

if test "x$ENABLED_I2C" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_I2C"
fi

# Memory-mapped I/O
AC_ARG_ENABLE([mmio],
    [AS_HELP_STRING([--enable-mmio],[Enable built-in MMIO callbacks (default: disabled)])],
    [ ENABLED_MMIO=$enableval ],
    [ ENABLED_MMIO=no ]
    )

if test "x$ENABLED_MMIO" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_MMIO"
fi

# Advanced IO
AC_ARG_ENABLE([advio],
    [AS_HELP_STRING([--enable-advio],[Enable Advanced IO (default: disabled)])],
    [ ENABLED_ADVIO=$enableval ],
    [ ENABLED_ADVIO=no ]
    )

if test "x$ENABLED_ADVIO" = "xyes" || test "x$ENABLED_I2C" = "xyes" || test "x$ENABLED_MMIO" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_ADV_IO"
fi


# Linux kernel TPM device Support
AC_ARG_ENABLE([devtpm],
    [AS_HELP_STRING([--enable-devtpm],[Enable use of TPM through the Linux kernel driver (default: disabled)])],
    [ ENABLED_DEVTPM=$enableval ],
    [ ENABLED_DEVTPM=no ]
    )

if test "x$ENABLED_DEVTPM" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_LINUX_DEV"
fi

# SW TPM device Support
AC_ARG_ENABLE([swtpm],
    [AS_HELP_STRING([--enable-swtpm],[Enable use of TPM through the SW socket driver (default: disabled)])],
    [ ENABLED_SWTPM=$enableval ],
    [ ENABLED_SWTPM=no ]
    )

if test "x$ENABLED_SWTPM" = "xyes"
then
    if test "x$ENABLED_DEVTPM" = "xyes"
    then
        AC_MSG_ERROR([Cannot enable both swtpm and devtpm])
    fi

    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_SWTPM"
fi

# Windows TBS device Support
AC_ARG_ENABLE([wintbs],,
    [ ENABLED_WINTBS=$enableval ],
    [ ENABLED_WINTBS=no ]
    )
AC_ARG_ENABLE([winapi],
    [AS_HELP_STRING([--enable-winapi],[Enable use of TPM through Windows driver (default: disabled)])],
    [ ENABLED_WINAPI=$enableval ],
    [ ENABLED_WINAPI=no ]
    )

if test "x$ENABLED_WINAPI" = "xyes" || test "x$ENABLED_WINTBS" = "xyes"
then
    if test "x$ENABLED_DEVTPM" = "xyes" -o "x$ENABLED_SWTPM" = "xyes"
    then
        AC_MSG_ERROR([Cannot enable swtpm or devtpm with windows API])
    fi

    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_WINAPI"
fi


# STM ST33 Support
AC_ARG_ENABLE([st33],,
    [ ENABLED_ST33=$enableval ],
    [ ENABLED_ST33=no ]
    )
AC_ARG_ENABLE([st],
    [AS_HELP_STRING([--enable-st],[Enable ST ST33 TPM Support (default: disabled)])],
    [ ENABLED_ST=$enableval ],
    [ ENABLED_ST=no ]
    )

if test "x$ENABLED_ST33" = "xyes" || test "x$ENABLED_ST" = "xyes"
then
    ENABLED_ST33=yes
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_ST33"
fi

# Microchip ATTPM20
AC_ARG_ENABLE([mchp],,
    [ ENABLED_MCHP=$enableval ],
    [ ENABLED_MCHP=no ]
    )
AC_ARG_ENABLE([microchip],
    [AS_HELP_STRING([--enable-microchip],[Enable Microchip ATPM2.0 Support (default: disabled)])],
    [ ENABLED_MICROCHIP=$enableval ],
    [ ENABLED_MICROCHIP=no ]
    )
if test "x$ENABLED_MCHP" = "xyes" || test "x$ENABLED_MICROCHIP" = "xyes"
then
    ENABLED_MICROCHIP=yes
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_MICROCHIP"
fi

# Nuvoton NPCT65x/NPCT75x
AC_ARG_ENABLE([nuvoton],
    [AS_HELP_STRING([--enable-nuvoton],[Enable Nuvoton NPCT65x/NPCT75x TPM Support (default: disabled)])],
    [ ENABLED_NUVOTON=$enableval ],
    [ ENABLED_NUVOTON=no ]
    )
if test "x$ENABLED_NUVOTON" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_NUVOTON"
fi

# Infineon SLB9670/SLB9672
AC_ARG_ENABLE([infineon],
    [AS_HELP_STRING([--enable-infineon],[Enable Infineon SLB9670/SLB9672 TPM Support (default: disabled)])],
    [ ENABLED_INFINEON=$enableval ],
    [ ENABLED_INFINEON=no ]
    )
if test "x$ENABLED_INFINEON" != "xno"
then
    if test "x$ENABLED_INFINEON" = "xslb9670"
    then
        AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_SLB9670"
    else
        AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_SLB9672"
    fi
fi


# TIS / SPI Check Wait State support
AC_ARG_ENABLE([checkwaitstate],
    [AS_HELP_STRING([--enable-checkwaitstate],[Enable TIS / SPI Check Wait State support (default: depends on chip)])],
    [ ENABLED_CHECKWAITSTATE=$enableval ],
    [ ENABLED_CHECKWAITSTATE=no ]
    )


# TIS Layer Named Semaphore locking for concurrent access between processes.
AC_ARG_ENABLE([tislock],
    [AS_HELP_STRING([--enable-tislock],[TIS Layer Named Semaphore locking for concurrent access between processes. (default: disabled)])],
    [ ENABLED_TIS_LOCK=$enableval ],
    [ ENABLED_TIS_LOCK=no ]
    )
if test "x$ENABLED_TIS_LOCK" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_TIS_LOCK"
fi

# Small Stack
AC_ARG_ENABLE([smallstack],
    [AS_HELP_STRING([--enable-smallstack],[Enable Small Stack Usage (default: disabled)])],
    [ ENABLED_SMALL_STACK=$enableval ],
    [ ENABLED_SMALL_STACK=no ]
    )

if test "x$ENABLED_SMALL_STACK" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_SMALL_STACK"

    # Reduces max packet and buffer sizes to 1024 bytes
    # RSA KeyGen AES response is 1329 MAX_RESPONSE_SIZE
    AM_CFLAGS="$AM_CFLAGS -DMAX_COMMAND_SIZE=1024 -DMAX_RESPONSE_SIZE=1350 -DWOLFTPM2_MAX_BUFFER=1500 -DMAX_DIGEST_BUFFER=973"

    # If parameter encryption is not used then maximum session count is one
    if test "x$ENABLED_WOLFCRYPT" = "xno"
    then
        AM_CFLAGS="$AM_CFLAGS -DMAX_SESSION_NUM=1"
    fi
fi

# Runtime Module Detection
AC_ARG_ENABLE([autodetect],
    [AS_HELP_STRING([--enable-autodetect],[Enable Runtime Module Detection (default: enable - when no module specified)])],
    [ ENABLED_AUTODETECT=$enableval ],
    [ ENABLED_AUTODETECT=test ]
    )

if test "x$ENABLED_AUTODETECT" = "xtest"
then
    # If a module hasn't been selected then enable auto-detection
    if test "x$ENABLED_INFINEON" = "xno" && test "x$ENABLED_MCHP" = "xno" && test "x$ENABLED_ST33" = "xno" && test "x$ENABLED_NUVOTON" = "xno"
    then
        ENABLED_AUTODETECT=yes
    fi
fi

if test "x$ENABLED_AUTODETECT" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_AUTODETECT"
fi


# Example HAL implementations
AC_ARG_ENABLE([hal],
    [AS_HELP_STRING([--enable-hal],[Enable example HAL interfaces (default: enabled)])],
    [ ENABLED_EXAMPLE_HAL=$enableval ],
    [ ENABLED_EXAMPLE_HAL=yes ]
    )
if test "x$ENABLED_EXAMPLE_HAL" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_EXAMPLE_HAL"
fi


# TIS / SPI Check Wait State support
# Required for all but Infineon only
if test "x$ENABLED_CHECKWAITSTATE" = "xyes" || test "x$ENABLED_AUTODETECT" = "xyes" || test "x$ENABLED_INFINEON" = "xno"
then
    ENABLED_CHECKWAITSTATE=yes
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_CHECK_WAIT_STATE"
fi


# Built-in TPM firmware upgrade support
AC_ARG_ENABLE([firmware],
    [AS_HELP_STRING([--enable-firmware],[Enable support for TPM firmware upgrades (default: enabled)])],
    [ ENABLED_FIRMWARE=$enableval ],
    [ ENABLED_FIRMWARE=yes ]
    )
if test "x$ENABLED_FIRMWARE" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_FIRMWARE_UPGRADE"
fi


# HARDEN FLAGS
AX_HARDEN_CC_COMPILER_FLAGS

OPTION_FLAGS="$CFLAGS $CPPFLAGS $AM_CFLAGS"



# The following AM_CONDITIONAL statements set flags for use in the Makefiles.
AM_CONDITIONAL([HAVE_LIBWOLFSSL], [test "x$ENABLED_WOLFCRYPT" = "xyes"])
AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$ENABLED_EXAMPLES" = "xyes"])
AM_CONDITIONAL([BUILD_WRAPPER], [test "x$ENABLED_WRAPPER" = "xyes"])
AM_CONDITIONAL([HAVE_LIBWOLFSSL], [test "x$ENABLED_WOLFCRYPT" = "xyes"])
AM_CONDITIONAL([BUILD_I2C], [test "x$ENABLED_I2C" = "xyes"])
AM_CONDITIONAL([BUILD_ADVIO], [test "x$ENABLED_ADVIO" = "xyes"])
AM_CONDITIONAL([BUILD_ST], [test "x$ENABLED_ST" = "xyes"])
AM_CONDITIONAL([BUILD_MICROCHIP], [test "x$ENABLED_MICROCHIP" = "xyes"])
AM_CONDITIONAL([BUILD_INFINEON], [test "x$ENABLED_INFINEON" != "xno"])
AM_CONDITIONAL([BUILD_DEVTPM], [test "x$ENABLED_DEVTPM" = "xyes"])
AM_CONDITIONAL([BUILD_SWTPM], [test "x$ENABLED_SWTPM" = "xyes"])
AM_CONDITIONAL([BUILD_WINAPI], [test "x$ENABLED_WINAPI" = "xyes"])
AM_CONDITIONAL([BUILD_NUVOTON], [test "x$ENABLED_NUVOTON" = "xyes"])
AM_CONDITIONAL([BUILD_CHECKWAITSTATE], [test "x$ENABLED_CHECKWAITSTATE" = "xyes"])
AM_CONDITIONAL([BUILD_AUTODETECT], [test "x$ENABLED_AUTODETECT" = "xyes"])
AM_CONDITIONAL([BUILD_FIRMWARE], [test "x$ENABLED_FIRMWARE" = "xyes"])
AM_CONDITIONAL([BUILD_HAL], [test "x$ENABLED_EXAMPLE_HAL" = "xyes" || test "x$ENABLED_MMIO" = "xyes"])


CREATE_HEX_VERSION
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

# FINAL
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([wolftpm/version.h])
AC_CONFIG_FILES([wolftpm/options.h])

AX_CREATE_GENERIC_CONFIG
AX_AM_JOBSERVER([yes])

AC_OUTPUT

# force make clean
echo "---"
echo "Running make clean..."
make clean >/dev/null 2>&1
echo

# generate user options header
echo "---"
echo "Generating user options header..."


OPTION_FILE="wolftpm/options.h"
rm -f $OPTION_FILE

echo "/* wolftpm options.h" > $OPTION_FILE
echo " * generated from configure options" >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " * Copyright (C) 2006-2021 wolfSSL Inc." >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " * * This file is part of wolfTPM." >> $OPTION_FILE
echo " *" >> $OPTION_FILE
echo " */" >> $OPTION_FILE

echo "" >> $OPTION_FILE
echo "#ifndef WOLFMTPM_OPTIONS_H" >> $OPTION_FILE
echo "#define WOLFMTPM_OPTIONS_H" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "#ifdef __cplusplus" >> $OPTION_FILE
echo "extern \"C\" {" >> $OPTION_FILE
echo "#endif" >> $OPTION_FILE
echo "" >> $OPTION_FILE

for option in $OPTION_FLAGS; do
    defonly=`echo $option | sed 's/-D//'`
    if test "$defonly" != "$option"
    then
        noequalsign=`echo $defonly | sed 's/=/ /'`
        if test "$noequalsign" = "NDEBUG" || test "$noequalsign" = "DEBUG"
        then
            echo "not outputting (N)DEBUG to $OPTION_FILE"
            continue
        fi

        # allow user to igonore system options
        ignoresys=no
        if [[[ $noequalsign == _* ]]] ;
        then
            ignoresys=yes
            echo "#ifndef WOLFSSL_OPTIONS_IGNORE_SYS" >> $OPTION_FILE
        fi

        noarg=`echo $defonly | sed 's/=.*//'`
        echo "#undef  $noarg" >> $OPTION_FILE
        echo "#define $noequalsign" >> $OPTION_FILE

        if test "$ignoresys" = "yes"
        then
            echo "#endif" >> $OPTION_FILE
        fi

        echo "" >> $OPTION_FILE
    else
        echo "option w/o begin -D is $option, not saving to $OPTION_FILE"
    fi
done

echo "" >> $OPTION_FILE
echo "#ifdef __cplusplus" >> $OPTION_FILE
echo "}" >> $OPTION_FILE
echo "#endif" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo "#endif /* WOLFMTPM_OPTIONS_H */" >> $OPTION_FILE
echo "" >> $OPTION_FILE
echo


# output config summary
echo "---"
echo "Configuration summary for $PACKAGE_NAME version $VERSION"
echo ""
echo "   * Installation prefix:       $prefix"
echo "   * System type:               $host_vendor-$host_os"
echo "   * Host CPU:                  $host_cpu"
echo "   * C Compiler:                $CC"
echo "   * C Flags:                   $CFLAGS"
echo "   * CPP Flags:                 $CPPFLAGS"
echo "   * Linker Flags:              $LDFLAGS"
echo "   * LIB Flags:                 $LIB"

echo "   * Wrappers:                  $ENABLED_WRAPPER"
echo "   * Examples:                  $ENABLED_EXAMPLES"
echo "   * wolfCrypt:                 $ENABLED_WOLFCRYPT"
echo "   * Advanced IO:               $ENABLED_ADVIO"
echo "   * I2C:                       $ENABLED_I2C"
echo "   * Linux kernel TPM device:   $ENABLED_DEVTPM"
echo "   * SWTPM:                     $ENABLED_SWTPM"
echo "   * WINAPI:                    $ENABLED_WINAPI"
echo "   * TIS/SPI Check Wait State:  $ENABLED_CHECKWAITSTATE"

echo "   * Infineon SLB967X           $ENABLED_INFINEON"
echo "   * STM ST33:                  $ENABLED_ST"
echo "   * Microchip ATTPM20:         $ENABLED_MICROCHIP"
echo "   * Nuvoton NPCT75x:           $ENABLED_NUVOTON"

echo "   * Runtime Module Detection:  $ENABLED_AUTODETECT"
echo "   * Firmware Upgrade Support:  $ENABLED_FIRMWARE"
