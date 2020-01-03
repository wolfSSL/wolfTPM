# wolftpm
# Copyright (C) 2020 wolfSSL Inc.
# All right reserved.

AC_COPYRIGHT([Copyright (C) 2014-2020 wolfSSL Inc.])
AC_INIT([wolftpm],[1.7.0],[https://github.com/wolfssl/wolfTPM/issues],[wolftpm],[http://www.wolfssl.com])

AC_PREREQ([2.63])
AC_CONFIG_AUX_DIR([build-aux])

# The following sets CFLAGS to empty if unset on command line.
: ${CFLAGS=""}

# Test ar for the "U" option. Should be checked before the libtool macros.
xxx_ar_flags=$((ar --help) 2>&1)
AS_CASE([$xxx_ar_flags],[*'use actual timestamps and uids/gids'*],[: ${AR_FLAGS="Ucru"}])

AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([1.11 -Wall -Werror -Wno-portability foreign tar-ustar subdir-objects no-define color-tests])

AC_ARG_PROGRAM
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/config.h])

WOLFTPM_LIBRARY_VERSION=7:0:0
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

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_SIZEOF([long long], 8)
AC_CHECK_SIZEOF([long], 4)

# Check headers/libs
AC_CHECK_FUNCS([gethostbyname getaddrinfo gettimeofday inet_ntoa memset socket])
AC_CHECK_LIB([network],[socket])

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
    AM_CFLAGS="$AM_CFLAGS $PTHREAD_CFLAGS"])


# Checks for typedefs, structures, and compiler characteristics.
if test "$ac_cv_sizeof_long" = "8"; then
   AM_CFLAGS="$AM_CFLAGS -DSIZEOF_LONG=8"
else
    if test "$ac_cv_sizeof_long_long" = "8"; then
        AM_CFLAGS="$AM_CFLAGS -DSIZEOF_LONG_LONG=8"
    fi
fi

# Verbose Logging
if test "x$ax_enable_debug" = "xverbose"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_DEBUG_VERBOSE"
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


# wolfCrypt
AC_ARG_ENABLE([wolfcrypt],
    [AS_HELP_STRING([--enable-wolfcrypt],[Enable wolfCrypt hooks for RNG, Auth Sessions and Parameter encryption (default: enabled)])],
    [ ENABLED_WOLFCRYPT=$enableval ],
    [ ENABLED_WOLFCRYPT=yes ]
    )

if test "x$ENABLED_WOLFCRYPT" = "xyes"
then
    TAO_REQUIRE_LIBWOLFSSL
else
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM2_NO_WOLFCRYPT"
fi


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


# Advanced IO
AC_ARG_ENABLE([advio],
    [AS_HELP_STRING([--enable-advio],[Enable Advanced IO (default: disabled)])],
    [ ENABLED_ADVIO=$enableval ],
    [ ENABLED_ADVIO=no ]
    )

if test "x$ENABLED_ADVIO" = "xyes" || test "x$ENABLED_I2C" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_ADV_IO"
fi


# STM ST33 Support
AC_ARG_ENABLE([st33],
    [AS_HELP_STRING([--enable-st33],[Enable ST33 TPM Support (default: disabled)])],
    [ ENABLED_ST33=$enableval ],
    [ ENABLED_ST33=no ]
    )

if test "x$ENABLED_ST33" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_ST33"
fi


# Microchip ATTPM20 Support
AC_ARG_ENABLE([mchp],
    [AS_HELP_STRING([--enable-mchp],[Enable TPM 2.0 Support (default: disabled)])],
    [ ENABLED_MCHP=$enableval ],
    [ ENABLED_MCHP=no ]
    )
if test "x$ENABLED_MCHP" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_MCHP"
fi


# Infineon SLB9670
ENABLED_INFINEON=no
if test "x$ENABLED_MCHP" = "xno" && test "x$ENABLED_ST33" = "xno"
then
    AM_CFLAGS="$AM_CFLAGS -DWOLFTPM_SLB9670"
    ENABLED_INFINEON=yes
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
    AM_CFLAGS="$AM_CFLAGS -DMAX_COMMAND_SIZE=1024 -DMAX_RESPONSE_SIZE=1024 -DWOLFTPM2_MAX_BUFFER=1500 -DMAX_SESSION_NUM=1 -DMAX_DIGEST_BUFFER=973"
fi



# HARDEN FLAGS
AX_HARDEN_CC_COMPILER_FLAGS

OPTION_FLAGS="$CFLAGS $CPPFLAGS $AM_CFLAGS"



# The following AM_CONDITIONAL statements set flags for use in the Makefiles.
AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$ENABLED_EXAMPLES" = "xyes"])
AM_CONDITIONAL([BUILD_WRAPPER], [test "x$ENABLED_WRAPPER" = "xyes"])
AM_CONDITIONAL([HAVE_LIBWOLFSSL], [test "x$ENABLED_WOLFCRYPT" = "xyes"])
AM_CONDITIONAL([BUILD_I2C], [test "x$ENABLED_I2C" = "xyes"])
AM_CONDITIONAL([BUILD_ADVIO], [test "x$ENABLED_ADVIO" = "xyes"])
AM_CONDITIONAL([BUILD_ST33], [test "x$ENABLED_ST33" = "xyes"])
AM_CONDITIONAL([BUILD_MCHP], [test "x$ENABLED_MCHP" = "xyes"])
AM_CONDITIONAL([BUILD_INFINEON], [test "x$ENABLED_INFINEON" = "xyes"])



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
echo " * Copyright (C) 2006-2020 wolfSSL Inc." >> $OPTION_FILE
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
echo "   * Infineon SLB9670           $ENABLED_INFINEON"
echo "   * STM ST33:                  $ENABLED_ST33"
echo "   * Microchip ATTPM20:         $ENABLED_MCHP"
echo "   * I2C:                       $ENABLED_I2C"
