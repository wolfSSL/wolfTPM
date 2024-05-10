#!/bin/sh
#
# Create configure and makefile stuff...
#

set -e

# Check environment
if [ -n "$WSL_DISTRO_NAME" ]; then
    # we found a non-blank WSL environment distro name
    current_path="$(pwd)"
    pattern="/mnt/?"
    if [ "$(echo "$current_path" | grep -E "^$pattern")" ]; then
        # if we are in WSL and shared Windows file system, 'ln' does not work.
        no_links=true
    else
        no_links=
    fi
fi

# Git hooks should come before autoreconf.
if test -d .git; then
    if [ -n "$no_links" ]; then
        echo "Linux ln does not work on shared Windows file system in WSL."
        if [ ! -e .git/hooks/pre-commit ]; then
            echo "The pre-commit.sh file will not be copied to .git/hooks/pre-commit"
            # shell scripts do not work on Windows; TODO create equivalent batch file
            # cp ./pre-commit.sh .git/hooks/pre-commit || exit $?
        fi
        if [ ! -e .git/hooks/pre-push ]; then
            echo "The pre-push.sh file will not be copied to .git/hooks/pre-commit"
            # shell scripts do not work on Windows; TODO create equivalent batch file
            # cp ./pre-push.sh .git/hooks/pre-push || exit $?
        fi
    else
      if ! test -d .git/hooks; then
        mkdir .git/hooks
      fi
      ln -s -f ../../pre-commit.sh .git/hooks/pre-commit
    fi
fi

# if get an error about libtool not setup
# " error: Libtool library used but 'LIBTOOL' is undefined
#     The usual way to define 'LIBTOOL' is to add 'LT_INIT' "
# manually call libtoolize or glibtoolize before running this again
# (g)libtoolize

# if you get an error about config.rpath missing, some buggy automake versions
# then touch the missing file (may need to make config/ first).
# touch config/config.rpath
# touch config.rpath

if test ! -d build-aux; then
  echo "Making missing build-aux directory."
  mkdir -p build-aux
fi

if test ! -f build-aux/config.rpath; then
  echo "Touching missing build-aux/config.rpath file."
  touch build-aux/config.rpath
fi


# If this is a source checkout then call autoreconf with error as well
if test -d .git; then
  WARNINGS="all,error"
else
  WARNINGS="all"
fi

autoreconf --install --force --verbose
