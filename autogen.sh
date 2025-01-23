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
if [ -e .git ]; then
    export WARNINGS="all,error"
else
    export WARNINGS="all"
fi

autoreconf --install --force --verbose
