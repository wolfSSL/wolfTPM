#!/bin/sh

WOLFTPM_SRC_DIR=../../../..

if [ ! -d $WOLFTPM_SRC_DIR ]; then
    echo "Directory does not exist: $WOLFTPM_SRC_DIR"
    exit 1
fi
if [ ! -f $WOLFTPM_SRC_DIR/examples/wrap/caps.c ]; then
    echo "Missing source file: $WOLFTPM_SRC_DIR/examples/wrap/caps.h"
    exit 1
fi

ZEPHYR_DIR=
if [ $# -ne 1 ]; then
    echo "Need location of zephyr project as a command line argument"
    exit 1
else
    ZEPHYR_DIR=$1
fi
if [ ! -d $ZEPHR_DIR ]; then
    echo "Zephyr project directory does not exist: $ZEPHYR_DIR"
    exit 1
fi
ZEPHYR_SAMPLES_DIR=$ZEPHYR_DIR/zephyr/samples/modules
if [ ! -d $ZEPHYR_SAMPLES_DIR ]; then
    echo "Zephyr samples/modules directory does not exist: $ZEPHYR_SAMPLES_DIR"
    exit 1
fi
ZEPHYR_WOLFTPM_DIR=$ZEPHYR_SAMPLES_DIR/wolftpm_wrap_caps

echo "wolfTPM directory:"
echo "  $ZEPHYR_WOLFTPM_DIR"
rm -rf $ZEPHYR_WOLFTPM_DIR
mkdir $ZEPHYR_WOLFTPM_DIR

echo "Copy in Build files ..."
cp -r * $ZEPHYR_WOLFTPM_DIR/
rm $ZEPHYR_WOLFTPM_DIR/$0

echo "Copy Source Code ..."
rm -rf $ZEPHYR_WOLFTPM_DIR/src
mkdir $ZEPHYR_WOLFTPM_DIR/src

cp -rf ${WOLFTPM_SRC_DIR}/examples/wrap/caps.c $ZEPHYR_WOLFTPM_DIR/src/

echo "Done"
