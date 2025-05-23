#!/bin/bash
# apt-get install build-essential cmake gcc libudev-dev libnl-3-dev libnl-route-3-dev ninja-build pkg-config valgrind python3-dev cython3 python3-docutils pandoc -y

set -e

SRCDIR=`dirname $0`
BUILDDIR="$SRCDIR/build"

mkdir -p "$BUILDDIR"

if hash cmake3 2>/dev/null; then
    # CentOS users are encouraged to install cmake3 from EPEL
    CMAKE=cmake3
else
    CMAKE=cmake
fi

if hash ninja-build 2>/dev/null; then
    # Fedora uses this name
    NINJA=ninja-build
elif hash ninja 2>/dev/null; then
    NINJA=ninja
fi

cd "$BUILDDIR"

if [ "x$NINJA" == "x" ]; then
    $CMAKE -DIN_PLACE=1 -DCMAKE_BUILD_TYPE=DEBUG -DMLX5_IO_DEBUG=1 ${EXTRA_CMAKE_FLAGS:-} ..
    make
else
    $CMAKE -DIN_PLACE=1 -GNinja -DCMAKE_BUILD_TYPE=DEBUG -DMLX5_IO_DEBUG=1 ${EXTRA_CMAKE_FLAGS:-} ..
    $NINJA
fi
