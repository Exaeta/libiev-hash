#!/bin/bash
PACKAGE_NAME="libiev-hash"
PACKAGE_VERSION="$(git describe --tags)"
PACKAGE_FULLNAME="${PACKAGE_NAME}${PACKAGE_VERSION}"
BUILDDIR="./build/${PACKAGE_FULLNAME}"
#echo $PACKAGE_NAME
#echo $BUILDDIR

mkdir -p $BUILDDIR/usr/include/iev
cp ./src/blake2b.hh $BUILDDIR/usr/include/iev/blake2b
cp ./src/sha512.hh $BUILDDIR/usr/include/iev/sha512
cp ./src/sha256.hh $BUILDDIR/usr/include/iev/sha256
mkdir -p $BUILDDIR/DEBIAN/
printf "Package: ${PACKAGE_NAME}\nVersion: ${PACKAGE_VERSION}\nSection: base\nPriority: Optional\nArchitecture: all\nDepends:\nDescription: LibIEV Hash Functions
 Contians: Blake2b
 Depends on libsodium\n" > $BUILDDIR/DEBIAN/control
OLDDIR = "$(pwd)"
cd build/
dpkg-deb --build $PACKAGE_FULLNAME
cd $OLDDIR
