#!/bin/bash
set -e

OPENSSL_INSTALL_DIR=$PWD/openssl
LIBEVENT_INSTALL_DIR=$PWD/libevent

mkdir -p tmp
cd tmp

if [ ! -d "openssl" ] ; then
	echo "Cloning OpenSSL repo"
	git clone https://github.com/openssl/openssl.git
	echo "Done"
fi

echo "Applying OpenSSL patches"
cd openssl
git checkout tags/OpenSSL_1_1_1-pre3
git apply ../../extras/openssl/0001-Adding-support-for-dynamic-client-authentication-cal.patch
echo "Done"
echo "Configuring OpenSSL"
mkdir -p $OPENSSL_INSTALL_DIR
./config --prefix=$OPENSSL_INSTALL_DIR --openssldir=$OPENSSL_INSTALL_DIR
echo "Done"
echo "Building OpenSSL"
make
echo "Done"
echo "Installing OpenSSL"
make install
cd ..
echo "Done"

echo "Downloading libevent source"
wget https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz -O libevent.tgz
echo "Done"
echo "Extracting libevent source"
mkdir -p libevent
tar xvf libevent.tgz -C libevent --strip-components 1
echo "Done"

echo "Configuring libevent"
cd libevent
mkdir -p $LIBEVENT_INSTALL_DIR
./configure CPPFLAGS="-I$OPENSSL_INSTALL_DIR/include" LDFLAGS="-L$OPENSSL_INSTALL_DIR/lib" --prefix=$LIBEVENT_INSTALL_DIR
echo "Done"
echo "Building libevent"
make
echo "Done"
echo "Installing libevent"
make install
cd ..
echo "Done"

cd ..
echo "Building Encryption Daemon"
make clientauth
echo "Done"

echo "Building custom sslsplit"
git clone https://github.com/droe/sslsplit
cd sslsplit
cp ../extras/sslsplit/0001-SSA-patch.patch .
cp ../extras/sslsplit/ca.crt .
cp ../extras/sslsplit/ca.key .
cp ../extras/sslsplit/start.sh .
cp ../extras/sslsplit/firewallOn.sh .
git apply 0001-SSA-patch.patch
make
cd ..
echo "Done"

echo "Cleaning up"
#rm -rf tmp
echo "Done"

