#! /bin/bash
HOST_FILE=/etc/hosts
DOMAIN_NAME="127.0.0.1	www.testshop.com testshop.com"

pkill testShopServer
pkill sslsplit
pkill tls_wrapper

sed -i "0,/${DOMAIN_NAME}/ d" $HOST_FILE
cd ./sslsplit
./firewallOn.sh > /dev/null &
