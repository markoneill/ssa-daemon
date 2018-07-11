#! /bin/bash
HOST_FILE=/etc/hosts
DOMAIN_NAME="127.0.0.1	www.testshop.com testshop.com"

pkill testShopServer
pkill sslsplit
pkill tls_wrapper

let count=$(grep -c "${DOMAIN_NAME}" $HOST_FILE)
if [ $count = "1" ]; then
	sed -i "0,/${DOMAIN_NAME}/ d" $HOST_FILE
fi
cd ./sslsplit
./firewallOn.sh > /dev/null &
