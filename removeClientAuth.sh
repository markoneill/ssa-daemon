#! /bin/bash
HOST_FILE=/etc/hosts
DOMAIN_NAME="www.testshop.com testshop.com"

if [ -z "$1"]; then
	echo "hosts will not be reset"
	RESET_HOSTS=false
else
	RESET_HOSTS=$1
	echo "request hosts reset? ${RESET_HOSTS}"
fi

pkill testShopServer
pkill sslsplit
pkill tls_wrapper

if [ ${RESET_HOSTS} == "true" ]; then
	let count=$(grep -c "$$[0-9.]* ${DOMAIN_NAME}" $HOST_FILE)
	if [ $count > "0" ]; then
		echo "removing redirect on ${DOMAIN_NAME}"
		sed -i "0,/${DOMAIN_NAME}/ d" $HOST_FILE
	fi
fi

cd ./sslsplit
./firewallOn.sh > /dev/null &
