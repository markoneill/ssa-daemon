#! /bin/bash
pkill testShopServer
pkill sslsplit
pkill tls_wrapper

cd ./sslsplit
./firewallOn.sh > /dev/null &
