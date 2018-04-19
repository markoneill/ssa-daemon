#! /bin/bash
PORT=8020
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 
	exit 1
fi

systemctl stop firewalld
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 127.0.0.1:$PORT -m owner --uid-owner 1000
./sslsplit -D  -k ca.key -c ca.crt ssl 0.0.0.0 $PORT
