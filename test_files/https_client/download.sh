#!/bin/bash
./threaded_https_client -D -a 101 -B 1000 -S 1000 -t 10 -b 1024 -c 1 -f downloadFullTest.csv -h 192.168.21.101 -r 30
./threaded_https_client -D -a 101 -B 1000 -S 1000 -t 10 -b 1024 -c 1 -f downloadFullTest.csv -h 192.168.21.101 -r 30 -s
./threaded_https_client -D -a 101 -B 1000 -S 1000 -t 10 -b 1024 -c 1 -f downloadFullTest.csv -h www.phoenixteam.net -r 30
./threaded_https_client -D -a 101 -B 1000 -S 1000 -t 10 -b 1024 -c 1 -f downloadFullTest.csv -h www.phoenixteam.net -r 30 -s
