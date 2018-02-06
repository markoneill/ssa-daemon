#!/bin/bash
./threaded_https_client -a 101 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h 192.168.21.101 -r 30
./threaded_https_client -a 101 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h 192.168.21.101 -s -r 30
./threaded_https_client -a 101 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h www.phoenixteam.net -r 30
./threaded_https_client -a 101 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h www.phoenixteam.net -s -r 30
