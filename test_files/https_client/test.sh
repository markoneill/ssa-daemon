#!/bin/bash

for i in {1..100}
do
	./threaded_https_client -b 1024 -c 1 -d 1000000 -f fresher.txt -t $i
	sleep 5
done

for i in {1..100}
do
	./threaded_https_client -b 1024 -c 1 -d 1000000 -f fresher.txt -t $i -s
	sleep 5
done
