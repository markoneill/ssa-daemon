#!/bin/bash

#./threaded_https_client -a 100 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h 192.168.21.101
#./threaded_https_client -a 100 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h 192.168.21.101 -s
#./threaded_https_client -a 100 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h www.phoenixteam.net
#./threaded_https_client -a 100 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h www.phoenixteam.net -s

for j in {1..2}
do
	echo "Iteration $j"
	for i in {1..100}
	do
		echo "Iteration $i"
		./threaded_https_client -b 1024 -c 1 -d 1000000 -f refactor_03.csv -h www.phoenixteam.net -t $i 
		#sleep 5
	done

	for i in {1..100}
	do
		echo "Iteration $i"
		./threaded_https_client -b 1024 -c 1 -d 1000000 -f refactor_03.csv -h www.phoenixteam.net -t $i -s
		#sleep 5
	done
done
