#!/bin/bash

#./threaded_https_client -a 100 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h 192.168.21.101
#./threaded_https_client -a 100 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h 192.168.21.101 -s
#./threaded_https_client -a 100 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h www.phoenixteam.net
#./threaded_https_client -a 100 -b 1024 -c 1 -d 1000000 -f fullTest.csv -h www.phoenixteam.net -s

for j in {1..5}
do
	echo "round $j"
	for i in {1..100}
	do
		echo "Iteration $i"
		./threaded_https_client -b 1024 -c 1 -d 1000000 -f final_5_iterations.csv -h 192.168.21.101 -t $i 
	done

	for i in {1..100}
	do
		echo "Iteration $i"
		./threaded_https_client -b 1024 -c 1 -d 1000000 -f final_5_iterations.csv -h 192.168.21.101 -t $i -s
	done
done

for j in {1..5}
  do
         echo "round $j"
         for i in {1..100}
         do
                 echo "Iteration $i"
                 ./threaded_https_client -b 1024 -c 1 -d 1000000 -f final_5_iterations.csv -h www.phoenixteam.net -t $i
         done
 
         for i in {1..100}
         do
                 echo "Iteration $i"
                 ./threaded_https_client -b 1024 -c 1 -d 1000000 -f final_5_iterations.csv -h www.phoenixteam.net -t $i -s
         done
 done
