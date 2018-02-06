
normal:
	gcc -o https_client https_client.c

threaded:
	gcc -g -Wall -w -pthread -o threaded_https_client threaded_client.c -lcrypto -lssl

clean_gprof:
	rm gmon.out
	rm analysis.txt
