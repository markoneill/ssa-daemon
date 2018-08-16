all: $(wildcard *.c) $(wildcard *.h)
	gcc -shared -fPIC -ldl -lnl-3 -lnl-genl-3 -lpthread -lrt -o unix_socket_preload.so -I/usr/include/libnl3 unix_socket_preload.c ../../hashmap.c

