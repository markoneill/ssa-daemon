CC = gcc
CXXFLAGS = -Wall -shared -fPIC -ldl -lpthread -lrt

EXEC = unix_socket_preload.so
STD_INCLUDES = `pkg-config --cflags libnl-3.0`
LIBS = `pkg-config --libs libnl-genl-3.0`

SOURCES = $(wildcard *.c) ../../hashmap.c

.PHONY: clean

all: INCLUDES=$(STD_INCLUDES)
all: $(EXEC)
#	gcc -shared -fPIC -ldl -lnl-3 -lnl-genl-3 -lpthread -lrt -o unix_socket_preload.so -I/usr/include/libnl3 unix_socket_preload.c ../../hashmap.c


$(EXEC): $(SOURCES)
	$(CC) $(CXXFLAGS) $(INCLUDES) $(LIBS) -o $(EXEC)

clean: 
	rm -rf $(EXEC)
