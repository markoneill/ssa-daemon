CC = gcc
CCFLAGS = -Wall -g
TARGET=https_client

all: https_client echo_server

echo_server: echo_server.c
	$(CC) $(CCFLAGS) -o echo_server echo_server.c

https_client: https_client.c
	$(CC) $(CCFLAGS) -o $(TARGET) https_client.c

clean :
	rm $(TARGET)
