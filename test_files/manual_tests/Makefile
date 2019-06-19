TARGET=https_client

all: https_client echo_server

echo_server: echo_server.c
	gcc -o echo_server echo_server.c

https_client: https_client.c
	gcc -o $(TARGET) https_client.c

clean :
	rm $(TARGET)
