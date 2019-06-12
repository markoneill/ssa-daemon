TARGET=https_client

all: https_client server

server:
	gcc -o server server.c

https_client:
	gcc -o $(TARGET) https_client.c

clean :
	rm $(TARGET)
