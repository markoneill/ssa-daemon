CC = gcc
CCFLAGS = -Wall -g
CXX_CLIENTAUTH_FLAGS= -DCLIENT_AUTH

HTTP_SERVER_SRC = main.c \
		http_server.c \
		client.c \
		config.c \
		utils.c

HTTP_SERVER_OBJ = $(HTTP_SERVER_SRC:%.c=%.o)
HTTP_SERVER_EXE = testShopServer

all: $(HTTP_SERVER_EXE)

clientauth: CCFLAGS+=$(CXX_CLIENTAUTH_FLAGS)
clientauth: $(HTTP_SERVER_EXE)

$(HTTP_SERVER_EXE) : $(HTTP_SERVER_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

%.o : %.c %.h
	$(CC) $(CCFLAGS) -c $< -o $@

clean:
	rm -rf *.o $(HTTP_SERVER_EXE)
