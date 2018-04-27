CC = gcc
CXXFLAGS=-w -Wall
CXX_DEBUG_FLAGS=-g
CXX_RELEASE_FLAGS=-O3 -DNO_LOG
CXX_CLIENTAUTH_FLAGS=-DCLIENT_AUTH
 
EXEC = tls_wrapper
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
STD_INCLUDES = -I/usr/include/libnl3
NEW_INCLUDES = -I/usr/include/libnl3 -I../openssl/include
LIBS = -lnl-3 -lnl-genl-3 -levent_openssl -levent -lcrypto -lssl -lconfig -lavahi-client -lavahi-common -lpthread
LIBS_EX = -L../openssl/ -lnl-3 -lnl-genl-3 -levent_openssl -levent -lconfig -lavahi-client -lavahi-common -lpthread -l:libssl.so -l:libcrypto.so -Wl,-rpath=../openssl
INCLUDES= 

all: CXXFLAGS+=$(CXX_DEBUG_FLAGS)
all: INCLUDES=$(STD_INCLUDES)
all: $(EXEC)

release: CXXFLAGS+=$(CXX_RELEASE_FLAGS)
release: INCLUDES+=$(STD_INCLUDES)
release: $(EXEC)

clientauth: CXXFLAGS+=$(CXX_CLIENTAUTH_FLAGS)
clientauth: INCLUDES+=$(NEW_INCLUDES)
clientauth: $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS_EX)

# Main target
$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CXXFLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)
