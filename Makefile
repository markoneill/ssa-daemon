CC = gcc
CXXFLAGS=-w -Wall
CXX_DEBUG_FLAGS=-g
CXX_RELEASE_FLAGS=-O3 -DNO_LOG
CXX_CLIENTAUTH_FLAGS=-DCLIENT_AUTH
 
EXEC = tls_wrapper
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
STD_INCLUDES = `pkg-config --cflags libnl-3.0`
NEW_INCLUDES = \
	-I/usr/include/libnl3 \
	-Iopenssl/include \
	-Ilibevent/include
LIBS = 	-lpthread \
	`pkg-config --libs \
		libconfig \
		libevent_openssl \
		libnl-genl-3.0 \
	       	avahi-client \
	       	openssl \
		` \
	$(shell curl-config --libs)
LIBS_EX = \
	-Llibevent/lib \
	-Lopenssl/lib \
	-Wl,-rpath \
	-Wl,libevent/lib \
	-Wl,-rpath \
	-Wl,openssl/lib \
	-lpthread \
	`pkg-config --libs \
		libconfig \
		libevent_openssl \
		libnl-genl-3.0 \
		libnotify \
	       	avahi-client \
	       	openssl \
		`
  
INCLUDES= \
	`pkg-config --cflags libnotify`

.PHONY: clean qrwindow run

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
