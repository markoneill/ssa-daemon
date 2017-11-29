CC = gcc
CXXFLAGS=-w -Wall
CXX_DEBUG_FLAGS=-g
CXX_RELEASE_FLAGS=-O3 -DNO_LOG
 
EXEC = tls_wrapper
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
INCLUDES = -I/usr/include/libnl3
LIBS = -lnl-3 -lnl-genl-3 -levent_openssl -levent -lcrypto -lssl

all: CXXFLAGS+=$(CXX_DEBUG_FLAGS)
all: $(EXEC)

release: CXXFLAGS+=$(CXX_RELEASE_FLAGS)
release: $(EXEC)

# Main target
$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CXXFLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)
