CC=gcc
#CFLAGS= -shared -fPIC
LIBS= -lconfig
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
DEPS = hashmap_str.c hashmap_str.h log.c log.h

dynamicSSA: config.c hashmap_str.c log.c
	$(CC) $(CFLAGS) config.c $(DEPS) -o config $(LIBS)


#gcc -o config log.c log.h config.c config.h -lconfig
