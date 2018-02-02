CC=gcc
CFLAGS= -shared -fPIC
LIBS= -ldl
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
DEPS = hashmap.c hashmap.h

dynamicSSA: dynamicSSA.c
	$(CC) $(CFLAGS) dynamicSSA.c $(DEPS) -o dynamicSSA.so $(LIBS)
