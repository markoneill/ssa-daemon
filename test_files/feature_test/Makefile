CC = gcc
CFLAGS = -Wall -g
LIBS = -lpthread
SOURCE = $(filter $(wildcard *.c), *.t.c)
TLS_OPTIONS_TEST = tls_options.t.c
EXE = test

.PHONY: all clean

all: MY_SOURCE=$(SOURCE) $(TLS_OPTIONS_TEST)
all: $(EXE)

$(EXE): $(MY_SOURCE)
	$(CC) $(CFLAGS) -o $(EXE) $(MY_SOURCE) $(LIBS)

clean:
	rm $(EXE)
