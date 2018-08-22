CC = gcc
CFLAGS = -Wall -g
SOURCE = $(filter $(wildcard *.c), *.t.c)
TLS_OPTIONS_TEST=tls_options.c
EXE = test

.PHONY: all clean

all: MY_SOURCE=$(SOURCE) $(TLS_OPTIONS_TEST)
all: $(EXE)

$(EXE): $(MY_SOURCE)
	$(CC) $(CFLAGS) -o $(EXE)$(MY_SOURCE)

clean:
	rm $(EXE)
