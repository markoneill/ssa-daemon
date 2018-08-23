CC = gcc
CFLAGS = -Wall -g
LIBS = -lpthread
SOURCE = $(filter $(wildcard *.c), *.t.c)
TLS_OPTIONS_TEST = tls_options.t.c
TLS_OPTIONS_EXE = $(TLS_OPTIONS_TEST:.t.c=)

.PHONY: all clean

all: $(TLS_OPTIONS_EXE)

$(TLS_OPTIONS_EXE): MY_SOURCE=$(SOURCE) $(TLS_OPTIONS_TEST)
$(TLS_OPTIONS_EXE):
	$(CC) $(CFLAGS) -o $(TLS_OPTIONS_EXE) $(MY_SOURCE) $(LIBS)

clean:
	rm $(TLS_OPTIONS_EXE)
