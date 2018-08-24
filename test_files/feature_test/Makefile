CC = gcc
CFLAGS = -Wall -g
LIBS = -lpthread
SOURCE = $(filter $(wildcard *.c), *.t.c)
TLS_OPTIONS_TEST = tls_options.t.c
TLS_OPTIONS_EXE = $(TLS_OPTIONS_TEST:.t.c=)

SSA_CONF_TEST = ssa_config.t.c
SSA_CONF_EXE = $(SSA_CONF_TEST:.t.c=)

.PHONY: all clean

all: $(TLS_OPTIONS_EXE)
all: $(SSA_CONF_EXE)


$(TLS_OPTIONS_EXE): MY_SOURCE=$(SOURCE) $(TLS_OPTIONS_TEST)
$(TLS_OPTIONS_EXE): $(TLS_OPTIONS_TEST)
	$(CC) $(CFLAGS) -o $(TLS_OPTIONS_EXE) $(MY_SOURCE) $(LIBS)

$(SSA_CONF_EXE): MY_SOURCE=$(SOURCE) $(SSA_CONF_TEST)
$(SSA_CONF_EXE):
	$(CC) $(CFLAGS) -o $(SSA_CONF_EXE) $(MY_SOURCE) $(LIBS)

clean:
	rm $(TLS_OPTIONS_EXE)
