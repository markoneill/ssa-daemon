CC = gcc
CFLAGS = -Wall -g
LIBS = -lpthread
SOURCE = $(filter-out $(wildcard *.t.c),$(wildcard *.c))
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

$(SSA_CONF_EXE): MY_SOURCE=$(SOURCE) $(SSA_CONF_TEST) ../../config.c ../../config.h ../../hashmap_str.c ../../hashmap_str.h ../../log.c ../../log.h
$(SSA_CONF_EXE): MY_LIBS=$(LIBS) `pkg-config --libs libconfig` 
$(SSA_CONF_EXE): $(SSA_CONF_TEST) ../../config.c ../../config.h ../../hashmap_str.c ../../hashmap_str.h ../../log.c ../../log.h
	$(CC) $(CFLAGS) -o $(SSA_CONF_EXE) $(MY_SOURCE) $(MY_LIBS)

clean:
	rm -f $(TLS_OPTIONS_EXE) $(SSA_CONF_EXE)
