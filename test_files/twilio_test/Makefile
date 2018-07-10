CC = $(shell curl-config --cc --cflags)
CCFLAGS = -Wall -O3 -fpic -g3
LIBS = $(shell curl-config --libs)

TEST_SRC = twilio_test.c
TEST_OBJ = $(TEST_SRC:%.c=%.o)
TEST_EXE = twilio_test

TLIB_SRC = ../../twilio.c
TLIB_OBJ = $(TLIB_SRC:%.c=%.o)

all: $(TEST_OBJ) $(TLIB_OBJ) $(TEST_SRC) $(TLIB_SRC)
	$(CC) -o $(TEST_EXE) $(TLIB_OBJ) $(TEST_OBJ) $(LIBS)

%.o: %.c
	$(CC) $(CCFLAGS) -c $< -o $@

.PHONY: clean
clean: 
	rm -f $(TLIB_OBJ) *.o $(TEST_EXE)
