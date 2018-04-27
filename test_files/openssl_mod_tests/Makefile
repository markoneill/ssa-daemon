CC = gcc
CXXFLAGS=-w -Wall
 
EXEC = client
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
INCLUDES = -I../../openssl/include
LIBS = -L../../openssl/lib -lcrypto -lssl -Wl,-rpath -Wl,../../openssl/lib

all: $(EXEC)

# Main target
$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CXXFLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)
