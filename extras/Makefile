CC = gcc
CXXFLAGS=-w -Wall -fPIC
CXX_DEBUG_FLAGS=-g
CXX_RELEASE_FLAGS=-O3
 
SO = addons.so
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
INCLUDES = 
LIBS = -ldl

all: CXXFLAGS+=$(CXX_DEBUG_FLAGS)
all: $(SO)

release: CXXFLAGS+=$(CXX_RELEASE_FLAGS)
release: $(SO)

# Main target
$(SO): $(OBJECTS)
	$(CC) -shared $(OBJECTS) -o $(SO) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CXXFLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(SO) $(OBJECTS)
