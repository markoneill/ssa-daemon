CC = gcc
CXXFLAGS=-Wall -Wno-deprecated-declarations
CXX_DEBUG_FLAGS=-g
CXX_RELEASE_FLAGS=-O3 -DNO_LOG
CXX_CLIENTAUTH_FLAGS= -g -DCLIENT_AUTH
 
EXEC = tls_wrapper
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
STD_INCLUDES = `pkg-config --cflags libnl-3.0`
NEW_INCLUDES = \
	`pkg-config --cflags libnl-3.0` \
	-Iopenssl/include \
	-Ilibevent/include
LIBS = 	-lpthread \
	`pkg-config --libs \
		libconfig \
		libevent_openssl \
		libnl-genl-3.0 \
	       	avahi-client \
	       	openssl \
		`
LIBS_EX = \
	-Llibevent/lib \
	-Lopenssl/lib \
	-Wl,-rpath \
	-Wl,libevent/lib \
	-Wl,-rpath \
	-Wl,openssl/lib \
	-lpthread \
	`pkg-config --libs \
		libconfig \
		libevent_openssl \
		libnl-genl-3.0 \
		libnotify \
	       	avahi-client \
	       	openssl \
		`
  
INCLUDES= \
	`pkg-config --cflags libnotify`

PRELOAD_PATH=$(PWD)/extras
QRVIEWR_PATH=./qrdisplay
BASHRC=$(HOME)/.bashrc

.PHONY: clean qrwindow sharedobject hostname-support preload hostname-support-remove

all: CXXFLAGS+=$(CXX_DEBUG_FLAGS)
all: INCLUDES=$(STD_INCLUDES)
all: $(EXEC)

release: CXXFLAGS+=$(CXX_RELEASE_FLAGS)
release: INCLUDES+=$(STD_INCLUDES)
release: $(EXEC)

hostname-support: sharedobject
hostname-support: preload
hostname-support: all

hostname-support-release: sharedobject
hostname-support-release: preload
hostname-support-release: release

clientauth: CXXFLAGS+=$(CXX_CLIENTAUTH_FLAGS)
clientauth: INCLUDES+=$(NEW_INCLUDES)
clientauth: qrwindow
clientauth: $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS_EX)

# Main target
$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXEC) $(LIBS)
 
# To obtain object files
%.o: %.c
	$(CC) -c $(CXXFLAGS) $< $(INCLUDES) -o $@
 
# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)
	$(MAKE) -C $(QRVIEWR_PATH) clean

qrwindow:
	$(MAKE) -C $(QRVIEWR_PATH)

sharedobject:
	$(MAKE) -C $(PRELOAD_PATH)

preload: 
ifeq (0, $(shell grep -c addons.so $(BASHRC)))
	@test -z $(LD_PRELOAD) && EMPTY_PRELOAD=1 || EMPTY_PRELOAD=0
ifneq	(0, $(shell grep -c LD_PRELOAD $(BASHRC)))
		@echo "adding addons.so to LD_PRELOAD"
		$(shell test -e $(BASHRC) || echo "# .bashrc" > $(BASHRC))
ifneq		(1,$(EMPTY_PRELOAD))
			# LD_PRELOAD in .bashrc only
			@sed -i -e "s|^\(export LD_PRELOAD=\)\([.:\/a-zA-z0-9 ]*\)|\0\n\1$(PRELOAD_PATH)/addons.so:\2|g" $(BASHRC)
else
			# LD_PRELOAD is in bash & .bashrc			
ifeq 			(1, $(shell grep -c "LD_PRELOAD=$(LD_PRELOAD)" $(BASHRC)))
				# LD_PRELOAD in bash matches .bashrc
				@echo "amending ~/.bashrc to include .so in LD_PRELOAD."
				@sed -i -e "\$$aexport LD_PRELOAD=$(PRELOAD_PATH)/addons.so:$(LD_PRELOAD)" $(BASHRC)
else
				# LD_PRELOAD in bash is differant than in .bashrc
				@echo "amending ~/.bashrc to include .so in LD_PRELOAD(along with this sessions LD_PRELOAD)."
				@sed -i -e "\$$aexport LD_PRELOAD=$(PRELOAD_PATH)/addons.so:$(LD_PRELOAD)" $(BASHRC)
endif 			#   $(shell grep -c "LD_PRELOAD=$(LD_PRELOAD)" $(BASHRC))
		@echo "please source your .bashrc file to import the updated LD_PRELOAD variable"
endif		#  $(EMPTY_PRELOAD)
else	#   $(shell grep -c LD_PRELOAD $(BASHRC))
ifneq		(1,$(EMPTY_PRELOAD))
			# LD_PRELOAD absent from bash and .bashrc
			@echo "LD_PRELOAD was absent. Adding .so to LD_PRELOAD in ~/.bashrc"
			@sed -i -e "\$$aexport LD_PRELOAD=$(PRELOAD_PATH)/addons.so" $(BASHRC)
else
			# LD_PRELOAD is in bash only			
			@echo "LD_PRELOAD is set in bash. Adding .so and saving to ~/.bashrc"
			@sed -i -e "\$$aexport LD_PRELOAD=$(PRELOAD_PATH)/addons.so:$(LD_PRELOAD)" $(BASHRC)
endif		#  $(EMPTY_PRELOAD)
endif	#   $(shell grep -c LD_PRELOAD $(BASHRC))
	@echo -e "\nLD_PRELOAD modifyed!\nplease source your .bashrc file\n\n"
endif

hostname-support-remove:
ifneq (0, $(shell grep -c addons.so $(BASHRC)))
	@echo "removing addons.so from LD_PRELOAD"
	@sed -i -e ':a;N;$$!ba;s|\nexport LD_PRELOAD=$(PRELOAD_PATH)/addons\.so\(:.*\)*||g' $(BASHRC)
endif

