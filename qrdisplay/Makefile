CFILES=qrPopUp.c
BIN_PATH=bin/
TARGET=$(BIN_PATH)qrPopUp
DBG_TARGET=$(BIN_PATH)qrPopUpDBG
LFLAGS=`pkg-config --cflags --libs gtk+-3.0`
DBG_CFLAGS= -D_DEBUG -Wall -g

.PHONY: clean dbg run

$(TARGET) : $(BIN_PATH) $(CFILES)
	$(CC) -o $(TARGET) $(CFILES) $(LFLAGS)

$(DBG_TARGET) : $(BIN_PATH) $(CFILES)
	$(CC) $(DBG_CFLAGS) -o $(DBG_TARGET) $(CFILES) $(LFLAGS)

$(BIN_PATH) : 
	@umask 0; mkdir -p "$(BIN_PATH)"

clean :
	@rm -rf "$(BIN_PATH)"

dbg : $(DBG_TARGET)

run : $(DEB_TARGET)
	./$(DEB_TARGET)

