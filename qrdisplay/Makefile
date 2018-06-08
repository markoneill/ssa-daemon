CFILES=qrPopUp.c
TARGET=bin/qrPopUp
DBG_TARGET=bin/qrPopUpDBG
LFLAGS=`pkg-config --cflags --libs gtk+-3.0`
DBG_CFLAGS= -D_DEBUG -Wall -g

$(TARGET) : $(CFILES)
	$(CC) -o $(TARGET) $(CFILES) $(LFLAGS)

$(DBG_TARGET) : $(CFILES)
	$(CC) $(DBG_CFLAGS) -o $(DBG_TARGET) $(CFILES) $(LFLAGS)

.PHONY: clean dbg run

clean :
	rm $(TARGET)
	rm $(DBG_TARGET)
	
dbg : $(DBG_TARGET)

run : $(DEB_TARGET)
	./$(DEB_TARGET)

