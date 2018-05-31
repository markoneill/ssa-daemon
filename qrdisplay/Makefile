CFILES=qrPopUp.c
TARGET=qrPopUp
LFLAGS=`pkg-config --cflags --libs gtk+-3.0`

TARGET : $(CFILES)
	$(CC) -o $(TARGET) $(CFILES) $(LFLAGS)
