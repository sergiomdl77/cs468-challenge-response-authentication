CC = gcc
CFLAGS = -g

TARGET1 = RShellClient2
TARGET2 = RShellServer2

all: $(TARGET1) $(TARGET2)

$(TARGET1):
	$(CC) $(CFLAGS) -o $(TARGET1) $(TARGET1).c -lcrypto -lssl

$(TARGET2):
	$(CC) $(CFLAGS) -o $(TARGET2) $(TARGET2).c -lcrypto -lssl

clean:
	rm $(TARGET1)
	rm $(TARGET2)
