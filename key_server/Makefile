CC=gcc

all:
	$(CC) -Wall -o key-server server.c -L/usr/local/lib -D_GNU_SOURCE -lpthread -lssl -lcrypto

clean:
	rm -f key-server
