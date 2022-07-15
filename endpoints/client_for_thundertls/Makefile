CC=gcc

all:
	$(CC) -Wall -o ssl-client client.c -L/usr/local/lib -lpthread -lssl -lcrypto
	$(CC) -Wall -o ssl-key key.c -L/usr/local/lib -lpthread -lssl -lcrypto
clean:
	rm -f ssl-*
