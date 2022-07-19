CC=gcc

all:
	$(CC) -Wall -o ssl_server server.c -L/usr/local/lib -D_GNU_SOURCE -lpthread -lssl -lcrypto
	$(CC) -Wall -o ssl_client client.c -L/usr/local/lib -lpthread -lssl -lcrypto
	$(CC) -Wall -o udp_sender udp_sender.c -L/usr/local/lib -lpthread

clean:
	rm -f ssl_* udp_sender
