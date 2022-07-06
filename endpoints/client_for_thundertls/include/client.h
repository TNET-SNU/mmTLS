#ifndef CLIENT_H
#define CLIENT_H

#define MAX_DATA_LEN 512
#define MAX_ADDR_LEN 20
#define MAX_THREAD_NUM 16

int OpenConnection(const char *hostname, int port);

SSL_CTX* InitCTX();

void ShowCerts(SSL* ssl);

#endif /* CLIENT_H */
