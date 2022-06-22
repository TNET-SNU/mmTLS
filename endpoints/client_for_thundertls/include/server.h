#ifndef SERVER_H
#define SERVER_H

#define FAIL             -1
#define UNUSED(x) (void)(x)

#define USE_PKA_ENGINE   0

#define MAX_ADDR_LEN 20
#define MAX_THREAD_NUM 16

#if USE_PKA_ENGINE
int InitializePkaEngine();
#endif

void InitializeSSLContext();

int OpenListener(char *addr, int port, int thread_idx);

int isRoot();

SSL_CTX* InitServerCTX();

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);

void ShowCerts(SSL* ssl);

void Servlet(SSL* ssl);

#endif	/* SERVER_H */
