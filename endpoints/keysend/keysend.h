#ifndef MMTLS_CLIENT_H_
#define MMTLS_CLIENT_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/file.h>
#include <netdb.h>
#include <sched.h>
#include <pthread.h>
#include <openssl/types.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_ADDR_LEN 20
#define TLS_PORT 443
#define BUF_SIZE   256
#define MAX_DATA_LEN 512
#define MAX_RANDOM_LEN  32
#define MAX_SECRET_LEN  48
#define CUSTOM_APP_INDEX 10

struct key_chan {
  int num_chan;
  SSL **key_ssl;
  pthread_mutex_t *mutex;
  int *cnt;
};
/*---------------------------------------------------------------------------*/
int
SSL_set_sockaddr(SSL *ssl, struct sockaddr_in *sock);
void
destroy_key_channel(SSL_CTX *ssl_ctx);
int
init_key_channel(SSL_CTX *ssl_ctx, int nthread);
void
keysend_callback(const SSL *ssl, const char *line);

#ifdef __cplusplus
}
#endif

#endif // MMTLS_CLIENT_H_